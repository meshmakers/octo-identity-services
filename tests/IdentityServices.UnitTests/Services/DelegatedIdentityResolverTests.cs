using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5026 — the delegation ("on-behalf-of") authority rule: a delegated token carries the
///     <b>intersection</b> of the service account's and the user's effective roles, never the union
///     and never either side alone.
/// </summary>
/// <remarks>
///     <see cref="DelegatedIdentityResolver" /> is deliberately free of Duende types, so the policy
///     is exercised here directly against substituted stores — no protocol plumbing, no
///     <c>ExtensionGrantValidationContext</c>. The stores themselves already resolve direct plus
///     group-inherited roles; that half is pinned by the integration suite against real MongoDB.
/// </remarks>
public class DelegatedIdentityResolverTests
{
    private const string ServiceAccountClientId = "octo-pipeline-sa";
    private const string UserSubjectId = "68b0000000000000000000a1";

    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();
    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly DelegatedIdentityResolver _sut;
    private readonly IUserRoleStore<RtUser> _userRoleStore = Substitute.For<IUserRoleStore<RtUser>>();

    public DelegatedIdentityResolverTests()
    {
        _sut = new DelegatedIdentityResolver(
            _clientStore, _clientRoleStore, _userRoleStore,
            NullLogger<DelegatedIdentityResolver>.Instance);
    }

    [Fact]
    public async Task Resolve_DisjointRoleSets_GrantsNoRoles()
    {
        GivenServiceAccountWithRoles("PipelineOperator", "AssetReader");
        GivenUserWithRoles("TenantAdministrator", "ReportViewer");

        var result = await ResolveAsync();

        // An empty intersection is a GRANT, not a denial: the token is issued and simply authorizes
        // nothing, so role-gated consumers fail closed instead of the caller seeing an opaque error.
        result.IsGranted.Should().BeTrue();
        result.DenialReason.Should().Be(DelegationDenialReason.None);
        result.EffectiveRoleNames.Should().BeEmpty();
    }

    [Fact]
    public async Task Resolve_UserRolesAreSubsetOfServiceAccountRoles_GrantsTheUserSubset()
    {
        GivenServiceAccountWithRoles("AssetReader", "AssetWriter", "PipelineOperator");
        GivenUserWithRoles("AssetReader", "AssetWriter");

        var result = await ResolveAsync();

        result.IsGranted.Should().BeTrue();
        result.EffectiveRoleNames.Should().BeEquivalentTo("AssetReader", "AssetWriter");
        // The service account's extra authority must not travel with the user's identity.
        result.EffectiveRoleNames.Should().NotContain("PipelineOperator");
    }

    [Fact]
    public async Task Resolve_ServiceAccountRolesAreSubsetOfUserRoles_GrantsTheServiceAccountSubset()
    {
        GivenServiceAccountWithRoles("AssetReader");
        GivenUserWithRoles("AssetReader", "AssetWriter", "TenantAdministrator");

        var result = await ResolveAsync();

        result.IsGranted.Should().BeTrue();
        result.EffectiveRoleNames.Should().BeEquivalentTo("AssetReader");
        // The user's admin authority must not be borrowable through a narrow service account.
        result.EffectiveRoleNames.Should().NotContain("TenantAdministrator");
    }

    [Fact]
    public async Task Resolve_IdenticalRoleSets_GrantsAllOfThem()
    {
        GivenServiceAccountWithRoles("AssetReader", "AssetWriter");
        GivenUserWithRoles("AssetWriter", "AssetReader");

        var result = await ResolveAsync();

        result.EffectiveRoleNames.Should().BeEquivalentTo("AssetReader", "AssetWriter");
    }

    [Fact]
    public async Task Resolve_ServiceAccountHasNoRoles_GrantsNoRoles()
    {
        GivenServiceAccountWithRoles();
        GivenUserWithRoles("TenantAdministrator", "AssetReader");

        var result = await ResolveAsync();

        result.IsGranted.Should().BeTrue();
        result.EffectiveRoleNames.Should().BeEmpty();
    }

    [Fact]
    public async Task Resolve_UserHasNoRoles_GrantsNoRoles()
    {
        GivenServiceAccountWithRoles("TenantAdministrator", "AssetReader");
        GivenUserWithRoles();

        var result = await ResolveAsync();

        result.IsGranted.Should().BeTrue();
        result.EffectiveRoleNames.Should().BeEmpty();
    }

    [Fact]
    public async Task Resolve_RoleNamesDifferOnlyInCasing_StillIntersect()
    {
        // Role names are looked up by upper-invariant NormalizedName everywhere in this repository,
        // so a casing-only difference denotes the SAME role. A case-sensitive intersection would
        // silently collapse to empty here.
        GivenServiceAccountWithRoles("assetreader");
        GivenUserWithRoles("AssetReader");

        var result = await ResolveAsync();

        result.EffectiveRoleNames.Should().HaveCount(1);
        // The user-side spelling wins — the same spelling a non-delegated token would carry.
        result.EffectiveRoleNames.Should().Contain("AssetReader");
    }

    [Fact]
    public async Task Resolve_UnknownServiceAccountClient_IsDenied()
    {
        _clientStore.FindRtClientByIdAsync(ServiceAccountClientId).Returns((RtClient?)null);
        GivenUserWithRoles("AssetReader");

        var result = await ResolveAsync();

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(DelegationDenialReason.ServiceAccountNotFound);
        result.EffectiveRoleNames.Should().BeEmpty();
    }

    [Fact]
    public async Task Resolve_UnknownUser_IsDenied()
    {
        GivenServiceAccountWithRoles("AssetReader");
        _userRoleStore.FindByIdAsync(UserSubjectId, Arg.Any<CancellationToken>()).Returns((RtUser?)null);

        var result = await ResolveAsync();

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(DelegationDenialReason.UserNotFound);
        result.EffectiveRoleNames.Should().BeEmpty();
    }

    [Fact]
    public async Task Resolve_MalformedSubjectIdentifier_IsDeniedNotThrown()
    {
        GivenServiceAccountWithRoles("AssetReader");
        _userRoleStore.FindByIdAsync("not-an-rtid", Arg.Any<CancellationToken>())
            .Returns<RtUser?>(_ => throw new FormatException("not a valid ObjectId"));

        var result = await _sut.ResolveAsync(
            ServiceAccountClientId, "not-an-rtid", TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(DelegationDenialReason.UserNotFound);
    }

    [Fact]
    public async Task Resolve_EmptyClientId_IsDenied()
    {
        var result = await _sut.ResolveAsync(string.Empty, UserSubjectId, TestContext.Current.CancellationToken);

        result.DenialReason.Should().Be(DelegationDenialReason.ServiceAccountNotFound);
    }

    [Fact]
    public async Task Resolve_EmptySubject_IsDenied()
    {
        var result = await _sut.ResolveAsync(
            ServiceAccountClientId, string.Empty, TestContext.Current.CancellationToken);

        result.DenialReason.Should().Be(DelegationDenialReason.UserNotFound);
    }

    // ---------- helpers ----------

    private Task<DelegatedIdentityResult> ResolveAsync() =>
        _sut.ResolveAsync(ServiceAccountClientId, UserSubjectId, TestContext.Current.CancellationToken);

    private void GivenServiceAccountWithRoles(params string[] roleNames)
    {
        var rtClient = new RtClient { RtId = OctoObjectId.GenerateNewId(), ClientId = ServiceAccountClientId };
        _clientStore.FindRtClientByIdAsync(ServiceAccountClientId).Returns(rtClient);
        _clientRoleStore.GetEffectiveRoleNamesAsync(rtClient.RtId)
            .Returns<IReadOnlySet<string>>(new HashSet<string>(roleNames));
    }

    private void GivenUserWithRoles(params string[] roleNames)
    {
        var user = new RtUser { RtId = new OctoObjectId(UserSubjectId), UserName = "alice" };
        _userRoleStore.FindByIdAsync(UserSubjectId, Arg.Any<CancellationToken>()).Returns(user);
        _userRoleStore.GetRolesAsync(user, Arg.Any<CancellationToken>())
            .Returns<IList<string>>(roleNames.ToList());
    }
}
