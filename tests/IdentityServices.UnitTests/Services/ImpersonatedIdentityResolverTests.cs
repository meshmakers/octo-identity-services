using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5114 — the impersonation authority rule: the ONLY thing that authorizes an actor client
///     to become a target client is the explicit <c>MayActAs</c> edge actor→target, and the issued
///     authority is the TARGET's role set — the actor's roles never participate.
/// </summary>
/// <remarks>
///     <see cref="ImpersonatedIdentityResolver" /> is protocol-free (like
///     <see cref="DelegatedIdentityResolver" />), so the policy is exercised here directly against
///     substituted stores. The real MayActAs association query and the effective-role resolution
///     against MongoDB are pinned by <c>ImpersonatedIdentityIntegrationTests</c>.
/// </remarks>
public class ImpersonatedIdentityResolverTests
{
    private const string ActorClientId = "adapter-chart-client";
    private const string TargetClientId = "octo-pipeline-sa-tenant";

    private readonly IClientImpersonationStore _impersonationStore =
        Substitute.For<IClientImpersonationStore>();

    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();
    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly ImpersonatedIdentityResolver _sut;

    private readonly RtClient _actorClient = new()
        { RtId = OctoObjectId.GenerateNewId(), ClientId = ActorClientId, Enabled = true };

    private readonly RtClient _targetClient = new()
        { RtId = OctoObjectId.GenerateNewId(), ClientId = TargetClientId, Enabled = true };

    public ImpersonatedIdentityResolverTests()
    {
        _sut = new ImpersonatedIdentityResolver(
            _clientStore, _clientRoleStore, _impersonationStore,
            NullLogger<ImpersonatedIdentityResolver>.Instance);
    }

    [Fact]
    public async Task Resolve_WithMayActAsEdge_GrantsTheTargetsRoles()
    {
        GivenBothClientsExist();
        GivenEdge(exists: true);
        _clientRoleStore.GetEffectiveRoleNamesAsync(_targetClient.RtId)
            .Returns(RoleSet("CommunicationManagement", "AssetReader"));

        var result = await ResolveAsync();

        result.IsGranted.Should().BeTrue();
        result.DenialReason.Should().Be(ImpersonationDenialReason.None);
        result.EffectiveRoleNames.Should().BeEquivalentTo("CommunicationManagement", "AssetReader");
    }

    /// <summary>
    ///     The impersonated token is the TARGET's identity — the actor's own role set must never be
    ///     read, let alone merged in.
    /// </summary>
    [Fact]
    public async Task Resolve_NeverReadsTheActorsRoles()
    {
        GivenBothClientsExist();
        GivenEdge(exists: true);
        _clientRoleStore.GetEffectiveRoleNamesAsync(_targetClient.RtId).Returns(RoleSet("AssetReader"));

        await ResolveAsync();

        await _clientRoleStore.Received(1).GetEffectiveRoleNamesAsync(_targetClient.RtId);
        await _clientRoleStore.DidNotReceive().GetEffectiveRoleNamesAsync(_actorClient.RtId);
    }

    /// <summary>THE authorization model: no edge, no token — regardless of anything else.</summary>
    [Fact]
    public async Task Resolve_WithoutMayActAsEdge_IsDeniedAsNotAuthorized()
    {
        GivenBothClientsExist();
        GivenEdge(exists: false);

        var result = await ResolveAsync();

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.NotAuthorized);
        result.EffectiveRoleNames.Should().BeEmpty();
        await _clientRoleStore.DidNotReceive().GetEffectiveRoleNamesAsync(Arg.Any<OctoObjectId>());
    }

    [Fact]
    public async Task Resolve_UnknownTargetClient_IsDeniedAsTargetNotFound()
    {
        _clientStore.FindRtClientByIdAsync(ActorClientId).Returns(_actorClient);
        _clientStore.FindRtClientByIdAsync(TargetClientId).Returns((RtClient?)null);

        var result = await ResolveAsync();

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.TargetNotFound);
    }

    /// <summary>
    ///     A disabled target cannot obtain a token with its own secret — impersonation must not be
    ///     a side door around the disable switch.
    /// </summary>
    [Fact]
    public async Task Resolve_DisabledTargetClient_IsDeniedAsTargetDisabled()
    {
        _targetClient.Enabled = false;
        GivenBothClientsExist();
        GivenEdge(exists: true);

        var result = await ResolveAsync();

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.TargetDisabled);
    }

    /// <summary>
    ///     The actor authenticated against OpenIddict, but only a tenant-local Client entity can
    ///     hold the MayActAs edge — an actor unknown to THIS tenant is denied.
    /// </summary>
    [Fact]
    public async Task Resolve_ActorNotProvisionedInTenant_IsDeniedAsActorNotFound()
    {
        _clientStore.FindRtClientByIdAsync(ActorClientId).Returns((RtClient?)null);
        _clientStore.FindRtClientByIdAsync(TargetClientId).Returns(_targetClient);

        var result = await ResolveAsync();

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.ActorNotFound);
    }

    /// <summary>The gate-only entry point (used by the on-behalf-of extension) mirrors ResolveAsync.</summary>
    [Fact]
    public async Task AuthorizeActor_WithEdge_ReturnsNone_AndResolvesNoRoles()
    {
        GivenBothClientsExist();
        GivenEdge(exists: true);

        var denial = await _sut.AuthorizeActorAsync(ActorClientId, TargetClientId,
            TestContext.Current.CancellationToken);

        denial.Should().Be(ImpersonationDenialReason.None);
        await _clientRoleStore.DidNotReceive().GetEffectiveRoleNamesAsync(Arg.Any<OctoObjectId>());
    }

    [Fact]
    public async Task AuthorizeActor_WithoutEdge_ReturnsNotAuthorized()
    {
        GivenBothClientsExist();
        GivenEdge(exists: false);

        var denial = await _sut.AuthorizeActorAsync(ActorClientId, TargetClientId,
            TestContext.Current.CancellationToken);

        denial.Should().Be(ImpersonationDenialReason.NotAuthorized);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Resolve_BlankTargetClientId_IsDeniedWithoutStoreCalls(string? targetClientId)
    {
        var result = await _sut.ResolveAsync(ActorClientId, targetClientId!,
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.TargetNotFound);
        await _clientStore.DidNotReceive().FindRtClientByIdAsync(Arg.Any<string>());
    }

    // ---------- helpers ----------

    private void GivenBothClientsExist()
    {
        _clientStore.FindRtClientByIdAsync(ActorClientId).Returns(_actorClient);
        _clientStore.FindRtClientByIdAsync(TargetClientId).Returns(_targetClient);
    }

    private void GivenEdge(bool exists)
    {
        _impersonationStore.HasMayActAsEdgeAsync(_actorClient.RtId, _targetClient.RtId)
            .Returns(exists);
    }

    private Task<ImpersonatedIdentityResult> ResolveAsync() =>
        _sut.ResolveAsync(ActorClientId, TargetClientId, TestContext.Current.CancellationToken);

    private static IReadOnlySet<string> RoleSet(params string[] roles) =>
        new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);
}
