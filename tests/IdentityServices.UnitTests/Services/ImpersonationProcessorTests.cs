using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5114 — protocol-level behaviour of the impersonation grant, driven through
///     <see cref="ImpersonationProcessor" />.
/// </summary>
/// <remarks>
///     The authorization arithmetic (MayActAs edge, target roles) is pinned by
///     <see cref="ImpersonatedIdentityResolverTests" /> and the claim composition by
///     <see cref="ImpersonationClaimCompositionTests" />; this class only exercises the protocol
///     adapter: parameter validation, the offline_access prohibition, the tenant gate and the
///     mapping of policy denials onto OAuth errors.
/// </remarks>
public class ImpersonationProcessorTests
{
    private const string TenantId = "acme";
    private const string ActorClientId = "adapter-chart-client";
    private const string TargetClientId = "octo-pipeline-sa-acme";

    private readonly IIdentityAuditService _auditService = Substitute.For<IIdentityAuditService>();
    private readonly IHttpContextAccessor _httpContextAccessor = Substitute.For<IHttpContextAccessor>();

    private readonly IImpersonatedIdentityResolver _resolver =
        Substitute.For<IImpersonatedIdentityResolver>();

    private readonly ImpersonationProcessor _sut;

    public ImpersonationProcessorTests()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items[InfrastructureCommon.TenantIdName] = TenantId;
        _httpContextAccessor.HttpContext.Returns(httpContext);

        _resolver.ResolveAsync(ActorClientId, TargetClientId, Arg.Any<CancellationToken>())
            .Returns(ImpersonatedIdentityResult.Granted(RoleSet("CommunicationManagement")));

        _sut = new ImpersonationProcessor(
            _resolver, _httpContextAccessor, _auditService,
            NullLogger<ImpersonationProcessor>.Instance);
    }

    /// <summary>The happy path: the outcome names the TARGET and carries the TARGET's roles.</summary>
    [Fact]
    public async Task AuthorizedActor_ReceivesTheTargetsIdentity()
    {
        var outcome = await Process();

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.TargetClientId.Should().Be(TargetClientId);
        outcome.TenantId.Should().Be(TenantId);
        outcome.EffectiveRoleNames.Should().BeEquivalentTo("CommunicationManagement");
        await _auditService.DidNotReceive().StoreFailureAsync(Arg.Any<string>(), Arg.Any<string>());
    }

    /// <summary>
    ///     Same prohibition, same rationale as the delegation grant: the MayActAs authorization and
    ///     the target's roles are evaluated at issuance; a refresh would freeze them past
    ///     revocation. Rejected before the resolver ever runs.
    /// </summary>
    [Fact]
    public async Task OfflineAccessRequested_IsRejectedAsInvalidScope_BeforeAnyPolicyWork()
    {
        var outcome = await Process(scopes: ["openid", "offline_access"]);

        outcome.Error.Should().Be(Errors.InvalidScope);
        outcome.ErrorDescription.Should().Contain("offline_access");
        outcome.ErrorDescription.Should().ContainEquivalentOf("refresh");
        await _resolver.DidNotReceive().ResolveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _auditService.Received(1).StoreFailureAsync("Impersonation Failure",
            Arg.Is<string>(m => m.Contains(ActorClientId) && m.Contains("offline_access")));
    }

    /// <summary>A scope merely containing "offline_access" as a prefix is a different scope.</summary>
    [Fact]
    public async Task ScopeMerelyContainingOfflineAccessAsASubstring_IsNotRejected()
    {
        var outcome = await Process(scopes: ["offline_access_report"]);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
    }

    [Fact]
    public async Task MissingRequestedClientId_IsRejectedAsInvalidRequest()
    {
        var outcome = await Process(requestedClientId: null);

        outcome.Error.Should().Be(Errors.InvalidRequest);
        outcome.ErrorDescription.Should().Contain(ImpersonationConstants.RequestedClientIdParameter);
    }

    [Fact]
    public async Task MissingAcrValues_IsRejectedAsInvalidRequest()
    {
        var outcome = await Process(acrValues: null);

        outcome.Error.Should().Be(Errors.InvalidRequest);
        outcome.ErrorDescription.Should().Contain("acr_values");
    }

    /// <summary>
    ///     acr_values names a tenant the request was not wired to — authorizing against the wrong
    ///     database is refused outright.
    /// </summary>
    [Fact]
    public async Task RequestWiredToADifferentTenant_IsRejectedAsInvalidTarget()
    {
        var outcome = await Process(acrValues: "tenant:other-tenant");

        outcome.Error.Should().Be(Errors.InvalidTarget);
        await _resolver.DidNotReceive().ResolveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _auditService.Received(1).StoreFailureAsync("Impersonation Failure",
            Arg.Is<string>(m => m.Contains("other-tenant")));
    }

    [Fact]
    public async Task UnknownTargetClient_IsRejectedAsInvalidGrant()
    {
        _resolver.ResolveAsync(ActorClientId, TargetClientId, Arg.Any<CancellationToken>())
            .Returns(ImpersonatedIdentityResult.Denied(ImpersonationDenialReason.TargetNotFound));

        var outcome = await Process();

        outcome.Error.Should().Be(Errors.InvalidGrant);
        outcome.ErrorDescription.Should().Contain("not provisioned");
    }

    [Fact]
    public async Task DisabledTargetClient_IsRejectedAsInvalidGrant()
    {
        _resolver.ResolveAsync(ActorClientId, TargetClientId, Arg.Any<CancellationToken>())
            .Returns(ImpersonatedIdentityResult.Denied(ImpersonationDenialReason.TargetDisabled));

        var outcome = await Process();

        outcome.Error.Should().Be(Errors.InvalidGrant);
        outcome.ErrorDescription.Should().Contain("disabled");
    }

    /// <summary>THE fail-closed case: no MayActAs edge, no token — and the audit trail records it.</summary>
    [Fact]
    public async Task MissingMayActAsEdge_IsRejectedAsInvalidGrant_AndAudited()
    {
        _resolver.ResolveAsync(ActorClientId, TargetClientId, Arg.Any<CancellationToken>())
            .Returns(ImpersonatedIdentityResult.Denied(ImpersonationDenialReason.NotAuthorized));

        var outcome = await Process();

        outcome.Error.Should().Be(Errors.InvalidGrant);
        outcome.ErrorDescription.Should().Contain("not authorized");
        await _auditService.Received(1).StoreFailureAsync("Impersonation Failure",
            Arg.Is<string>(m =>
                m.Contains(ActorClientId) && m.Contains(TargetClientId) && m.Contains("NotAuthorized")));
    }

    [Fact]
    public async Task UnauthenticatedClient_IsRejectedAsInvalidClient()
    {
        var outcome = await _sut.ProcessAsync(actorClientId: null, TargetClientId,
            $"tenant:{TenantId}", ["openid"], TestContext.Current.CancellationToken);

        outcome.Error.Should().Be(Errors.InvalidClient);
    }

    // ---------- helpers ----------

    private Task<ImpersonationProcessor.ImpersonationOutcome> Process(
        string? requestedClientId = TargetClientId,
        string? acrValues = $"tenant:{TenantId}",
        IReadOnlyCollection<string>? scopes = null) =>
        _sut.ProcessAsync(ActorClientId, requestedClientId, acrValues, scopes ?? ["openid"],
            TestContext.Current.CancellationToken);

    private static IReadOnlySet<string> RoleSet(params string[] roles) =>
        new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);
}
