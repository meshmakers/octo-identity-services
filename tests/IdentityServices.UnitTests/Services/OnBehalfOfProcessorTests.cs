using System.Security.Cryptography;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5026 — protocol-level behaviour of the delegation ("on-behalf-of") grant, driven through
///     <see cref="OnBehalfOfProcessor" /> with a genuinely signed <c>subject_token</c>.
/// </summary>
/// <remarks>
///     <para>
///         The focus here is the <b>refresh-token prohibition</b>. The role intersection is computed
///         at issuance; a <c>grant_type=refresh_token</c> request rebuilds the access token from the
///         stored principal without ever re-entering this processor, so the intersection would
///         freeze and a role revoked on either side (service account or user) would keep working for
///         the refresh token's whole lifetime. The grant therefore refuses <c>offline_access</c>
///         outright instead of merely documenting the hazard.
///     </para>
///     <para>
///         The intersection arithmetic itself is pinned by <c>DelegatedIdentityResolverTests</c>
///         and the claim composition by <see cref="DelegationClaimCompositionTests" />; this class
///         only exercises the protocol adapter.
///     </para>
/// </remarks>
public class OnBehalfOfProcessorTests
{
    private const string Authority = "https://identity.example.com";
    private const string TenantId = "acme";
    private const string ServiceAccountClientId = "octo-pipeline-sa";
    private const string UserSubjectId = "68b0000000000000000000a1";

    private readonly IIdentityAuditService _auditService = Substitute.For<IIdentityAuditService>();
    private readonly IHttpContextAccessor _httpContextAccessor = Substitute.For<IHttpContextAccessor>();
    private readonly IImpersonatedIdentityResolver _impersonationResolver =
        Substitute.For<IImpersonatedIdentityResolver>();
    private readonly IDelegatedIdentityResolver _resolver = Substitute.For<IDelegatedIdentityResolver>();
    private readonly RsaSecurityKey _signingKey = new(RSA.Create(2048)) { KeyId = "unit-test-key" };
    private readonly OnBehalfOfProcessor _sut;

    public OnBehalfOfProcessorTests()
    {
        var serverOptions = Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>();
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256));
        serverOptions.CurrentValue.Returns(options);

        var httpContext = new DefaultHttpContext();
        httpContext.Items[InfrastructureCommon.TenantIdName] = TenantId;
        _httpContextAccessor.HttpContext.Returns(httpContext);

        _resolver.ResolveAsync(ServiceAccountClientId, UserSubjectId, Arg.Any<CancellationToken>())
            .Returns(DelegatedIdentityResult.Granted(
                RoleSet("AssetReader"), RoleSet("AssetReader", "PipelineOperator"),
                RoleSet("AssetReader", "TenantAdministrator")));

        _sut = new OnBehalfOfProcessor(
            serverOptions,
            Options.Create(new OctoIdentityServicesOptions
            {
                AuthorityUrl = Authority,
                AutoMapperLicenseKey = string.Empty
            }),
            _resolver,
            _impersonationResolver,
            _httpContextAccessor,
            _auditService,
            NullLogger<OnBehalfOfProcessor>.Instance);
    }

    /// <summary>
    ///     THE regression this hardening exists for: a delegating client that asks for a refresh
    ///     token must be refused, not quietly served a token whose role intersection can never be
    ///     re-evaluated.
    /// </summary>
    [Fact]
    public async Task OfflineAccessRequested_IsRejectedAsInvalidScope()
    {
        var outcome = await Process(scopes: ["openid", "octo_api", "offline_access"]);

        outcome.Error.Should().Be(Errors.InvalidScope);
    }

    /// <summary>
    ///     The error has to say <b>why</b>, otherwise an integrator hitting it has no path from
    ///     "invalid_scope" to "delegated tokens are not refreshable by design".
    /// </summary>
    [Fact]
    public async Task OfflineAccessRejection_ExplainsThatTheIntersectionCannotBeReEvaluated()
    {
        var outcome = await Process(scopes: ["offline_access"]);

        outcome.ErrorDescription.Should().Contain("offline_access");
        outcome.ErrorDescription.Should().Contain("intersection");
        outcome.ErrorDescription.Should().ContainEquivalentOf("refresh");
    }

    [Fact]
    public async Task OfflineAccessRejection_PersistsADelegationFailureAudit()
    {
        var outcome = await Process(scopes: ["openid", "offline_access"]);

        outcome.Error.Should().Be(Errors.InvalidScope);
        await _auditService.Received(1).StoreFailureAsync("Delegation Failure",
            Arg.Is<string>(m => m.Contains(ServiceAccountClientId) && m.Contains("offline_access")));
    }

    /// <summary>
    ///     A structurally impossible request is refused before any cryptography or database work —
    ///     and, more importantly, before anything reads the unvalidated <c>subject_token</c>.
    /// </summary>
    [Fact]
    public async Task OfflineAccessRejection_HappensBeforeTheSubjectTokenIsValidatedOrRolesResolved()
    {
        await Process(scopes: ["offline_access"]);

        await _resolver.DidNotReceive().ResolveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>The unchanged happy path: without <c>offline_access</c> the grant still issues.</summary>
    [Fact]
    public async Task WithoutOfflineAccess_TheGrantSucceedsUnchanged()
    {
        var outcome = await Process(scopes: ["openid", "octo_api"]);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.UserSubjectId.Should().Be(UserSubjectId, "the delegated token runs on the USER's sub");
        outcome.TenantId.Should().Be(TenantId);
        outcome.EffectiveRoleNames.Should().BeEquivalentTo("AssetReader");

        await _auditService.DidNotReceive().StoreFailureAsync(Arg.Any<string>(), Arg.Any<string>());
    }

    /// <summary>A request with no <c>scope</c> parameter at all is the normal delegation shape.</summary>
    [Fact]
    public async Task NoScopeParameterAtAll_TheGrantSucceedsUnchanged()
    {
        var outcome = await Process(scopes: []);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
    }

    /// <summary>
    ///     Scopes arrive tokenised — a scope that merely contains "offline_access" as a prefix is a
    ///     different scope and must not be swept up.
    /// </summary>
    [Fact]
    public async Task ScopeMerelyContainingOfflineAccessAsASubstring_IsNotRejected()
    {
        var outcome = await Process(scopes: ["openid", "offline_access_report"]);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
    }

    [Fact]
    public async Task SubjectTokenFromAnotherTenant_IsRejectedAsInvalidTarget()
    {
        var outcome = await Process(scopes: ["openid"],
            subjectToken: CreateSubjectToken(tenantId: "other-tenant"));

        outcome.Error.Should().Be(Errors.InvalidTarget);
        outcome.ErrorDescription.Should().Contain("same-tenant");
    }

    [Fact]
    public async Task MissingAcrValues_IsRejectedAsInvalidRequest()
    {
        var outcome = await _sut.ProcessAsync(ServiceAccountClientId, requestedClientId: null,
            CreateSubjectToken(),
            "urn:ietf:params:oauth:token-type:access_token", acrValues: null, ["openid"],
            TestContext.Current.CancellationToken);

        outcome.Error.Should().Be(Errors.InvalidRequest);
        outcome.ErrorDescription.Should().Contain("acr_values");
    }

    // ---------- AB#5114: requested_client_id — delegation without the SA's secret ----------

    /// <summary>
    ///     The AB#5114 happy path: an actor client (the adapter's own client) that holds a
    ///     MayActAs edge to the SA delegates THROUGH the SA. The intersection must be computed
    ///     for the SA (never the actor) and the outcome must name the SA so the act claim does.
    /// </summary>
    [Fact]
    public async Task RequestedClientIdWithMayActAsEdge_DelegatesThroughTheServiceAccount()
    {
        _impersonationResolver.AuthorizeActorAsync(ActorClientId, ServiceAccountClientId,
                Arg.Any<CancellationToken>())
            .Returns(ImpersonationDenialReason.None);

        var outcome = await ProcessAsActor(requestedClientId: ServiceAccountClientId);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.UserSubjectId.Should().Be(UserSubjectId);
        outcome.EffectiveRoleNames.Should().BeEquivalentTo(["AssetReader"],
            "the intersection is SA roles ∩ user roles — the actor's roles never participate");
        outcome.ServiceAccountClientId.Should().Be(ServiceAccountClientId,
            "act must name the SA the delegation ran through, not the actor that authenticated");

        // The intersection was resolved for the SA — the actor's identity contributes nothing.
        await _resolver.Received(1).ResolveAsync(ServiceAccountClientId, UserSubjectId,
            Arg.Any<CancellationToken>());
        await _resolver.DidNotReceive().ResolveAsync(ActorClientId, Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    /// <summary>No MayActAs edge — the actor must not reach the delegation at all.</summary>
    [Fact]
    public async Task RequestedClientIdWithoutMayActAsEdge_FailsClosed()
    {
        _impersonationResolver.AuthorizeActorAsync(ActorClientId, ServiceAccountClientId,
                Arg.Any<CancellationToken>())
            .Returns(ImpersonationDenialReason.NotAuthorized);

        var outcome = await ProcessAsActor(requestedClientId: ServiceAccountClientId);

        outcome.Error.Should().Be(Errors.InvalidGrant);
        outcome.ErrorDescription.Should().Contain("not authorized");
        await _resolver.DidNotReceive().ResolveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _auditService.Received(1).StoreFailureAsync("Delegation Failure",
            Arg.Is<string>(m => m.Contains(ActorClientId) && m.Contains(ServiceAccountClientId)));
    }

    /// <summary>
    ///     requested_client_id naming a client the edge does not allow (here: an SA that does not
    ///     even exist in the tenant) is refused with the same wording as an unknown SA today.
    /// </summary>
    [Fact]
    public async Task RequestedClientIdNamingAnUnknownServiceAccount_IsRejectedAsInvalidClient()
    {
        _impersonationResolver.AuthorizeActorAsync(ActorClientId, "octo-pipeline-sa-other",
                Arg.Any<CancellationToken>())
            .Returns(ImpersonationDenialReason.TargetNotFound);

        var outcome = await ProcessAsActor(requestedClientId: "octo-pipeline-sa-other");

        outcome.Error.Should().Be(Errors.InvalidClient);
        outcome.ErrorDescription.Should().Contain("not provisioned");
    }

    /// <summary>
    ///     The regression guard for plain on-behalf-of: without requested_client_id nothing may
    ///     change — no edge check, intersection and act for the authenticated client itself.
    /// </summary>
    [Fact]
    public async Task WithoutRequestedClientId_TheOriginalSemanticsAreUntouched()
    {
        var outcome = await Process(scopes: ["openid"]);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.ServiceAccountClientId.Should().Be(ServiceAccountClientId);
        await _impersonationResolver.DidNotReceive().AuthorizeActorAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    ///     requested_client_id naming the authenticated client itself is the original grant — a
    ///     redundant parameter must not suddenly demand a self-edge.
    /// </summary>
    [Fact]
    public async Task RequestedClientIdNamingTheAuthenticatedClientItself_NeedsNoEdge()
    {
        var outcome = await _sut.ProcessAsync(ServiceAccountClientId, ServiceAccountClientId,
            CreateSubjectToken(), "urn:ietf:params:oauth:token-type:access_token",
            $"tenant:{TenantId}", ["openid"], TestContext.Current.CancellationToken);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.ServiceAccountClientId.Should().Be(ServiceAccountClientId);
        await _impersonationResolver.DidNotReceive().AuthorizeActorAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ---------- helpers ----------

    private const string ActorClientId = "adapter-chart-client";

    private Task<OnBehalfOfProcessor.DelegationOutcome> Process(
        IReadOnlyCollection<string> scopes, string? subjectToken = null) =>
        _sut.ProcessAsync(ServiceAccountClientId, requestedClientId: null,
            subjectToken ?? CreateSubjectToken(),
            "urn:ietf:params:oauth:token-type:access_token", $"tenant:{TenantId}", scopes,
            TestContext.Current.CancellationToken);

    private Task<OnBehalfOfProcessor.DelegationOutcome> ProcessAsActor(string requestedClientId) =>
        _sut.ProcessAsync(ActorClientId, requestedClientId, CreateSubjectToken(),
            "urn:ietf:params:oauth:token-type:access_token", $"tenant:{TenantId}", ["openid"],
            TestContext.Current.CancellationToken);

    /// <summary>
    ///     A genuinely signed user access token: same issuer and signing key the processor resolves
    ///     from the OpenIddict server options, carrying <c>sub</c> and <c>tenant_id</c>.
    /// </summary>
    private string CreateSubjectToken(string? tenantId = null) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority.EnsureEndsWith("/"),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object>
            {
                [Claims.Subject] = UserSubjectId,
                ["tenant_id"] = tenantId ?? TenantId
            }
        });

    private static IReadOnlySet<string> RoleSet(params string[] roles) =>
        new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);
}
