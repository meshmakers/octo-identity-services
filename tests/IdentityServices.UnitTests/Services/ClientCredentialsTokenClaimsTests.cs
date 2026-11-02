using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5032 — pins that a <c>client_credentials</c> token carries the <c>tenant_id</c> of the
///     tenant it was issued for.
/// </summary>
/// <remarks>
///     <para>
///         Without this claim the tenant gate in octo-common-services
///         (<c>TenantAuthorizationMiddleware</c>) has nothing to check a service token against, which
///         is why it skipped the check entirely — and, because the consuming services run with
///         <c>ValidateAudience = false</c>, why every client-credentials client of this authority
///         could address every tenant.
///     </para>
///     <para>
///         The claim must be present even when the client has no roles at all — the pre-migration
///         role-injection path returned early in that case, and the OpenIddict port keeps the
///         ordering (tenant stamped before the roles) for the same reason.
///     </para>
///     <para>
///         This file covers the <b>decision</b> (which tenant is bound).
///         <c>ClientCredentialsClaimCompositionTests</c> covers the composition (the decision
///         actually reaching the issued identity), and
///         <c>TokenShapeGoldenTests.ClientCredentials_AccessTokenShape_MatchesGoldenBaseline</c>
///         pins it on the wire.
///     </para>
/// </remarks>
public class ClientCredentialsTokenClaimsTests
{
    private const string ClientId = "octo-pipeline-sa-68b0000000000000000000a1";
    private const string RequestTenantId = "meshtest";
    private const string SystemTenantId = "octosystem";

    private readonly IClientMirrorProvisioningService _mirrorService =
        Substitute.For<IClientMirrorProvisioningService>();

    private readonly IIdentityAuditService _auditService = Substitute.For<IIdentityAuditService>();
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly HttpContextAccessor _httpContextAccessor = new();

    public ClientCredentialsTokenClaimsTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);
        _mirrorService.GetMirrorsAsync(Arg.Any<string>(), Arg.Any<string>())
            .Returns((IReadOnlyList<RtClientMirror>)Array.Empty<RtClientMirror>());
    }

    private ClientCredentialsTenantProcessor CreateProcessor() => new(
        _mirrorService, _httpContextAccessor, _systemContext, _auditService,
        NullLogger<ClientCredentialsTenantProcessor>.Instance);

    /// <summary>Simulates what <c>OidcTenantResolutionMiddleware</c> writes for this request.</summary>
    private void ResolveRequestToTenant(string? tenantId)
    {
        var httpContext = new DefaultHttpContext();
        if (tenantId != null)
        {
            httpContext.Items[InfrastructureCommon.TenantIdName] = tenantId;
        }

        _httpContextAccessor.HttpContext = httpContext;
    }

    private static RtClient UnmirroredClient() => new RtClientBuilder()
        .WithClientId(ClientId)
        .WithGrantTypes("client_credentials")
        .Build();

    [Fact]
    public async Task ClientCredentialsToken_IsBoundToTheResolvedTenant()
    {
        ResolveRequestToTenant(RequestTenantId);

        var outcome = await CreateProcessor().ResolveAsync(ClientId, UnmirroredClient());

        outcome.Error.Should().BeNull();
        outcome.TenantId.Should().Be(RequestTenantId);
    }

    [Fact]
    public async Task ClientCredentialsToken_WithoutAcrValues_CarriesTheSystemTenant()
    {
        // No acr_values on /connect/token: the client store resolved against the system tenant, so
        // that is the tenant the token belongs to — the claim must state that, not stay absent.
        ResolveRequestToTenant(null);

        var outcome = await CreateProcessor().ResolveAsync(ClientId, UnmirroredClient());

        outcome.Error.Should().BeNull();
        outcome.TenantId.Should().Be(SystemTenantId);
    }

    [Fact]
    public async Task ClientCredentialsToken_WithNoHttpContext_FallsBackToTheSystemTenant()
    {
        _httpContextAccessor.HttpContext = null;

        var outcome = await CreateProcessor().ResolveAsync(ClientId, UnmirroredClient());

        outcome.TenantId.Should().Be(SystemTenantId);
    }

    /// <summary>
    ///     A client id the resolved directory does not know cannot have been mirrored from there, and
    ///     OpenIddict would have failed the client authentication long before this point. Refusing
    ///     here would only turn an <c>invalid_client</c> into a confusing <c>invalid_request</c>.
    /// </summary>
    [Fact]
    public async Task UnknownClient_WithoutAcrValues_IsNotRefused()
    {
        ResolveRequestToTenant(null);

        var outcome = await CreateProcessor().ResolveAsync(ClientId, null);

        outcome.Error.Should().BeNull();
        outcome.TenantId.Should().Be(SystemTenantId);
    }

    /// <summary>
    ///     Without a configured system tenant there is nothing to fall back to. The token is issued
    ///     without the claim rather than with a guessed one — the pre-migration behaviour.
    /// </summary>
    [Fact]
    public async Task WithoutASystemTenant_TheTokenIsIssuedUnstamped()
    {
        _systemContext.TenantId.Returns(string.Empty);
        ResolveRequestToTenant(null);

        var outcome = await CreateProcessor().ResolveAsync(ClientId, UnmirroredClient());

        outcome.Error.Should().BeNull();
        outcome.TenantId.Should().BeNull();
    }
}

/// <summary>
///     AB#5032 — the composition half: the bound tenant actually reaches the issued identity as an
///     unprefixed <c>tenant_id</c> claim, and it is routed into the <b>access</b> token.
/// </summary>
/// <remarks>
///     Split out from the decision tests deliberately. The pre-migration validator could be tested
///     in one piece because it both decided and stamped; under OpenIddict the stamping lives in
///     <c>TokenEndpointController.HandleClientCredentialsAsync</c> and the routing in
///     <see cref="OctoClaimsDestinations" />. A destination mapping that dropped <c>tenant_id</c>
///     would leave every unit test above green while no consumer ever sees the claim, which is
///     exactly the AB#5032 failure mode.
/// </remarks>
public class ClientCredentialsClaimCompositionTests
{
    [Fact]
    public void TenantIdClaim_IsDestinedIntoTheAccessToken()
    {
        var destinations = OctoClaimsDestinations
            .Resolve(new Claim(OctoClaimTypes.TenantId, "meshtest"))
            .ToList();

        destinations.Should().Contain(Destinations.AccessToken,
            "TenantAuthorizationMiddleware reads tenant_id off the access token");
    }

    /// <summary>
    ///     The claim type is a wire contract shared with octo-common-services, the MCP server and the
    ///     mesh adapter — all of which look for exactly <c>tenant_id</c>. Duende would have emitted
    ///     <c>client_tenant_id</c> unless its prefix was cleared; OpenIddict has no prefix, so the
    ///     only thing left to protect is the literal.
    /// </summary>
    [Fact]
    public void TenantIdClaimType_IsUnprefixed()
    {
        OctoClaimTypes.TenantId.Should().Be("tenant_id");
    }
}
