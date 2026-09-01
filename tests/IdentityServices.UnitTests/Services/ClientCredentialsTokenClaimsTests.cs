using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityModel;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5032 — pins that a <c>client_credentials</c> token carries the <c>tenant_id</c> of the
///     tenant it was issued for.
/// </summary>
/// <remarks>
///     Without this claim the tenant gate in octo-common-services
///     (<c>TenantAuthorizationMiddleware</c>) has nothing to check a service token against, which is
///     why it skipped the check entirely — and, because the consuming services run with
///     <c>ValidateAudience = false</c>, why every client-credentials client of this authority could
///     address every tenant. The claim must be <b>unprefixed</b> (Duende would otherwise emit
///     <c>client_tenant_id</c>) and must be present even when the client has no roles at all — the
///     old role-injection path returned early in that case.
/// </remarks>
public class ClientCredentialsTokenClaimsTests
{
    private const string ClientId = "octo-pipeline-sa-68b0000000000000000000a1";
    private const string RequestTenantId = "meshtest";
    private const string SystemTenantId = "octosystem";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly HttpContextAccessor _httpContextAccessor = new();

    public ClientCredentialsTokenClaimsTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);
        // No RtClient for this id — the role branch bails out, which is exactly the case that used
        // to leave the token without any custom claim at all.
        _clientStore.FindRtClientByIdAsync(Arg.Any<string>()).Returns((Persistence.IdentityCkModel.Generated
            .System.Identity.v2.RtClient?)null);
    }

    private ClientCredentialsRoleTokenValidator CreateValidator() => new(
        _clientStore, _clientRoleStore, _httpContextAccessor, _systemContext,
        NullLogger<ClientCredentialsRoleTokenValidator>.Instance);

    private static CustomTokenRequestValidationContext CreateContext(string grantType, string clientId = ClientId)
    {
        var request = new ValidatedTokenRequest { GrantType = grantType };
        request.SetClient(new Client { ClientId = clientId });
        return new CustomTokenRequestValidationContext
        {
            Result = new TokenRequestValidationResult(request)
        };
    }

    private void ResolveRequestToTenant(string? tenantId)
    {
        var httpContext = new DefaultHttpContext();
        if (tenantId != null)
        {
            httpContext.Items[InfrastructureCommon.TenantIdName] = tenantId;
        }

        _httpContextAccessor.HttpContext = httpContext;
    }

    [Fact]
    public async Task ClientCredentialsToken_CarriesTheResolvedTenantIdUnprefixed()
    {
        ResolveRequestToTenant(RequestTenantId);
        var context = CreateContext(GrantType.ClientCredentials);

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        var request = context.Result!.ValidatedRequest;
        request.ClientClaims.Should()
            .ContainSingle(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType)
            .Which.Value.Should().Be(RequestTenantId);

        // Duende prefixes ClientClaims with ClientClaimsPrefix ("client_" by default). A prefixed
        // claim would never be found by the consuming middleware.
        request.Client.ClientClaimsPrefix.Should().BeNull();
    }

    [Fact]
    public async Task ClientCredentialsToken_WithoutAcrValues_CarriesTheSystemTenant()
    {
        // No acr_values on /connect/token: the client store resolved against the system tenant, so
        // that is the tenant the token belongs to — the claim must state that, not stay absent.
        ResolveRequestToTenant(null);
        var context = CreateContext(GrantType.ClientCredentials);

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.ValidatedRequest.ClientClaims.Should()
            .ContainSingle(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType)
            .Which.Value.Should().Be(SystemTenantId);
    }

    [Fact]
    public async Task ClientCredentialsToken_WithNoHttpContext_FallsBackToTheSystemTenant()
    {
        _httpContextAccessor.HttpContext = null;
        var context = CreateContext(GrantType.ClientCredentials);

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.ValidatedRequest.ClientClaims.Should()
            .ContainSingle(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType)
            .Which.Value.Should().Be(SystemTenantId);
    }

    [Fact]
    public async Task TenantIdClaim_IsNotDuplicatedWhenTheClientAlreadyCarriesOne()
    {
        ResolveRequestToTenant(RequestTenantId);
        var context = CreateContext(GrantType.ClientCredentials);
        context.Result!.ValidatedRequest.ClientClaims.Add(
            new System.Security.Claims.Claim(ClientCredentialsRoleTokenValidator.TenantIdClaimType, "preset"));

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.ValidatedRequest.ClientClaims
            .Where(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType)
            .Should().ContainSingle()
            .Which.Value.Should().Be("preset");
    }

    [Theory]
    [InlineData(GrantType.AuthorizationCode)]
    [InlineData(GrantType.DeviceFlow)]
    [InlineData("refresh_token")]
    public async Task OtherGrants_AreUntouched(string grantType)
    {
        // User flows get tenant_id from UserProfileService; adding it here as a *client* claim would
        // duplicate it and change the token shape for every interactive client.
        ResolveRequestToTenant(RequestTenantId);
        var context = CreateContext(grantType);

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.ValidatedRequest.ClientClaims.Should().BeEmpty();
        context.Result!.ValidatedRequest.Client.ClientClaimsPrefix.Should().Be("client_");
    }
}
