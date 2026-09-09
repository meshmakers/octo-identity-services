using FluentAssertions;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServerPersistence.UnitTests.Stores;

/// <summary>
///     Pins the legacy-client-configuration→OpenIddict permissions transform (AB#4991) against
///     every client
///     shape seeded by the <c>System.Identity.Bootstrap</c> blueprint plus the shapes created at
///     runtime (DCR clients, client_credentials service accounts). The transform is the single
///     point deciding what a client may do on the OpenIddict server — a regression here silently
///     locks clients out (or lets them do more than before).
/// </summary>
public class ClientPermissionsMapperTests
{
    /// <summary>octo-data-refinery-studio: interactive SPA (authorization_code + PKCE + offline).</summary>
    [Fact]
    public void SpaClient_GetsCodeFlowEndpointsRefreshAndScopes()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-data-refinery-studio")
            .WithGrantTypes("authorization_code")
            .WithScopes("openid", "profile", "email", "role", "allowed_tenants", "octo_api")
            .WithAllowOfflineAccess()
            .RequirePkce()
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().Contain(
        [
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code,
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.PushedAuthorization,
            Permissions.Endpoints.EndSession,
            Permissions.Endpoints.Revocation,
            Permissions.Prefixes.Scope + "openid",
            Permissions.Prefixes.Scope + "profile",
            Permissions.Prefixes.Scope + "email",
            Permissions.Prefixes.Scope + "role",
            Permissions.Prefixes.Scope + "allowed_tenants",
            Permissions.Prefixes.Scope + "octo_api"
        ]);
        permissions.Should().NotContain(Permissions.GrantTypes.ClientCredentials);
        permissions.Should().NotContain(Permissions.GrantTypes.DeviceCode);

        ClientPermissionsMapper.MapRequirements(client)
            .Should().ContainSingle()
            .Which.Should().Be(Requirements.Features.ProofKeyForCodeExchange);
    }

    /// <summary>octo-cli: device flow client without PKCE, with refresh tokens.</summary>
    [Fact]
    public void DeviceFlowClient_GetsDeviceEndpointsAndRefresh()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-cli")
            .WithGrantTypes(ClientPermissionsMapper.DeviceCodeGrantType)
            .WithScopes("openid", "profile", "email", "role", "octo_api")
            .WithAllowOfflineAccess()
            .RequirePkce(false)
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().Contain(
        [
            Permissions.GrantTypes.DeviceCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.Endpoints.DeviceAuthorization,
            Permissions.Endpoints.Token
        ]);
        permissions.Should().NotContain(Permissions.Endpoints.Authorization);
        permissions.Should().NotContain(Permissions.ResponseTypes.Code);

        ClientPermissionsMapper.MapRequirements(client).Should().BeEmpty();
    }

    /// <summary>octo-mcpServices-device: device flow + RFC 8693 cross-tenant token exchange.</summary>
    [Fact]
    public void McpDeviceClient_GetsTokenExchangeGrant()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-mcpServices-device")
            .WithGrantTypes(
                ClientPermissionsMapper.DeviceCodeGrantType,
                ClientPermissionsMapper.TokenExchangeGrantType)
            .WithScopes("openid", "profile", "email", "role", "octo_api", "offline_access")
            .WithAllowOfflineAccess()
            .RequirePkce(false)
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().Contain(
        [
            Permissions.GrantTypes.DeviceCode,
            Permissions.GrantTypes.TokenExchange,
            Permissions.GrantTypes.RefreshToken,
            Permissions.Endpoints.DeviceAuthorization,
            Permissions.Endpoints.Token
        ]);
    }

    /// <summary>Swagger clients: authorization_code + PKCE, NO offline access.</summary>
    [Fact]
    public void SwaggerClient_GetsNoRefreshTokenGrant()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-idenityServices-swagger")
            .WithGrantTypes("authorization_code")
            .WithScopes("openid", "profile", "email", "role", "octo_api", "octo_api.read_only")
            .RequirePkce()
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().Contain(Permissions.GrantTypes.AuthorizationCode);
        permissions.Should().NotContain(Permissions.GrantTypes.RefreshToken);
    }

    /// <summary>Service accounts (adapters, CI/CD, mirrors): client_credentials with secret.</summary>
    [Fact]
    public void ClientCredentialsClient_GetsTokenEndpointOnly()
    {
        var client = new RtClientBuilder()
            .WithClientId("service-account")
            .WithGrantTypes("client_credentials")
            .WithScopes("octo_api")
            .WithSecret("SharedSecret", "hashed")
            .RequireClientSecret()
            .RequirePkce(false)
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().Contain(
        [
            Permissions.GrantTypes.ClientCredentials,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.Revocation,
            Permissions.Prefixes.Scope + "octo_api"
        ]);
        permissions.Should().NotContain(Permissions.Endpoints.Authorization);
        permissions.Should().NotContain(Permissions.Endpoints.DeviceAuthorization);
    }

    /// <summary>DCR clients (octo-dcr-*): loopback authorization_code + refresh, PKCE required.</summary>
    [Fact]
    public void DynamicallyRegisteredClient_MatchesDcrContract()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-dcr-12345678")
            .WithGrantTypes("authorization_code", "refresh_token")
            .WithScopes("openid", "profile", "email", "role", "octo_api", "offline_access")
            .WithRedirectUris("http://127.0.0.1:33418/callback")
            .RequirePkce()
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().Contain(
        [
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token
        ]);

        ClientPermissionsMapper.MapRequirements(client)
            .Should().ContainSingle()
            .Which.Should().Be(Requirements.Features.ProofKeyForCodeExchange);
    }

    /// <summary>A legacy "refresh_token" entry in AllowedGrantTypes is honored, without duplicates.</summary>
    [Fact]
    public void RefreshTokenGrantAndOfflineAccess_ProduceNoDuplicates()
    {
        var client = new RtClientBuilder()
            .WithClientId("both-refresh-signals")
            .WithGrantTypes("authorization_code", "refresh_token")
            .WithScopes("openid")
            .WithAllowOfflineAccess()
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().OnlyHaveUniqueItems();
        permissions.Should().Contain(Permissions.GrantTypes.RefreshToken);
    }

    /// <summary>
    /// AB#5114: a pipeline service account carrying the impersonation URN in AllowedGrantTypes is
    /// allowed the custom impersonation flow (prefixed-permission model, like on-behalf-of) —
    /// this is how the communication reconcile will grant the flow to adapter clients.
    /// </summary>
    [Fact]
    public void ClientWithImpersonationGrant_GetsThePrefixedCustomFlowPermission()
    {
        var client = new RtClientBuilder()
            .WithClientId("adapter-chart-client")
            .WithGrantTypes("client_credentials", ClientPermissionsMapper.ImpersonationGrantType)
            .WithScopes("octo_api")
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().Contain(
        [
            Permissions.GrantTypes.ClientCredentials,
            Permissions.Prefixes.GrantType + ClientPermissionsMapper.ImpersonationGrantType,
            Permissions.Endpoints.Token
        ]);
    }

    /// <summary>
    /// The opt-in is per URN: neither on-behalf-of nor token exchange may smuggle in the far
    /// stronger impersonation capability (OpenIddict answers unauthorized_client without it).
    /// </summary>
    [Fact]
    public void ClientWithoutImpersonationGrant_DoesNotGetTheImpersonationPermission()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-pipeline-sa-plain")
            .WithGrantTypes("client_credentials", ClientPermissionsMapper.OnBehalfOfGrantType,
                ClientPermissionsMapper.TokenExchangeGrantType)
            .WithScopes("octo_api")
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().NotContain(
            Permissions.Prefixes.GrantType + ClientPermissionsMapper.ImpersonationGrantType);
    }

    /// <summary>A client with no grant types gets no endpoint permissions except revocation.</summary>
    [Fact]
    public void ClientWithoutGrantTypes_GetsNoEndpointPermissions()
    {
        var client = new RtClientBuilder()
            .WithClientId("empty")
            .WithGrantTypes()
            .WithScopes()
            .Build();

        var permissions = ClientPermissionsMapper.MapPermissions(client);

        permissions.Should().BeEquivalentTo([Permissions.Endpoints.Revocation]);
    }
}
