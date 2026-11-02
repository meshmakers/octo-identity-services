using Shared.TestUtilities.Builders;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServices.IntegrationTests.Helpers;

/// <summary>
/// Factory for creating test OAuth clients with various configurations.
/// </summary>
public static class TestClients
{
    /// <summary>
    /// Creates a standard SPA client with authorization code flow.
    /// </summary>
    public static RtClient CreateSpaClient(string clientId = "test-spa") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName($"{clientId} SPA")
            .WithGrantTypes("authorization_code")
            .WithRedirectUris("https://localhost:4200/callback")
            .WithPostLogoutRedirectUris("https://localhost:4200/")
            .WithScopes("openid", "profile", "email")
            .RequirePkce()
            .Build();

    /// <summary>
    /// Creates a SPA client with front-channel logout configured.
    /// </summary>
    public static RtClient CreateSpaClientWithLogout(string clientId = "test-spa-logout") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName($"{clientId} SPA with Logout")
            .WithGrantTypes("authorization_code")
            .WithRedirectUris("https://localhost:4200/callback")
            .WithPostLogoutRedirectUris("https://localhost:4200/")
            .WithFrontChannelLogoutUri("https://localhost:4200/logout-callback")
            .WithFrontChannelLogoutSessionRequired()
            .WithScopes("openid", "profile", "email")
            .RequirePkce()
            .Build();

    /// <summary>
    /// Creates a device flow client.
    /// </summary>
    public static RtClient CreateDeviceFlowClient(string clientId = "test-device") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName($"{clientId} Device")
            .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
            .WithScopes("openid", "profile")
            .Build();

    /// <summary>
    /// Creates a machine-to-machine client with client credentials flow.
    /// </summary>
    public static RtClient CreateMachineClient(string clientId = "test-machine") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName($"{clientId} Machine")
            .WithGrantTypes("client_credentials")
            .WithSecret("SharedSecret", "secret-hash")
            .WithScopes("api.read", "api.write")
            .RequireClientSecret()
            .Build();

    /// <summary>
    /// Creates a disabled client.
    /// </summary>
    public static RtClient CreateDisabledClient(string clientId = "disabled-client") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName("Disabled Client")
            .WithGrantTypes("authorization_code")
            .Disabled()
            .Build();

    /// <summary>
    /// Creates a client with custom scopes.
    /// </summary>
    public static RtClient CreateClientWithScopes(string clientId, params string[] scopes) =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId)
            .WithGrantTypes("authorization_code")
            .WithScopes(scopes)
            .RequirePkce()
            .Build();
}
