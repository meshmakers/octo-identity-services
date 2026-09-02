using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#4989 Duende parity: clients configured with <c>RequireClientSecret = false</c>
///     (octo-cli, adapters) send a <c>client_secret</c> anyway; Duende ignored it while
///     OpenIddict rejects public clients presenting a secret (error ID2053). Pins
///     <c>OctoPublicClientSecretHandler</c>: the secret is dropped for public clients, while
///     confidential clients still authenticate strictly.
/// </summary>
public class PublicClientSecretToleranceTests : IntegrationTestBase
{
    public PublicClientSecretToleranceTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task DeviceAuthorization_PublicClientSendingSecret_IsAccepted()
    {
        var ct = TestContext.Current.CancellationToken;
        await CreateClientAsync("tolerance-public-device", builder => builder
            .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
            .WithScopes("openid")
            .RequirePkce(false));

        var client = CreateAnonymousClient();
        var response = await client.PostAsync("/connect/deviceauthorization", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["client_id"] = "tolerance-public-device",
                ["client_secret"] = "sent-anyway-like-octo-cli-does",
                ["scope"] = "openid",
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "a public client sending a client_secret must stay accepted (Duende parity): {0}", raw);
        JsonNode.Parse(raw)!.AsObject().ContainsKey("device_code").Should().BeTrue();
    }

    [Fact]
    public async Task Token_ConfidentialClientWithWrongSecret_IsStillRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await CreateClientAsync("tolerance-confidential", builder => builder
            .WithGrantTypes("client_credentials")
            .WithScopes("openid")
            .WithSecret("SharedSecret", Sha256Base64("the-real-secret"))
            .RequireClientSecret()
            .RequirePkce(false));

        var client = CreateAnonymousClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "tolerance-confidential",
                ["client_secret"] = "wrong-secret",
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "confidential clients must still authenticate strictly: {0}", raw);
        JsonNode.Parse(raw)!["error"]!.GetValue<string>().Should().Be("invalid_client");
    }

    private async Task CreateClientAsync(string clientId, Action<RtClientBuilder> configure)
    {
        using var scope = CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();

        if (await clientStore.FindRtClientByIdAsync(clientId) != null)
        {
            return;
        }

        var builder = new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId);
        configure(builder);
        await clientStore.CreateAsync(builder.Build());
    }

    private static string Sha256Base64(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
