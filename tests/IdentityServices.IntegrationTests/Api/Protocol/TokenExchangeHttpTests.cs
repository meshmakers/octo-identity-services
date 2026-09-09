using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#4989 HTTP-level pin for the RFC 8693 token-exchange grant: the built-in OpenIddict
///     <c>Exchange.ValidateAuthorizedParty</c> handler rejects a subject token whose audiences
///     and presenters do not name the exchanging client (ID2186/ID2187). Platform access tokens
///     never name client ids there, so every cross-tenant exchange died with "The specified
///     subject token cannot be used by this client application" before
///     <c>TenantExchangeProcessor</c> ran. <c>OctoTokenExchangeAuthorizedPartyHandler</c>
///     bypasses that check for the exchange grant only — this test proves an exchange request
///     reaches the processor (recognizable by ITS validation message) while a full cross-tenant
///     roundtrip still needs a child-tenant setup the HTTP factory does not provide.
/// </summary>
public class TokenExchangeHttpTests : IntegrationTestBase
{
    private const string ExchangeApiScope = "exchange-api";
    private const string MachineSecret = "exchange-machine-secret";

    public TokenExchangeHttpTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task TokenExchange_SubjectTokenWithForeignAudience_ReachesTenantExchangeProcessor()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureApiScopeAsync();

        // Machine client mints the subject token; its audiences are API resources, never clients.
        await CreateExchangeClientAsync("exchange-machine", builder => builder
            .WithGrantTypes("client_credentials")
            .WithScopes(ExchangeApiScope)
            .WithSecret("SharedSecret", Sha256Base64(MachineSecret))
            .RequireClientSecret()
            .RequirePkce(false));

        // Public client performing the exchange (device + token-exchange, like octo-mcpServices-device).
        await CreateExchangeClientAsync("exchange-client", builder => builder
            .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code",
                "urn:ietf:params:oauth:grant-type:token-exchange")
            .WithScopes("openid", ExchangeApiScope)
            .RequirePkce(false));

        var http = CreateAnonymousClient();
        var tokenResponse = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "exchange-machine",
                ["client_secret"] = MachineSecret,
                ["scope"] = ExchangeApiScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
        var tokenRaw = await tokenResponse.Content.ReadAsStringAsync(ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK, "subject token minting failed: {0}", tokenRaw);
        var subjectToken = JsonNode.Parse(tokenRaw)!["access_token"]!.GetValue<string>();

        var exchangeResponse = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
                ["client_id"] = "exchange-client",
                ["subject_token"] = subjectToken,
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        var raw = await exchangeResponse.Content.ReadAsStringAsync(ct);
        var body = JsonNode.Parse(raw)!.AsObject();

        // The built-in authorized-party check would answer "The specified subject token cannot be
        // used by this client application". Reaching TenantExchangeProcessor instead yields ITS
        // rejection: a client_credentials token has no user subject.
        exchangeResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        body["error"]!.GetValue<string>().Should().Be("invalid_grant");
        body["error_description"]!.GetValue<string>().Should().Contain("user subject",
            "the exchange must be rejected by TenantExchangeProcessor, not by the built-in " +
            "authorized-party check: {0}", raw);
    }

    private async Task EnsureApiScopeAsync()
    {
        using var scope = CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();
        if (await resourceStore.GetApiScopeByNameAsync(ExchangeApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ExchangeApiScope,
                DisplayName = "Exchange API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }
    }

    private async Task CreateExchangeClientAsync(string clientId, Action<RtClientBuilder> configure)
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
