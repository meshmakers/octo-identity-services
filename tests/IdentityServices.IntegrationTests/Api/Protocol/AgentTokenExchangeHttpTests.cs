using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     The agent token exchange over the real token endpoint: an agent token (scope <c>octo_agent</c>) becomes a short-lived <c>octo_api</c>
///     token only through MCP's confidential client <c>octo-mcpServices-agent-exchange</c> in the agent's own tenant, and
///     the issued token always carries <c>act</c>. Abuse cases: a public client of that id, the public MCP device client,
///     any other client, a disabled agent client, a second exchange of the issued token.
/// </summary>
public sealed class AgentTokenExchangeHttpTests : IntegrationTestBase, IAsyncLifetime
{
    private const string AgentScope = "octo_agent";
    private const string ApiScope = "octo_api";
    private const string ExchangeClientId = "octo-mcpServices-agent-exchange";
    private const string ExchangeSecret = "agent-xchg-exchange-secret";
    private const string AgentClientId = "agent-xchg-builder";
    private const string AgentSecret = "agent-xchg-builder-secret";
    private const string AgentRole = "Agent9729Role";
    private const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";

    private static readonly string[] CreatedClients =
        [AgentClientId, ExchangeClientId, "agent-xchg-device-like", "agent-xchg-other"];

    private readonly WebApplicationFactory<Program> _host;
    private readonly IIdentityAuditService _audit = Substitute.For<IIdentityAuditService>();

    public AgentTokenExchangeHttpTests(CustomWebApplicationFactory factory) : base(factory)
    {
        // The audit service records every refusal; a substitute lets the tests assert that each refusal is audited.
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.RemoveAll<IIdentityAuditService>();
            services.AddSingleton(_audit);
        }));
    }

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    /// <summary>Removes every client the tests created, so the shared system tenant keeps no test client.</summary>
    public async ValueTask DisposeAsync()
    {
        using (var scope = _host.Services.CreateScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
            foreach (var clientId in CreatedClients)
            {
                if (await store.FindRtClientByIdAsync(clientId) is { } client)
                {
                    await store.DeleteAsync(client.ClientId!);
                }
            }
        }

        await _host.DisposeAsync();
    }

    private void ShouldBeAudited(string reasonPart) =>
        _audit.Received().StoreFailureAsync("Token Exchange Failure", Arg.Is<string>(m => m.Contains(reasonPart)));

    [Fact]
    public async Task AgentToken_ExchangedByTheConfidentialExchangeClient_IsAnOctoApiTokenOfTheAgent_WithAct()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: true);
        var agentToken = await RequestAgentTokenAsync(ct);

        var (status, body) = await ExchangeAsync(ExchangeClientId, ExchangeSecret, agentToken, ct);

        status.Should().Be(HttpStatusCode.OK, "{0}", body.ToJsonString());
        body.ContainsKey("refresh_token").Should().BeFalse("an exchanged token is never refreshable");
        body["expires_in"]!.GetValue<int>().Should().BeLessThanOrEqualTo(300, "the exchanged token is short-lived");
        var token = new JsonWebToken(body["access_token"]!.GetValue<string>());
        token.TryGetPayloadValue<string>("sub", out _).Should().BeFalse("a service token carries no sub");
        token.GetClaim("client_id").Value.Should().Be(AgentClientId);
        token.GetClaim("act").Value.Should().Be(AgentClientId, "the exchanged token always names the agent as actor");
        token.GetClaim("tenant_id").Value.Should().Be(NormalizedSystemTenantId);
        token.Claims.Where(c => c.Type == "scope").Select(c => c.Value).Should().BeEquivalentTo([ApiScope]);
        token.Claims.Where(c => c.Type == "role").Select(c => c.Value).Should().BeEquivalentTo([AgentRole]);
        token.Claims.Where(c => c.Type == "amr").Select(c => c.Value).Should().Contain("agent_exchange");
    }

    [Fact]
    public async Task AgentToken_DirectlyAgainstTheExchange_OfAPublicClientWithTheExchangeClientId_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: false);
        var agentToken = await RequestAgentTokenAsync(ct);

        var (status, body) = await ExchangeAsync(ExchangeClientId, null, agentToken, ct);

        status.Should().Be(HttpStatusCode.BadRequest, "{0}", body.ToJsonString());
        body["error"]!.GetValue<string>().Should().Be("unauthorized_client");
        body.ContainsKey("access_token").Should().BeFalse();
        ShouldBeAudited("not a confidential, exchange-only client");
    }

    [Fact]
    public async Task AgentToken_ExchangedByThePublicMcpDeviceClient_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: true);
        await CreateClientAsync("agent-xchg-device-like", b => b
            .WithGrantTypes(TokenExchange, "urn:ietf:params:oauth:grant-type:device_code")
            .WithScopes(ApiScope)
            .RequirePkce(false));
        var agentToken = await RequestAgentTokenAsync(ct);

        var (status, body) = await ExchangeAsync("agent-xchg-device-like", null, agentToken, ct);

        status.Should().Be(HttpStatusCode.BadRequest, "{0}", body.ToJsonString());
        body["error"]!.GetValue<string>().Should().Be("unauthorized_client");
        body["error_description"]!.GetValue<string>().Should().Contain(ExchangeClientId);
    }

    [Fact]
    public async Task AgentToken_ExchangedByAnotherConfidentialClient_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: true);
        await CreateClientAsync("agent-xchg-other", b => b
            .WithGrantTypes(TokenExchange)
            .WithScopes(ApiScope)
            .WithSecret("SharedSecret", Hash("agent-xchg-other-secret"))
            .RequireClientSecret()
            .RequirePkce(false));
        var agentToken = await RequestAgentTokenAsync(ct);

        var (status, body) = await ExchangeAsync("agent-xchg-other", "agent-xchg-other-secret", agentToken, ct);

        status.Should().Be(HttpStatusCode.BadRequest, "{0}", body.ToJsonString());
        body["error"]!.GetValue<string>().Should().Be("unauthorized_client");
    }

    [Fact]
    public async Task AgentToken_OfADisabledAgentClient_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: true);
        var agentToken = await RequestAgentTokenAsync(ct);
        await SetAgentEnabledAsync(false);
        try
        {
            var (status, body) = await ExchangeAsync(ExchangeClientId, ExchangeSecret, agentToken, ct);

            status.Should().Be(HttpStatusCode.BadRequest, "{0}", body.ToJsonString());
            body["error"]!.GetValue<string>().Should().Be("invalid_grant");
            ShouldBeAudited("does not exist or is disabled");
        }
        finally
        {
            await SetAgentEnabledAsync(true);
        }
    }

    [Fact]
    public async Task ExchangedToken_CannotBeExchangedAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: true);
        var (_, first) = await ExchangeAsync(ExchangeClientId, ExchangeSecret, await RequestAgentTokenAsync(ct), ct);
        var exchanged = first["access_token"]!.GetValue<string>();

        var (status, body) = await ExchangeAsync(ExchangeClientId, ExchangeSecret, exchanged, ct);

        status.Should().Be(HttpStatusCode.BadRequest, "{0}", body.ToJsonString());
        body["error"]!.GetValue<string>().Should().Be("invalid_grant");
    }

    [Fact]
    public async Task ExchangeClientWithASecretAndASecondGrant_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: true, extraGrant: "client_credentials");
        var agentToken = await RequestAgentTokenAsync(ct);

        var (status, body) = await ExchangeAsync(ExchangeClientId, ExchangeSecret, agentToken, ct);

        status.Should().Be(HttpStatusCode.BadRequest, "{0}", body.ToJsonString());
        body["error"]!.GetValue<string>().Should().Be("unauthorized_client",
            "an exchange client that can also act on its own is no boundary");
        ShouldBeAudited("not a confidential, exchange-only client");
    }

    [Fact]
    public async Task AScopeOtherThanOctoApi_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeAsync(exchangeClientConfidential: true, extraScope: AgentScope);
        var agentToken = await RequestAgentTokenAsync(ct);

        var (status, body) = await ExchangeAsync(ExchangeClientId, ExchangeSecret, agentToken, ct,
            scope: $"{ApiScope} {AgentScope}");

        status.Should().Be(HttpStatusCode.BadRequest, "{0}", body.ToJsonString());
        body["error"]!.GetValue<string>().Should().Be("invalid_scope");
        ShouldBeAudited("a scope other than octo_api");
    }

    // ---------- arrangement ----------

    private static string Hash(string secret) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    private async Task ArrangeAsync(bool exchangeClientConfidential, string? extraGrant = null,
        string? extraScope = null)
    {
        using (var scope = _host.Services.CreateScope())
        {
            var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();
            foreach (var name in new[] { AgentScope, ApiScope })
            {
                if (await resourceStore.GetApiScopeByNameAsync(name) == null)
                {
                    await resourceStore.CreateApiScopeAsync(new RtApiScope
                    {
                        RtId = OctoObjectId.GenerateNewId(),
                        Name = name,
                        DisplayName = name,
                        Enabled = true,
                        ShowInDiscoveryDocument = false,
                        Claims = new AttributeStringValueList(),
                        IsEmphasized = false,
                        IsRequired = false
                    });
                }
            }
        }

        await CreateClientAsync(AgentClientId, b => b
            .WithGrantTypes("client_credentials")
            .WithScopes(AgentScope)
            .WithSecret("SharedSecret", Hash(AgentSecret))
            .RequireClientSecret()
            .RequirePkce(false));
        await AddRoleAsync((await FindClientAsync(AgentClientId))!, AgentRole);

        // A fresh exchange client per test: confidential or public decides the case.
        using (var scope = _host.Services.CreateScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
            if (await store.FindRtClientByIdAsync(ExchangeClientId) is { } existing)
            {
                await store.DeleteAsync(existing.ClientId!);
            }
        }

        await CreateClientAsync(ExchangeClientId, b =>
        {
            b.WithGrantTypes(extraGrant == null ? [TokenExchange] : [TokenExchange, extraGrant])
                .WithScopes(extraScope == null ? [ApiScope] : [ApiScope, extraScope])
                .RequirePkce(false);
            if (exchangeClientConfidential)
            {
                b.WithSecret("SharedSecret", Hash(ExchangeSecret)).RequireClientSecret();
            }
        });
    }

    private async Task SetAgentEnabledAsync(bool enabled)
    {
        using var scope = _host.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().MutateAsync(AgentClientId, c =>
        {
            c.Enabled = enabled;
            return true;
        });
    }

    private async Task CreateClientAsync(string clientId, Action<RtClientBuilder> configure)
    {
        using var scope = _host.Services.CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
        if (await clientStore.FindRtClientByIdAsync(clientId) != null)
        {
            return;
        }

        var builder = new RtClientBuilder().WithClientId(clientId).WithClientName(clientId);
        configure(builder);
        await clientStore.CreateAsync(builder.Build());
    }

    private async Task<RtClient?> FindClientAsync(string clientId)
    {
        using var scope = _host.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(clientId);
    }

    private async Task AddRoleAsync(RtClient client, string roleName)
    {
        using var scope = _host.Services.CreateScope();
        var roleManager = scope.ServiceProvider
            .GetRequiredService<Microsoft.AspNetCore.Identity.RoleManager<RtRole>>();
        if (await roleManager.FindByNameAsync(roleName) == null)
        {
            await roleManager.CreateAsync(new RtRoleBuilder().WithName(roleName).Build());
        }

        var clientRoleStore = scope.ServiceProvider.GetRequiredService<IClientRoleStore>();
        if (!(await clientRoleStore.GetEffectiveRoleNamesAsync(client.RtId)).Contains(roleName))
        {
            await clientRoleStore.AddRoleAsync(client.RtId, roleName);
        }
    }

    private async Task<string> RequestAgentTokenAsync(CancellationToken ct)
    {
        using var http = _host.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = AgentClientId,
                ["client_secret"] = AgentSecret,
                ["scope"] = AgentScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "the agent token could not be minted: {0}", raw);
        var token = JsonNode.Parse(raw)!["access_token"]!.GetValue<string>();
        new JsonWebToken(token).Claims.Where(c => c.Type == "scope").Select(c => c.Value).Should()
            .BeEquivalentTo([AgentScope], "the agent client holds the agent scope only");
        return token;
    }

    private async Task<(HttpStatusCode Status, JsonObject Body)> ExchangeAsync(string presentingClientId,
        string? presentingSecret, string subjectToken, CancellationToken ct, string scope = ApiScope)
    {
        using var http = _host.CreateClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchange,
            ["client_id"] = presentingClientId,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["scope"] = scope,
            ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
        };
        if (presentingSecret != null)
        {
            form["client_secret"] = presentingSecret;
        }

        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(form), ct);
        return (response.StatusCode, JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject());
    }
}
