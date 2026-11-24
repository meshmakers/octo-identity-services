using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.Services.ServiceAccountExchange;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.TenantGeneration;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#9777 over the real token endpoint: the wire shape of the token a service-account exchange issues, and the
///     refusals OpenIddict and the processor add around <see cref="IServiceAccountExchangeGate" />.
/// </summary>
/// <remarks>
///     The test host has only its system tenant, which the real gate always refuses. The derived host therefore replaces
///     the gate with one that admits the arranged shadow client (the gate's decisions are covered against MongoDB by
///     <c>ServiceAccountExchangeGateIntegrationTests</c>); subject token validation, the presenter binding, OpenIddict's
///     client authentication and grant permission, claim composition, the access token shape and the tenant generation
///     stamp are the production code.
/// </remarks>
public sealed class TokenExchangeServiceAccountHttpTests : IntegrationTestBase, IDisposable
{
    private const string ApiScope = "sa-exchange-api";
    private const string SourceClientId = "sa9777-source";
    private const string SourceSecret = "sa9777-source-secret";
    private const string TargetRole = "Sa9777TargetRole";
    private const string SourceRole = "Sa9777SourceOnlyRole";
    private static readonly DateTime Generation = new(2026, 11, 24, 10, 0, 0, 777, DateTimeKind.Utc);
    private const string GenerationMs = "1795514400777";

    private readonly WebApplicationFactory<Program> _host;
    private RtClient? _admittedShadow;

    public TokenExchangeServiceAccountHttpTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.RemoveAll<IServiceAccountExchangeGate>();
            services.AddScoped<IServiceAccountExchangeGate>(_ => new AdmittingGate(this));
        }));
    }

    private string ShadowClientId => $"xt_{NormalizedSystemTenantId}_{SourceClientId}";

    public void Dispose()
    {
        _host.Dispose();
        Factory.TenantLifecycleStore.Reset();
    }

    [Fact]
    public async Task AdmittedExchange_IssuesAServiceTokenForTheShadowClient_InTheTargetTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        Factory.TenantLifecycleStore.ArrangeGeneration(NormalizedSystemTenantId, Generation);
        _host.Services.GetRequiredService<ITenantGenerationReader>().Invalidate(NormalizedSystemTenantId);
        await ArrangeClientsAsync(shadowMayExchange: true);
        var subjectToken = await RequestSourceTokenAsync(ct);

        var (status, body) = await ExchangeAsync(ShadowClientId, subjectToken, ct);

        status.Should().Be(HttpStatusCode.OK, "{0}", body.ToJsonString());
        body.ContainsKey("refresh_token").Should().BeFalse("exchanged tokens are never refreshable");
        body["expires_in"]!.GetValue<int>().Should().BeLessThanOrEqualTo(300, "the exchanged token is short-lived");
        var token = new JsonWebToken(body["access_token"]!.GetValue<string>());
        token.TryGetPayloadValue<string>("sub", out _).Should().BeFalse("a service token carries no sub");
        token.GetClaim("client_id").Value.Should().Be(ShadowClientId);
        token.GetClaim("tenant_id").Value.Should().Be(NormalizedSystemTenantId);
        token.GetClaim("tenant_gen").Value.Should().Be(GenerationMs);
        token.GetClaim("act").Value.Should().Be(SourceClientId);
        token.Claims.Where(c => c.Type == "role").Select(c => c.Value).Should().BeEquivalentTo([TargetRole],
            "the roles are the shadow client's roles in the target, never the source account's");
        token.Claims.Where(c => c.Type == "amr").Select(c => c.Value).Should().Contain("token_exchange");
    }

    [Fact]
    public async Task ExchangePresentedByAnotherClient_IsUnauthorizedClient()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeClientsAsync(shadowMayExchange: true);
        await CreateClientAsync("sa9777-other", b => b
            .WithGrantTypes("urn:ietf:params:oauth:grant-type:token-exchange")
            .WithScopes(ApiScope)
            .RequirePkce(false));
        var subjectToken = await RequestSourceTokenAsync(ct);

        var (status, body) = await ExchangeAsync("sa9777-other", subjectToken, ct);

        status.Should().Be(HttpStatusCode.BadRequest);
        body["error"]!.GetValue<string>().Should().Be("unauthorized_client");
        body["error_description"]!.GetValue<string>().Should().Contain("shadow client");
    }

    [Fact]
    public async Task ShadowClientWithoutTheTokenExchangePermission_IsUnauthorizedClient()
    {
        var ct = TestContext.Current.CancellationToken;
        await ArrangeClientsAsync(shadowMayExchange: false);
        var subjectToken = await RequestSourceTokenAsync(ct);

        var (status, body) = await ExchangeAsync(ShadowClientId, subjectToken, ct);

        status.Should().Be(HttpStatusCode.BadRequest);
        body["error"]!.GetValue<string>().Should().Be("unauthorized_client",
            "OpenIddict refuses a client that is not permitted to use the token-exchange grant: {0}", body.ToJsonString());
    }

    // ---------- arrangement ----------

    private async Task ArrangeClientsAsync(bool shadowMayExchange)
    {
        using var scope = _host.Services.CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();
        if (await resourceStore.GetApiScopeByNameAsync(ApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ApiScope,
                DisplayName = "SA exchange API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }

        await CreateClientAsync(SourceClientId, b => b
            .WithGrantTypes("client_credentials")
            .WithScopes(ApiScope)
            .WithSecret("SharedSecret", Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(SourceSecret))))
            .RequireClientSecret()
            .RequirePkce(false));
        var source = await FindClientAsync(SourceClientId);
        await AddRoleAsync(source!, SourceRole);

        // A fresh shadow per test: the grant types decide the permission case.
        var shadowStore = _host.Services.CreateScope().ServiceProvider.GetRequiredService<IOctoClientStore>();
        if (await shadowStore.FindRtClientByIdAsync(ShadowClientId) is { } existing)
        {
            await shadowStore.DeleteAsync(existing.ClientId!);
        }

        await CreateClientAsync(ShadowClientId, b => b
            .WithGrantTypes(shadowMayExchange
                ? ["urn:ietf:params:oauth:grant-type:token-exchange"]
                : ["urn:ietf:params:oauth:grant-type:device_code"])
            .WithScopes(ApiScope)
            .RequirePkce(false));
        _admittedShadow = await FindClientAsync(ShadowClientId);
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

    private async Task<string> RequestSourceTokenAsync(CancellationToken ct)
    {
        using var http = _host.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = SourceClientId,
                ["client_secret"] = SourceSecret,
                ["scope"] = ApiScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "the source token could not be minted: {0}", raw);
        var token = JsonNode.Parse(raw)!["access_token"]!.GetValue<string>();
        new JsonWebToken(token).Claims.Where(c => c.Type == "role").Select(c => c.Value).Should().Contain(SourceRole,
            "the source account holds its own role in its tenant, which must not reach the exchanged token");
        return token;
    }

    private async Task<(HttpStatusCode Status, JsonObject Body)> ExchangeAsync(string presentingClientId,
        string subjectToken, CancellationToken ct)
    {
        using var http = _host.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
                ["client_id"] = presentingClientId,
                ["subject_token"] = subjectToken,
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["scope"] = ApiScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
        return (response.StatusCode, JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject());
    }

    /// <summary>Admits the arranged shadow client with exactly <see cref="TargetRole" />.</summary>
    private sealed class AdmittingGate(TokenExchangeServiceAccountHttpTests test) : IServiceAccountExchangeGate
    {
        public Task<ServiceAccountExchangeDecision> EvaluateAsync(string sourceTenantId, string sourceClientId,
            string targetTenantId) => Task.FromResult(new ServiceAccountExchangeDecision
        {
            Refusal = ServiceAccountExchangeRefusal.None,
            Relation = ServiceAccountExchangeRelation.Parent,
            ShadowClient = test._admittedShadow,
            RoleNames = new HashSet<string> { TargetRole }
        });
    }
}
