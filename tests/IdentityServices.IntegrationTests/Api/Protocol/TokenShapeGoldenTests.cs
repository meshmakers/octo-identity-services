using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#4989 golden baseline for the Duende → OpenIddict migration: records the wire-visible
///     shape of the discovery document and of the tokens issued by every locally drivable OAuth
///     flow (client credentials with effective client roles, authorization code + PKCE including
///     refresh, device authorization) while Duende is still the active server. After the swap to
///     OpenIddict the same tests compare against the recorded baseline — resource services must
///     not be able to tell the difference. See <see cref="GoldenFile" /> for the record/compare
///     mechanics and <c>docs/CONCEPT-OPENIDDICT-MIGRATION.md</c> §6 for the strategy.
/// </summary>
/// <remarks>
///     The RFC 8693 cross-tenant token exchange is deliberately not part of this baseline: it
///     needs a child tenant + mapping setup that the HTTP factory does not provide today. Its
///     claims parity is pinned separately by <c>TenantExchangeIntegrationTests</c> (role subset
///     resolution) and will get an HTTP-level golden once the OpenIddict handler exists (AB#4997).
/// </remarks>
public class TokenShapeGoldenTests : IntegrationTestBase
{
    private const string GoldenApiScope = "golden-api";
    private const string GoldenApiResource = "golden-api-resource";
    private const string MachineClientSecret = "golden-machine-secret";

    public TokenShapeGoldenTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task DiscoveryDocument_MatchesGoldenBaseline()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = CreateAnonymousClient();

        var response = await client.GetAsync("/.well-known/openid-configuration", ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject();
        await GoldenFile.MatchAllAsync(ct, ("discovery-document", body));
    }

    [Fact]
    public async Task JwksDocument_StructureMatchesGoldenBaseline()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = CreateAnonymousClient();

        var discovery = await GetAsync<JsonObject>("/.well-known/openid-configuration");
        var jwksUri = new Uri(discovery!["jwks_uri"]!.GetValue<string>());

        var response = await client.GetAsync(jwksUri.PathAndQuery, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject();

        // Key material (n/e) is generated per test run — pin only the structural fields.
        var keys = new JsonArray();
        foreach (var key in body["keys"]!.AsArray())
        {
            var obj = key!.AsObject();
            keys.Add(new JsonObject
            {
                ["kty"] = obj["kty"]?.DeepClone(),
                ["use"] = obj["use"]?.DeepClone(),
                ["alg"] = obj["alg"]?.DeepClone(),
                // The key id is deployment-specific — pin only its presence.
                ["kid"] = obj["kid"] != null ? "<kid>" : null
            });
        }

        await GoldenFile.MatchAllAsync(ct, ("jwks-structure", new JsonObject
        {
            ["jwksPath"] = jwksUri.AbsolutePath,
            ["keys"] = keys
        }));
    }

    /// <summary>
    ///     🔴 The wire-level proof for AB#5032: the recorded baseline carries <c>tenant_id</c> on the
    ///     client-credentials access token. That is a <b>deliberate</b> departure from the Duende
    ///     recording — the third such re-record of the migration, after the access-token identity
    ///     claims and the on-behalf-of grant entry — and the claim the platform's tenant gate
    ///     (<c>TenantAuthorizationMiddleware</c> in octo-common-services) authorizes service tokens
    ///     on. If a refactoring ever drops it, this test is what notices: the failure mode it guards
    ///     against is silent, because the tenant gate defaults to <c>LogOnly</c> and would simply
    ///     write a worthless inventory instead of erroring.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_AccessTokenShape_MatchesGoldenBaseline()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureGoldenApiResourcesAsync();

        var rtClient = await CreateGoldenClientAsync("golden-machine", builder => builder
            .WithGrantTypes("client_credentials")
            .WithScopes(GoldenApiScope)
            .WithSecret("SharedSecret", Sha256Base64(MachineClientSecret))
            .RequireClientSecret()
            .RequirePkce(false));
        await AssignClientRoleAsync(rtClient.RtId, "GoldenClientRole");

        var client = CreateAnonymousClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "golden-machine",
                ["client_secret"] = MachineClientSecret,
                ["scope"] = GoldenApiScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "token request failed: {0}", raw);
        var body = JsonNode.Parse(raw)!.AsObject();

        await GoldenFile.MatchAllAsync(ct,
            ("client-credentials-token-response",
                GoldenFile.NormalizeResponseShape(body, "token_type", "expires_in", "scope")),
            ("client-credentials-access-token",
                GoldenFile.NormalizeJwt(body["access_token"]!.GetValue<string>())));
    }

    [Fact]
    public async Task AuthorizationCodePkce_TokenShapes_MatchGoldenBaseline()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureGoldenApiResourcesAsync();

        const string redirectUri = "https://golden.example/callback";
        await CreateGoldenClientAsync("golden-spa", builder => builder
            .WithGrantTypes("authorization_code")
            .WithScopes("openid", "profile", "email", "offline_access", GoldenApiScope)
            .WithRedirectUris(redirectUri)
            .WithAllowOfflineAccess()
            .RequirePkce());

        await CreateTestUserAsync("goldenuser", "golden@example.com");
        var browser = await LoginAndGetAuthenticatedClientAsync("goldenuser", DefaultPassword, ct);
        browser.Should().NotBeNull("cookie login must succeed to drive the authorize flow");

        var codeVerifier = "golden-code-verifier-golden-code-verifier-1234567890";
        var codeChallenge = Base64UrlSha256(codeVerifier);

        var authorizeUrl = "/connect/authorize" +
                           "?client_id=golden-spa" +
                           $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                           "&response_type=code" +
                           $"&scope={Uri.EscapeDataString($"openid profile email offline_access {GoldenApiScope}")}" +
                           "&state=golden-state" +
                           "&nonce=golden-nonce" +
                           $"&code_challenge={codeChallenge}" +
                           "&code_challenge_method=S256" +
                           $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}";

        var authorizeResponse = await browser!.GetAsync(authorizeUrl, ct);
        ((int)authorizeResponse.StatusCode).Should().BeInRange(302, 303,
            "an authenticated authorize request must redirect straight back to the client (body: {0})",
            await authorizeResponse.Content.ReadAsStringAsync(ct));
        var location = authorizeResponse.Headers.Location!;
        location.ToString().Should().StartWith(redirectUri,
            "no interactive step (login/consent) may interrupt the flow for a first-party client");
        var code = HttpUtility.ParseQueryString(location.Query)["code"];
        code.Should().NotBeNullOrEmpty();

        var tokenClient = CreateAnonymousClient();
        var tokenResponse = await tokenClient.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "golden-spa",
                ["code"] = code!,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier
            }), ct);

        var raw = await tokenResponse.Content.ReadAsStringAsync(ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK, "code redemption failed: {0}", raw);
        var body = JsonNode.Parse(raw)!.AsObject();

        // Refresh-token grant — the shape a background consumer sees on renewal.
        var refreshToken = body["refresh_token"]!.GetValue<string>();
        var refreshResponse = await tokenClient.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = "golden-spa",
                ["refresh_token"] = refreshToken,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        var refreshRaw = await refreshResponse.Content.ReadAsStringAsync(ct);
        refreshResponse.StatusCode.Should().Be(HttpStatusCode.OK, "refresh failed: {0}", refreshRaw);
        var refreshBody = JsonNode.Parse(refreshRaw)!.AsObject();

        await GoldenFile.MatchAllAsync(ct,
            ("authcode-token-response",
                GoldenFile.NormalizeResponseShape(body, "token_type", "expires_in", "scope")),
            ("authcode-access-token",
                GoldenFile.NormalizeJwt(body["access_token"]!.GetValue<string>())),
            ("authcode-id-token",
                GoldenFile.NormalizeJwt(body["id_token"]!.GetValue<string>())),
            ("refresh-token-response",
                GoldenFile.NormalizeResponseShape(refreshBody, "token_type", "expires_in", "scope")),
            ("refresh-access-token",
                GoldenFile.NormalizeJwt(refreshBody["access_token"]!.GetValue<string>())));
    }

    [Fact]
    public async Task DeviceFlow_ResponseAndTokenShapes_MatchGoldenBaseline()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureGoldenApiResourcesAsync();

        await CreateGoldenClientAsync("golden-device", builder => builder
            .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
            .WithScopes("openid", "profile", GoldenApiScope)
            .RequirePkce(false));

        var client = CreateAnonymousClient();
        var deviceResponse = await client.PostAsync("/connect/deviceauthorization", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["client_id"] = "golden-device",
                ["scope"] = $"openid profile {GoldenApiScope}",
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        var deviceRaw = await deviceResponse.Content.ReadAsStringAsync(ct);
        deviceResponse.StatusCode.Should().Be(HttpStatusCode.OK, "device authorization failed: {0}", deviceRaw);
        var deviceBody = JsonNode.Parse(deviceRaw)!.AsObject();

        // Approve the user code through the SPA API (cookie-authenticated user), then redeem.
        await CreateTestUserAsync("goldendeviceuser", "golden-device@example.com");
        var browser = await LoginAndGetAuthenticatedClientAsync("goldendeviceuser", DefaultPassword, ct);
        browser.Should().NotBeNull();

        var userCode = deviceBody["user_code"]!.GetValue<string>();
        var approveResponse = await browser!.PostAsync("/connect/deviceverification",
            new FormUrlEncodedContent(new List<KeyValuePair<string, string>>
            {
                new("user_code", userCode),
                new("scopes_consented", "openid"),
                new("scopes_consented", "profile"),
                new("scopes_consented", GoldenApiScope)
            }), ct);
        var approveRaw = await approveResponse.Content.ReadAsStringAsync(ct);
        approveResponse.StatusCode.Should().Be(HttpStatusCode.OK, "device approval failed: {0}", approveRaw);

        var tokenResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["client_id"] = "golden-device",
                ["device_code"] = deviceBody["device_code"]!.GetValue<string>()
            }), ct);

        var tokenRaw = await tokenResponse.Content.ReadAsStringAsync(ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK, "device code redemption failed: {0}", tokenRaw);
        var tokenBody = JsonNode.Parse(tokenRaw)!.AsObject();

        await GoldenFile.MatchAllAsync(ct,
            ("device-authorization-response",
                GoldenFile.NormalizeResponseShape(deviceBody, "expires_in", "interval", "verification_uri")),
            ("device-token-response",
                GoldenFile.NormalizeResponseShape(tokenBody, "token_type", "expires_in", "scope")),
            ("device-access-token",
                GoldenFile.NormalizeJwt(tokenBody["access_token"]!.GetValue<string>())));
    }

    #region Arrange helpers

    /// <summary>
    ///     Creates the golden API scope and an API resource carrying it, so issued access tokens
    ///     get the <c>aud</c> claim the resource services validate. Idempotent per factory.
    /// </summary>
    private async Task EnsureGoldenApiResourcesAsync()
    {
        using var scope = CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();

        if (await resourceStore.GetApiScopeByNameAsync(GoldenApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = GoldenApiScope,
                DisplayName = "Golden API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }

        if (await resourceStore.GetApiResourceByNameAsync(GoldenApiResource) == null)
        {
            await resourceStore.CreateApiResourceAsync(new RtApiResource
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = GoldenApiResource,
                DisplayName = "Golden API Resource",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                Scopes = new AttributeStringValueList { GoldenApiScope }
            });
        }
    }

    private async Task<RtClient> CreateGoldenClientAsync(string clientId, Action<RtClientBuilder> configure)
    {
        using var scope = CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();

        var existing = await clientStore.FindRtClientByIdAsync(clientId);
        if (existing != null)
        {
            return existing;
        }

        var builder = new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId);
        configure(builder);
        var client = builder.Build();
        await clientStore.CreateAsync(client);
        return client;
    }

    /// <summary>
    ///     Assigns an effective role to a client so the golden baseline pins the unprefixed
    ///     <c>role</c> claim that <c>TokenEndpointController.HandleClientCredentialsAsync</c>
    ///     injects (AB#4183).
    /// </summary>
    private async Task AssignClientRoleAsync(OctoObjectId clientRtId, string roleName)
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();

        if (await roleManager.FindByNameAsync(roleName) == null)
        {
            var result = await roleManager.CreateAsync(new RtRoleBuilder().WithName(roleName).Build());
            result.Succeeded.Should().BeTrue("role creation failed: {0}",
                string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        var clientRoleStore = scope.ServiceProvider.GetRequiredService<IClientRoleStore>();
        await clientRoleStore.AddRoleAsync(clientRtId, roleName);
    }

    private static string Sha256Base64(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Base64UrlSha256(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(value)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    #endregion
}
