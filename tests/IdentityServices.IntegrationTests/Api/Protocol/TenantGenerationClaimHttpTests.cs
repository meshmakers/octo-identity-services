using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#8997 over the real token endpoint: <c>tenant_gen</c> = <c>CreatedUtc</c> of the tenant's lifecycle record
///     (Unix ms, decimal string) on the access tokens of client credentials, authorization code, refresh and device code;
///     never on the id token or the userinfo response; re-read on refresh; absent without a record; a failing lookup
///     refuses the token. The lifecycle record is arranged through
///     <see cref="Helpers.TestTenantLifecycleStore" /> (the test host has no asset repository that writes one).
///     Impersonation is covered over HTTP in <c>ImpersonationHttpGoldenTests</c>. Token exchange, on-behalf-of and
///     cross-tenant login run through the same sign-in handler; this HTTP host cannot complete them (they need a child
///     tenant and a signed subject token), so their grant-type cases are pinned in
///     <c>OctoTenantGenerationClaimHandlerTests</c> (unit).
/// </summary>
public class TenantGenerationClaimHttpTests : IntegrationTestBase
{
    private const string ApiScope = "tenantgen-api";
    private const string ApiResource = "tenantgen-api-resource";
    private const string MachineSecret = "tenantgen-machine-secret";
    private const string RedirectUri = "https://tenantgen.example/callback";

    private static readonly DateTime Generation1 = new DateTime(2025, 11, 15, 8, 0, 0, 123, DateTimeKind.Utc)
        .AddTicks(4_567);

    private static readonly DateTime Generation2 = new(2025, 11, 15, 9, 30, 0, 456, DateTimeKind.Utc);

    private const string Generation1Ms = "1763193600123";
    private const string Generation2Ms = "1763199000456";

    public TenantGenerationClaimHttpTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task ClientCredentials_AccessTokenCarriesTheGeneration_WithOneLifecycleReadPerIssuance()
    {
        var ct = TestContext.Current.CancellationToken;
        try
        {
            Factory.TenantLifecycleStore.ArrangeGeneration(NormalizedSystemTenantId, Generation1);
            await CreateMachineClientAsync();
            var readsBefore = Factory.TenantLifecycleStore.ReadsOf(NormalizedSystemTenantId);

            var token = await RequestClientCredentialsTokenAsync(ct);

            token.StatusCode.Should().Be(HttpStatusCode.OK, "token request failed: {0}", token.Raw);
            var claims = DecodePayload(token.Body!["access_token"]!.GetValue<string>());
            claims["tenant_id"]!.GetValue<string>().Should().Be(NormalizedSystemTenantId);
            claims["tenant_gen"]!.GetValueKind().Should().Be(JsonValueKind.String, "the value is a decimal string");
            claims["tenant_gen"]!.GetValue<string>().Should().Be(Generation1Ms);
            (Factory.TenantLifecycleStore.ReadsOf(NormalizedSystemTenantId) - readsBefore).Should().Be(1,
                "one lifecycle read per issued token");
        }
        finally
        {
            Factory.TenantLifecycleStore.Reset();
        }
    }

    [Fact]
    public async Task NoLifecycleRecord_TokenIsIssuedWithoutTheClaim()
    {
        var ct = TestContext.Current.CancellationToken;
        try
        {
            Factory.TenantLifecycleStore.ArrangeNoRecord(NormalizedSystemTenantId);
            await CreateMachineClientAsync();

            var token = await RequestClientCredentialsTokenAsync(ct);

            token.StatusCode.Should().Be(HttpStatusCode.OK, "token request failed: {0}", token.Raw);
            var claims = DecodePayload(token.Body!["access_token"]!.GetValue<string>());
            claims.ContainsKey("tenant_id").Should().BeTrue();
            claims.ContainsKey("tenant_gen").Should().BeFalse();
        }
        finally
        {
            Factory.TenantLifecycleStore.Reset();
        }
    }

    [Fact]
    public async Task RecordWithoutCreatedUtc_TokenIsIssuedWithoutTheClaim()
    {
        var ct = TestContext.Current.CancellationToken;
        try
        {
            Factory.TenantLifecycleStore.ArrangeGeneration(NormalizedSystemTenantId, default);
            await CreateMachineClientAsync();

            var token = await RequestClientCredentialsTokenAsync(ct);

            token.StatusCode.Should().Be(HttpStatusCode.OK, "token request failed: {0}", token.Raw);
            DecodePayload(token.Body!["access_token"]!.GetValue<string>()).ContainsKey("tenant_gen").Should()
                .BeFalse();
        }
        finally
        {
            Factory.TenantLifecycleStore.Reset();
        }
    }

    [Fact]
    public async Task LifecycleStoreFailure_RefusesTheTokenWithAServerError()
    {
        var ct = TestContext.Current.CancellationToken;
        try
        {
            Factory.TenantLifecycleStore.ArrangeFailure(NormalizedSystemTenantId,
                new TimeoutException("lifecycle store unreachable"));
            await CreateMachineClientAsync();

            var token = await RequestClientCredentialsTokenAsync(ct);

            ((int)token.StatusCode).Should().BeGreaterThanOrEqualTo(500, "body: {0}", token.Raw);
            token.Body.Should().NotBeNull("the error is an OAuth error response: {0}", token.Raw);
            token.Body!["error"]!.GetValue<string>().Should().Be("server_error");
            token.Body.ContainsKey("access_token").Should().BeFalse();
        }
        finally
        {
            Factory.TenantLifecycleStore.Reset();
        }
    }

    [Fact]
    public async Task AuthorizationCode_ThenRefresh_StampsTheCurrentGeneration_OnTheAccessTokenOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        try
        {
            Factory.TenantLifecycleStore.ArrangeGeneration(NormalizedSystemTenantId, Generation1);
            await EnsureApiResourcesAsync();
            // AlwaysIncludeUserClaimsInIdToken: tenant_id and roles go into the id token too — tenant_gen must not.
            await CreateClientAsync("tenantgen-spa", builder => builder
                    .WithGrantTypes("authorization_code")
                    .WithScopes("openid", "profile", "offline_access", ApiScope)
                    .WithRedirectUris(RedirectUri)
                    .WithAllowOfflineAccess()
                    .RequirePkce(),
                client => client.AlwaysIncludeUserClaimsInIdToken = true);

            await CreateTestUserAsync("tenantgenuser", "tenantgen@example.com");
            var browser = await LoginAndGetAuthenticatedClientAsync("tenantgenuser", DefaultPassword, ct);
            browser.Should().NotBeNull();

            const string codeVerifier = "tenantgen-code-verifier-tenantgen-code-verifier-8997";
            var authorizeUrl = "/connect/authorize" +
                               "?client_id=tenantgen-spa" +
                               $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                               "&response_type=code" +
                               $"&scope={Uri.EscapeDataString($"openid profile offline_access {ApiScope}")}" +
                               "&state=s&nonce=n" +
                               $"&code_challenge={Base64UrlSha256(codeVerifier)}&code_challenge_method=S256" +
                               $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}";
            var readsBefore = Factory.TenantLifecycleStore.ReadsOf(NormalizedSystemTenantId);
            var authorize = await browser!.GetAsync(authorizeUrl, ct);
            ((int)authorize.StatusCode).Should().BeInRange(302, 303);
            var code = HttpUtility.ParseQueryString(authorize.Headers.Location!.Query)["code"];
            code.Should().NotBeNullOrEmpty();
            (Factory.TenantLifecycleStore.ReadsOf(NormalizedSystemTenantId) - readsBefore).Should().Be(0,
                "issuing the authorization code generates no access token, so nothing is read");

            var http = CreateAnonymousClient();
            var redeemed = await PostTokenAsync(http, new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "tenantgen-spa",
                ["code"] = code!,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = codeVerifier
            }, ct);
            redeemed.StatusCode.Should().Be(HttpStatusCode.OK, "code redemption failed: {0}", redeemed.Raw);

            (Factory.TenantLifecycleStore.ReadsOf(NormalizedSystemTenantId) - readsBefore).Should().Be(1,
                "one lifecycle read for the redeemed access token");
            var accessToken = redeemed.Body!["access_token"]!.GetValue<string>();
            DecodePayload(accessToken)["tenant_gen"]!.GetValue<string>().Should().Be(Generation1Ms);
            var idToken = DecodePayload(redeemed.Body["id_token"]!.GetValue<string>());
            idToken.ContainsKey("tenant_id").Should().BeTrue("the client puts user claims into the id token");
            idToken.ContainsKey("tenant_gen").Should().BeFalse("tenant_gen is an access-token claim only");

            // Userinfo serves no tenant_gen either.
            using (var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo"))
            {
                userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var userInfo = await http.SendAsync(userInfoRequest, ct);
                var userInfoRaw = await userInfo.Content.ReadAsStringAsync(ct);
                userInfo.StatusCode.Should().Be(HttpStatusCode.OK, "userinfo failed: {0}", userInfoRaw);
                JsonNode.Parse(userInfoRaw)!.AsObject().ContainsKey("tenant_gen").Should().BeFalse();
            }

            // A new creation cycle (as after delete and recreate): the refresh grant reads the record again.
            Factory.TenantLifecycleStore.ArrangeGeneration(NormalizedSystemTenantId, Generation2);
            var refreshed = await PostTokenAsync(http, new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = "tenantgen-spa",
                ["refresh_token"] = redeemed.Body["refresh_token"]!.GetValue<string>(),
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }, ct);
            refreshed.StatusCode.Should().Be(HttpStatusCode.OK, "refresh failed: {0}", refreshed.Raw);
            DecodePayload(refreshed.Body!["access_token"]!.GetValue<string>())["tenant_gen"]!.GetValue<string>()
                .Should().Be(Generation2Ms, "the refresh grant stamps the generation read at issuance");
            (Factory.TenantLifecycleStore.ReadsOf(NormalizedSystemTenantId) - readsBefore).Should().Be(2,
                "the refresh grant reads the record once more; userinfo (token validation) reads nothing");
            DecodePayload(refreshed.Body["id_token"]!.GetValue<string>()).ContainsKey("tenant_gen").Should().BeFalse();
        }
        finally
        {
            Factory.TenantLifecycleStore.Reset();
        }
    }

    [Fact]
    public async Task DeviceCode_AccessTokenCarriesTheGeneration()
    {
        var ct = TestContext.Current.CancellationToken;
        try
        {
            Factory.TenantLifecycleStore.ArrangeGeneration(NormalizedSystemTenantId, Generation1);
            await EnsureApiResourcesAsync();
            await CreateClientAsync("tenantgen-device", builder => builder
                .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
                .WithScopes("openid", "profile", ApiScope)
                .RequirePkce(false));

            var http = CreateAnonymousClient();
            var device = await http.PostAsync("/connect/deviceauthorization", new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    ["client_id"] = "tenantgen-device",
                    ["scope"] = $"openid profile {ApiScope}",
                    ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
                }), ct);
            var deviceRaw = await device.Content.ReadAsStringAsync(ct);
            device.StatusCode.Should().Be(HttpStatusCode.OK, "device authorization failed: {0}", deviceRaw);
            var deviceBody = JsonNode.Parse(deviceRaw)!.AsObject();

            await CreateTestUserAsync("tenantgendevice", "tenantgen-device@example.com");
            var browser = await LoginAndGetAuthenticatedClientAsync("tenantgendevice", DefaultPassword, ct);
            browser.Should().NotBeNull();
            var approve = await browser!.PostAsync("/connect/deviceverification",
                new FormUrlEncodedContent(new List<KeyValuePair<string, string>>
                {
                    new("user_code", deviceBody["user_code"]!.GetValue<string>()),
                    new("scopes_consented", "openid"),
                    new("scopes_consented", "profile"),
                    new("scopes_consented", ApiScope)
                }), ct);
            approve.StatusCode.Should().Be(HttpStatusCode.OK, "device approval failed: {0}",
                await approve.Content.ReadAsStringAsync(ct));

            var token = await PostTokenAsync(http, new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["client_id"] = "tenantgen-device",
                ["device_code"] = deviceBody["device_code"]!.GetValue<string>()
            }, ct);

            token.StatusCode.Should().Be(HttpStatusCode.OK, "device code redemption failed: {0}", token.Raw);
            DecodePayload(token.Body!["access_token"]!.GetValue<string>())["tenant_gen"]!.GetValue<string>()
                .Should().Be(Generation1Ms);
        }
        finally
        {
            Factory.TenantLifecycleStore.Reset();
        }
    }

    #region Helpers

    private sealed record TokenResult(HttpStatusCode StatusCode, string Raw, JsonObject? Body);

    private async Task<TokenResult> RequestClientCredentialsTokenAsync(CancellationToken ct) =>
        await PostTokenAsync(CreateAnonymousClient(), new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "tenantgen-machine",
            ["client_secret"] = MachineSecret,
            ["scope"] = ApiScope,
            ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
        }, ct);

    private static async Task<TokenResult> PostTokenAsync(HttpClient http, Dictionary<string, string> form,
        CancellationToken ct)
    {
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(form), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        JsonObject? body = null;
        try
        {
            body = JsonNode.Parse(raw) as JsonObject;
        }
        catch (JsonException)
        {
            // not JSON — the assertions report the raw body
        }

        return new TokenResult(response.StatusCode, raw, body);
    }

    /// <summary>Decodes the JWT payload; the signature is irrelevant for these assertions.</summary>
    private static JsonObject DecodePayload(string jwt)
    {
        var payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        return JsonNode.Parse(Convert.FromBase64String(payload))!.AsObject();
    }

    private async Task CreateMachineClientAsync()
    {
        await EnsureApiResourcesAsync();
        await CreateClientAsync("tenantgen-machine", builder => builder
            .WithGrantTypes("client_credentials")
            .WithScopes(ApiScope)
            .WithSecret("SharedSecret",
                Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(MachineSecret))))
            .RequireClientSecret()
            .RequirePkce(false));
    }

    private async Task EnsureApiResourcesAsync()
    {
        using var scope = CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();

        if (await resourceStore.GetApiScopeByNameAsync(ApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ApiScope,
                DisplayName = "Tenant generation API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }

        if (await resourceStore.GetApiResourceByNameAsync(ApiResource) == null)
        {
            await resourceStore.CreateApiResourceAsync(new RtApiResource
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ApiResource,
                DisplayName = "Tenant generation API resource",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                Scopes = new AttributeStringValueList { ApiScope }
            });
        }
    }

    private async Task CreateClientAsync(string clientId, Action<RtClientBuilder> configure,
        Action<RtClient>? adjust = null)
    {
        using var scope = CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
        if (await clientStore.FindRtClientByIdAsync(clientId) != null)
        {
            return;
        }

        var builder = new RtClientBuilder().WithClientId(clientId).WithClientName(clientId);
        configure(builder);
        var client = builder.Build();
        adjust?.Invoke(client);
        await clientStore.CreateAsync(client);
    }

    private static string Base64UrlSha256(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(value)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    #endregion
}
