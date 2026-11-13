using System.Collections;
using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using IdentityServices.IntegrationTests.Persistence;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Mvc.Testing.Handlers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#7892: authorization codes, PAR request_uris and refresh tokens of a non-system tenant work when the
///     requests of one flow land on different identity replicas, and after identity restarts.
/// </summary>
/// <remarks>
///     <para>
///         Each "replica" is its own in-process host (<see cref="WebApplicationFactory{TEntryPoint}.WithWebHostBuilder" />)
///         over the same MongoDB — its own DI container, caches and OpenIddict server, like a second pod. The OIDC
///         client lives in the sub-tenant only (like the Energy Community app on test-2), so a lookup in the wrong
///         tenant answers <c>invalid_client</c>.
///     </para>
///     <para>
///         Static state of the middleware would be shared by all hosts of this test process, so two hosts alone would
///         not catch a process-local tenant map. Between issuing and redeeming, every test therefore clears all static
///         dictionaries of <see cref="OidcTenantResolutionMiddleware" /> (<see cref="ForgetProcessState" />) — exactly what
///         the second pod or the restarted process does not have. Before AB#7892 this emptied the in-process
///         <c>TokenToTenantMap</c> and the tests failed with <c>invalid_client</c> / a tenant-discovery redirect; since
///         AB#7892 the middleware holds no such state and the tenant travels with the value the client sends back.
///     </para>
/// </remarks>
public class OidcTenantResolutionReplicaTests : IntegrationTestBase
{
    private const string ClientId = "replica-subtenant-app";
    private const string RedirectUri = "https://replica-subtenant.example/callback";
    private const string CodeVerifier = "replica-subtenant-code-verifier-replica-subtenant-code-verifier";
    private const string Scopes = "openid profile offline_access";

    public OidcTenantResolutionReplicaTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task AuthorizationCode_IssuedOnReplicaA_RedeemedOnReplicaB_IssuesTokenForTheSubTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var replicaA = NewReplica();
        var replicaB = NewReplica();
        var cookies = new CookieContainer();

        await SignInAsync(replicaA, cookies, tenantId, userName, ct);
        var code = await AuthorizeAsync(replicaA, cookies, AuthorizeQuery(tenantId), ct);
        ForgetProcessState();

        var response = await RedeemCodeAsync(replicaB, code, ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            "replica B must look up the client in the sub-tenant, not the system tenant: {0}", ErrorOf(raw));
        TenantOf(JsonNode.Parse(raw)!["access_token"]!.GetValue<string>()).Should().BeEquivalentTo(tenantId);
    }

    [Fact]
    public async Task PushedAuthorizationRequest_CreatedOnReplicaA_UsedOnReplicaB_ResolvesTheSubTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var replicaA = NewReplica();
        var replicaB = NewReplica();
        var cookies = new CookieContainer();

        var par = await AnonymousClient(replicaA).PostAsync("/connect/par",
            new FormUrlEncodedContent(AuthorizeParameters(tenantId)), ct);
        var parRaw = await par.Content.ReadAsStringAsync(ct);
        par.StatusCode.Should().Be(HttpStatusCode.Created, ErrorOf(parRaw));
        var requestUri = JsonNode.Parse(parRaw)!["request_uri"]!.GetValue<string>();
        requestUri.Should().StartWith("urn:ietf:params:oauth:request_uri:", "the request_uri stays a PAR URN");
        ForgetProcessState();

        await SignInAsync(replicaB, cookies, tenantId, userName, ct);
        var code = await AuthorizeAsync(replicaB, cookies,
            $"client_id={ClientId}&request_uri={Uri.EscapeDataString(requestUri)}", ct);
        ForgetProcessState();

        var response = await RedeemCodeAsync(replicaA, code, ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, ErrorOf(raw));
        TenantOf(JsonNode.Parse(raw)!["access_token"]!.GetValue<string>()).Should().BeEquivalentTo(tenantId);
    }

    [Fact]
    public async Task RefreshToken_WithoutAcrValues_AfterRestart_RefreshesInTheSubTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var cookies = new CookieContainer();

        var beforeRestart = NewReplica();
        await SignInAsync(beforeRestart, cookies, tenantId, userName, ct);
        var code = await AuthorizeAsync(beforeRestart, cookies, AuthorizeQuery(tenantId), ct);
        var token = await RedeemCodeAsync(beforeRestart, code, ct);
        var tokenRaw = await token.Content.ReadAsStringAsync(ct);
        token.StatusCode.Should().Be(HttpStatusCode.OK, ErrorOf(tokenRaw));
        var refreshToken = JsonNode.Parse(tokenRaw)!["refresh_token"]!.GetValue<string>();

        // A fresh host = a restarted process: nothing of the first host survives except the database.
        ForgetProcessState();
        var afterRestart = NewReplica();

        var refresh = await RefreshAsync(afterRestart, refreshToken, acrTenantId: null, ct);
        var raw = await refresh.Content.ReadAsStringAsync(ct);
        refresh.StatusCode.Should().Be(HttpStatusCode.OK,
            "a client without acr_values (octo-sdk without TenantId, services) must keep its session: {0}", ErrorOf(raw));
        var body = JsonNode.Parse(raw)!;
        TenantOf(body["access_token"]!.GetValue<string>()).Should().BeEquivalentTo(tenantId);

        // The rotated refresh token keeps working on another replica too.
        ForgetProcessState();
        var otherReplica = NewReplica();
        var second = await RefreshAsync(otherReplica, body["refresh_token"]!.GetValue<string>(), null, ct);
        second.StatusCode.Should().Be(HttpStatusCode.OK, ErrorOf(await second.Content.ReadAsStringAsync(ct)));
    }

    [Fact]
    public async Task RefreshToken_WithAcrValues_StillRefreshes()
    {
        // The Studio/SPA path: acr_values=tenant:{T} on every refresh — unchanged.
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var cookies = new CookieContainer();
        await SignInAsync(Factory, cookies, tenantId, userName, ct);
        var code = await AuthorizeAsync(Factory, cookies, AuthorizeQuery(tenantId), ct);
        var tokenRaw = await (await RedeemCodeAsync(Factory, code, ct)).Content.ReadAsStringAsync(ct);
        var refreshToken = JsonNode.Parse(tokenRaw)!["refresh_token"]!.GetValue<string>();
        ForgetProcessState();

        var refresh = await RefreshAsync(Factory, refreshToken, tenantId, ct);
        var raw = await refresh.Content.ReadAsStringAsync(ct);
        refresh.StatusCode.Should().Be(HttpStatusCode.OK, ErrorOf(raw));
        TenantOf(JsonNode.Parse(raw)!["access_token"]!.GetValue<string>()).Should().BeEquivalentTo(tenantId);
    }

    [Fact]
    public async Task AuthorizationCode_PointedAtAnotherTenant_IsRejected()
    {
        // The tenant travels with the code but only selects the token store; a code redeemed against another
        // tenant (a changed marker) does not exist there. The client exists in both tenants, so the request
        // reaches the code validation.
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithClientAsync();
        var otherTenantId = await CreateTenantWithClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var cookies = new CookieContainer();
        await SignInAsync(Factory, cookies, tenantId, userName, ct);
        var code = await AuthorizeAsync(Factory, cookies, AuthorizeQuery(tenantId), ct);

        OidcTenantMarker.TryDecode(code, out var markedTenant, out var innerCode).Should().BeTrue(
            "the code carries its tenant");
        markedTenant.Should().BeEquivalentTo(tenantId);

        var response = await RedeemCodeAsync(Factory, OidcTenantMarker.Encode(otherTenantId, innerCode), ct);
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        ErrorOf(await response.Content.ReadAsStringAsync(ct)).Should().StartWith("invalid_grant");

        // The genuine code is still valid in its own tenant (the failed attempt did not redeem it elsewhere).
        (await RedeemCodeAsync(Factory, code, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RefreshToken_PointedAtAnotherTenant_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithClientAsync();
        var otherTenantId = await CreateTenantWithClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var cookies = new CookieContainer();
        await SignInAsync(Factory, cookies, tenantId, userName, ct);
        var code = await AuthorizeAsync(Factory, cookies, AuthorizeQuery(tenantId), ct);
        var tokenRaw = await (await RedeemCodeAsync(Factory, code, ct)).Content.ReadAsStringAsync(ct);
        var refreshToken = JsonNode.Parse(tokenRaw)!["refresh_token"]!.GetValue<string>();
        OidcTenantMarker.TryDecode(refreshToken, out _, out var innerToken).Should().BeTrue();

        var forged = await RefreshAsync(Factory, OidcTenantMarker.Encode(otherTenantId, innerToken), null, ct);
        forged.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        ErrorOf(await forged.Content.ReadAsStringAsync(ct)).Should().StartWith("invalid_grant");

        // acr_values naming another tenant does not move the token there either: the marker names the store the
        // token lives in, so the refresh runs — and issues — in the token's own tenant only.
        var crossAcr = await RefreshAsync(Factory, refreshToken, otherTenantId, ct);
        var crossRaw = await crossAcr.Content.ReadAsStringAsync(ct);
        crossAcr.StatusCode.Should().Be(HttpStatusCode.OK, ErrorOf(crossRaw));
        TenantOf(JsonNode.Parse(crossRaw)!["access_token"]!.GetValue<string>()).Should().BeEquivalentTo(tenantId);
    }

    [Fact]
    public async Task Revocation_OfAMarkedRefreshToken_RevokesItInItsTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var cookies = new CookieContainer();
        await SignInAsync(Factory, cookies, tenantId, userName, ct);
        var code = await AuthorizeAsync(Factory, cookies, AuthorizeQuery(tenantId), ct);
        var tokenRaw = await (await RedeemCodeAsync(Factory, code, ct)).Content.ReadAsStringAsync(ct);
        var refreshToken = JsonNode.Parse(tokenRaw)!["refresh_token"]!.GetValue<string>();

        var revoke = await AnonymousClient(Factory).PostAsync("/connect/revocation", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["client_id"] = ClientId,
                ["token"] = refreshToken,
                ["token_type_hint"] = "refresh_token"
            }), ct);
        revoke.StatusCode.Should().Be(HttpStatusCode.OK, ErrorOf(await revoke.Content.ReadAsStringAsync(ct)));

        var refresh = await RefreshAsync(Factory, refreshToken, null, ct);
        refresh.StatusCode.Should().Be(HttpStatusCode.BadRequest, "the revoked refresh token is no longer valid");
        ErrorOf(await refresh.Content.ReadAsStringAsync(ct)).Should().StartWith("invalid_grant");
    }

    [Fact]
    public void Middleware_HoldsNoProcessLocalTokenToTenantState()
    {
        // AC: TokenToTenantMap is removed — no mapping a second replica would need lives in process memory, so no
        // mapping can outlive its token either.
        typeof(OidcTenantResolutionMiddleware)
            .GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
            .Where(f => typeof(IDictionary).IsAssignableFrom(f.FieldType) ||
                        f.FieldType.GetInterfaces().Any(i => i.IsGenericType &&
                                                             i.GetGenericTypeDefinition() == typeof(IDictionary<,>)))
            .Select(f => f.Name)
            .Should().BeEmpty();
    }

    #region Helpers

    /// <summary>
    ///     Empties every static dictionary of the middleware — what a second pod or a restarted process does not have.
    ///     A no-op once the middleware keeps no such state (AB#7892).
    /// </summary>
    private static void ForgetProcessState()
    {
        foreach (var field in typeof(OidcTenantResolutionMiddleware).GetFields(BindingFlags.Static |
                     BindingFlags.NonPublic | BindingFlags.Public))
        {
            if (field.GetValue(null) is IDictionary dictionary)
            {
                dictionary.Clear();
            }
        }
    }

    /// <summary>
    ///     A new in-process host over the same MongoDB. Not disposed inside the test: the parent factory disposes its
    ///     derived hosts at fixture teardown. Disposing one mid-test races with the host's own shutdown in
    ///     <c>AuditEventAggregationFlushService.StopAsync</c> (octo-common-services) and fails at random, unrelated to
    ///     what these tests check.
    /// </summary>
    private WebApplicationFactory<Program> NewReplica() => Factory.WithWebHostBuilder(_ => { });

    private static HttpClient AnonymousClient(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static HttpClient CookieClient(WebApplicationFactory<Program> host, CookieContainer cookies)
        => host.CreateDefaultClient(new Uri("http://localhost"), new CookieContainerHandler(cookies));

    private static Dictionary<string, string> AuthorizeParameters(string tenantId)
        => new()
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = Scopes,
            ["state"] = "replica-state",
            ["nonce"] = "replica-nonce",
            ["code_challenge"] = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(CodeVerifier))),
            ["code_challenge_method"] = "S256",
            ["acr_values"] = $"tenant:{tenantId}"
        };

    private static string AuthorizeQuery(string tenantId)
        => string.Join('&', AuthorizeParameters(tenantId)
            .Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));

    private static async Task SignInAsync(WebApplicationFactory<Program> host, CookieContainer cookies,
        string tenantId, string userName, CancellationToken ct)
    {
        var response = await CookieClient(host, cookies).PostAsJsonAsync(AuthApiUrl("login", tenantId),
            new LoginRequestDto { Username = userName, Password = DefaultPassword }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!.Success.Should().BeTrue();
    }

    /// <summary>Runs <c>/connect/authorize</c> with the signed-in browser and returns the code of the redirect.</summary>
    private static async Task<string> AuthorizeAsync(WebApplicationFactory<Program> host, CookieContainer cookies,
        string query, CancellationToken ct)
    {
        var browser = host.CreateDefaultClient(new Uri("http://localhost"), new CookieContainerHandler(cookies));
        var response = await browser.GetAsync($"/connect/authorize?{query}", ct);
        ((int)response.StatusCode).Should().BeInRange(302, 303, "authorize must redirect");
        var location = response.Headers.Location!;
        location.ToString().Should().StartWith(RedirectUri,
            "the tenant is resolved, so authorize answers the client and does not loop to tenant discovery");
        var code = HttpUtility.ParseQueryString(location.Query)["code"];
        code.Should().NotBeNullOrEmpty();
        return code!;
    }

    private static Task<HttpResponseMessage> RedeemCodeAsync(WebApplicationFactory<Program> host, string code,
        CancellationToken ct)
        => AnonymousClient(host).PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = ClientId,
                ["code"] = code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = CodeVerifier
            }), ct);

    private static Task<HttpResponseMessage> RefreshAsync(WebApplicationFactory<Program> host, string refreshToken,
        string? acrTenantId, CancellationToken ct)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = ClientId,
            ["refresh_token"] = refreshToken
        };
        if (acrTenantId != null)
        {
            form["acr_values"] = $"tenant:{acrTenantId}";
        }

        return AnonymousClient(host).PostAsync("/connect/token", new FormUrlEncodedContent(form), ct);
    }

    private static string? TenantOf(string accessToken)
        => new JsonWebToken(accessToken).Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;

    /// <summary>The OAuth error of a response — never the response itself, which may carry a token.</summary>
    private static string ErrorOf(string body)
    {
        try
        {
            var node = JsonNode.Parse(body);
            return $"{node?["error"]?.GetValue<string>() ?? "(none)"}: {node?["error_description"]?.GetValue<string>()}";
        }
        catch (System.Text.Json.JsonException)
        {
            return "(no JSON body)";
        }
    }

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A child tenant whose OIDC client exists only there (not in the system tenant).</summary>
    private async Task<string> CreateTenantWithClientAsync()
    {
        var tenantId = $"oidcrep{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        }

        var repository = (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
        var clientStore = new ClientStore(new FixedTenantResolver(repository));
        if (await clientStore.FindRtClientByIdAsync(ClientId) == null)
        {
            await clientStore.CreateAsync(new RtClientBuilder()
                .WithClientId(ClientId)
                .WithClientName(ClientId)
                .WithGrantTypes("authorization_code")
                .WithScopes("openid", "profile", "offline_access")
                .WithRedirectUris(RedirectUri)
                .WithAllowOfflineAccess()
                .RequirePkce()
                .Build());
        }

        return tenantId;
    }

    /// <summary>A local user of the tenant itself.</summary>
    private async Task<string> CreateLocalUserAsync(string tenantId)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var repository = (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
        using var scope = CreateScope();
        var sp = scope.ServiceProvider;
        using var userManager = new UserManager<RtUser>(
            new OctoUserStore(new FixedTenantResolver(repository), sp.GetRequiredService<IGroupRoleResolver>(), null),
            sp.GetRequiredService<IOptions<IdentityOptions>>(),
            sp.GetRequiredService<IPasswordHasher<RtUser>>(),
            sp.GetServices<IUserValidator<RtUser>>(),
            sp.GetServices<IPasswordValidator<RtUser>>(),
            sp.GetRequiredService<ILookupNormalizer>(),
            sp.GetRequiredService<IdentityErrorDescriber>(),
            sp,
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<UserManager<RtUser>>>());

        var userName = $"oidcrep_{Guid.NewGuid():N}";
        var user = new RtUserBuilder().WithUserName(userName).WithEmail($"{userName}@example.com")
            .WithEmailConfirmed(true).Build();
        (await userManager.CreateAsync(user, DefaultPassword)).Succeeded.Should().BeTrue();
        return userName;
    }

    #endregion
}
