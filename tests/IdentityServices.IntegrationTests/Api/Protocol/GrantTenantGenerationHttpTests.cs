using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Helpers;
using IdentityServices.IntegrationTests.Infrastructure;
using IdentityServices.IntegrationTests.Persistence;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Configuration;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Infrastructure.TenantGeneration;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#9017 over the real token endpoint: a refresh token, an authorization code and a token-exchange subject token of
///     an earlier tenant with the same id (deleted and created again: a new lifecycle <c>CreatedUtc</c>) are refused with
///     <c>invalid_grant</c> in <c>Enforce</c>, nothing is redeemed, rotated or provisioned, and a fresh sign-in works; in
///     <c>LogOnly</c> the same requests behave as before and are counted as <c>mismatch</c> with <c>transport=grant</c>.
/// </summary>
/// <remarks>
///     <para>
///         The recreation is arranged through <see cref="TestTenantLifecycleStore" /> (a new generation of the same tenant
///         id) plus <see cref="ITenantGenerationReader.Invalidate" />, which the tenant events do in production.
///     </para>
///     <para>
///         The test host signs in to its system tenant, and the system tenant is never checked (AB#8999). The derived hosts
///         of this class therefore build the production <see cref="TenantGenerationCheck" /> with another
///         <c>SystemTenantId</c>; evaluator, reader, option binding, metric and every identity code path are the real ones.
///         On-behalf-of runs through the same guard; its cases are covered by <c>GrantTenantGenerationGuardTests</c> (unit,
///         genuinely signed subject tokens, the real evaluator).
///     </para>
/// </remarks>
public sealed class GrantTenantGenerationHttpTests : IntegrationTestBase, IDisposable
{
    private const string ApiScope = "grantgen-api";
    private const string RedirectUri = "https://grantgen.example/callback";
    private const string CodeVerifier = "grantgen-code-verifier-grantgen-code-verifier-9017";
    private const string ExchangeClientId = "grantgen-exchange";

    private static readonly DateTime Generation1 = new(2026, 11, 15, 8, 0, 0, 123, DateTimeKind.Utc);
    private static readonly DateTime Generation2 = new(2026, 11, 15, 9, 30, 0, 456, DateTimeKind.Utc);
    private const string Generation1Ms = "1794729600123";

    private readonly Dictionary<TenantGenerationEnforcementMode, WebApplicationFactory<Program>> _hosts = new();

    public GrantTenantGenerationHttpTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public void Dispose()
    {
        foreach (var host in _hosts.Values)
        {
            host.Dispose();
        }

        Factory.TenantLifecycleStore.Reset();
    }

    // --- refresh token -----------------------------------------------------------------------------------------------

    [Fact]
    public async Task Enforce_RefreshTokenOfAnEarlierTenant_IsRefused_NotRotated_AndAFreshSignInWorks()
    {
        var ct = TestContext.Current.CancellationToken;
        var host = Host(TenantGenerationEnforcementMode.Enforce);
        Arrange(host, Generation1);
        var clientId = await CreateSpaClientAsync();
        var userName = await CreateUserAsync();

        var first = await SignInAndRedeemAsync(host, clientId, userName, ct);
        DecodePayload(first.AccessToken)["tenant_gen"]!.GetValue<string>().Should().Be(Generation1Ms);

        // The tenant is deleted and created again with the same id.
        Arrange(host, Generation2);
        var refused = await RefreshAsync(host, clientId, first.RefreshToken, ct);
        refused.Status.Should().Be(HttpStatusCode.BadRequest, "body error: {0}", ErrorOf(refused.Body));
        refused.Body!["error"]!.GetValue<string>().Should().Be("invalid_grant");
        refused.Body.ContainsKey("access_token").Should().BeFalse();
        refused.Body["error_description"]!.GetValue<string>().Should().Be(GrantTenantGenerationGuard.RefusedDescription);

        // Not redeemed: the same refresh token still works for the generation it was issued for.
        Arrange(host, Generation1);
        (await RefreshAsync(host, clientId, first.RefreshToken, ct)).Status.Should().Be(HttpStatusCode.OK,
            "the refused request must not have redeemed or rotated the refresh token");

        // A fresh sign-in on the recreated tenant works for code and refresh.
        Arrange(host, Generation2);
        var fresh = await SignInAndRedeemAsync(host, clientId, userName, ct);
        (await RefreshAsync(host, clientId, fresh.RefreshToken, ct)).Status.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Enforce_AuthorizationCodeOfAnEarlierTenant_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var host = Host(TenantGenerationEnforcementMode.Enforce);
        Arrange(host, Generation1);
        var clientId = await CreateSpaClientAsync();
        var userName = await CreateUserAsync();
        var browser = await SignInAsync(host, userName, ct);
        var code = await AuthorizeAsync(browser, clientId, ct);

        Arrange(host, Generation2);
        var refused = await RedeemAsync(host, clientId, code, ct);

        refused.Status.Should().Be(HttpStatusCode.BadRequest);
        refused.Body!["error"]!.GetValue<string>().Should().Be("invalid_grant");

        Arrange(host, Generation1);
        (await RedeemAsync(host, clientId, code, ct)).Status.Should().Be(HttpStatusCode.OK,
            "the refused redemption left the single-use code unredeemed");
    }

    [Fact]
    public async Task Enforce_RefreshTokenWithoutStoredGeneration_IsRefused_LogOnly_LetsItThrough()
    {
        var ct = TestContext.Current.CancellationToken;
        var enforce = Host(TenantGenerationEnforcementMode.Enforce);
        var logOnly = Host(TenantGenerationEnforcementMode.LogOnly);
        var clientId = await CreateSpaClientAsync();
        var userName = await CreateUserAsync();

        // Issued while the tenant had no generation: the stored grant carries none (like a grant from before AB#9017).
        Factory.TenantLifecycleStore.ArrangeNoRecord(NormalizedSystemTenantId);
        Invalidate(enforce);
        Invalidate(logOnly);
        var legacy = await SignInAndRedeemAsync(enforce, clientId, userName, ct);

        Arrange(enforce, Generation1);
        Invalidate(logOnly);
        var refused = await RefreshAsync(enforce, clientId, legacy.RefreshToken, ct);
        refused.Status.Should().Be(HttpStatusCode.BadRequest);
        refused.Body!["error"]!.GetValue<string>().Should().Be("invalid_grant", "missing is refused in Enforce");

        (await RefreshAsync(logOnly, clientId, legacy.RefreshToken, ct)).Status.Should().Be(HttpStatusCode.OK,
            "LogOnly behaves as before the check");
    }

    [Fact]
    public async Task LogOnly_RefreshTokenOfAnEarlierTenant_IsAllowed_Counted_AndTheRotatedTokenKeepsTheOldGeneration()
    {
        var ct = TestContext.Current.CancellationToken;
        var logOnly = Host(TenantGenerationEnforcementMode.LogOnly);
        var enforce = Host(TenantGenerationEnforcementMode.Enforce);
        Arrange(logOnly, Generation1);
        var clientId = await CreateSpaClientAsync();
        var userName = await CreateUserAsync();
        var first = await SignInAndRedeemAsync(logOnly, clientId, userName, ct);

        Arrange(logOnly, Generation2);
        Invalidate(enforce);
        using var counted = new GrantCheckCounter(clientId);
        var allowed = await RefreshAsync(logOnly, clientId, first.RefreshToken, ct);

        allowed.Status.Should().Be(HttpStatusCode.OK, "LogOnly never refuses: {0}", ErrorOf(allowed.Body));
        counted.Outcomes("refresh_token").Should().Contain("mismatch");

        // The rotated refresh token still names the earlier generation: once the environment enforces, it is refused.
        var rotated = allowed.Body!["refresh_token"]!.GetValue<string>();
        var later = await RefreshAsync(enforce, clientId, rotated, ct);
        later.Status.Should().Be(HttpStatusCode.BadRequest, "LogOnly must not launder an old grant into a valid one");
        later.Body!["error"]!.GetValue<string>().Should().Be("invalid_grant");
    }

    // --- token exchange ------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Enforce_TokenExchangeWithASubjectTokenOfAnEarlierTenant_IsRefused_AndCreatesNoShadowUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var host = Host(TenantGenerationEnforcementMode.Enforce);
        var logOnly = Host(TenantGenerationEnforcementMode.LogOnly);
        Arrange(host, Generation1);
        Invalidate(logOnly);
        var clientId = await CreateSpaClientAsync();
        var userName = await CreateUserAsync();
        var user = await FindUserAsync(userName);
        var childTenantId = await CreateChildTenantAsync(host);
        await GrantChildRoleAsync(childTenantId, user.RtId.ToString(), userName);

        var stale = (await SignInAndRedeemAsync(host, clientId, userName, ct)).AccessToken;
        Arrange(host, Generation2);
        Invalidate(logOnly);
        var shadowUsersBefore = await CountShadowUsersAsync(childTenantId);

        var refused = await ExchangeAsync(host, stale, childTenantId, ct);
        refused.Status.Should().NotBe(HttpStatusCode.OK);
        refused.Body!["error"]!.GetValue<string>().Should().Be("invalid_grant");
        (await CountShadowUsersAsync(childTenantId)).Should().Be(shadowUsersBefore, "no shadow user is created");

        // LogOnly: the same stale token is exchanged as before (and counted).
        using var counted = new GrantCheckCounter(clientId);
        var allowed = await ExchangeAsync(logOnly, stale, childTenantId, ct);
        allowed.Status.Should().Be(HttpStatusCode.OK, "LogOnly behaves as before: {0}", ErrorOf(allowed.Body));
        counted.Outcomes("token_exchange").Should().Contain("mismatch");

        // A fresh token of the recreated tenant is exchanged in Enforce.
        var fresh = (await SignInAndRedeemAsync(host, clientId, userName, ct)).AccessToken;
        (await ExchangeAsync(host, fresh, childTenantId, ct)).Status.Should().Be(HttpStatusCode.OK);
    }

    // --- identity's own HTTP tenant check (AuthenticationType "Bearer") --------------------------------------------------

    [Fact]
    public void IdentityRunsTheUserAndServiceTokenTenantCheckWithTheLibraryDefaults_AndTheConfigurationCanLowerIt()
    {
        // The bearer label makes TenantAuthorizationMiddleware run on identity's API; identity adds no default of its
        // own, so user and service tokens of another tenant are refused (Enforce, octo-common-services default).
        var defaults = Factory.Services.GetRequiredService<IOptions<TenantAuthorizationOptions>>().Value;
        defaults.UserTokenEnforcement.Should().Be(UserTokenTenantEnforcementMode.Enforce);
        defaults.ServiceTokenEnforcement.Should().Be(ServiceTokenTenantEnforcementMode.Enforce);
        defaults.TenantGenerationEnforcement.Should().Be(TenantGenerationEnforcementMode.LogOnly);

        using var lowered = Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("TenantAuthorization:UserTokenEnforcement", "LogOnly");
            b.UseSetting("TenantAuthorization:ServiceTokenEnforcement", "LogOnly");
        });
        var configured = lowered.Services.GetRequiredService<IOptions<TenantAuthorizationOptions>>().Value;
        configured.UserTokenEnforcement.Should().Be(UserTokenTenantEnforcementMode.LogOnly);
        configured.ServiceTokenEnforcement.Should().Be(ServiceTokenTenantEnforcementMode.LogOnly);
    }

    // --- hosts and arrangement ------------------------------------------------------------------------------------------

    /// <summary>A host in the given mode whose generation check does not exempt the test host's system tenant.</summary>
    private WebApplicationFactory<Program> Host(TenantGenerationEnforcementMode mode)
    {
        if (_hosts.TryGetValue(mode, out var existing))
        {
            return existing;
        }

        var host = Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("TenantAuthorization:TenantGenerationEnforcement", mode.ToString());
            b.ConfigureTestServices(services =>
            {
                services.RemoveAll<ITenantGenerationCheck>();
                services.AddSingleton<ITenantGenerationCheck>(sp => new TenantGenerationCheck(
                    sp.GetRequiredService<ITenantGenerationReader>(),
                    sp.GetRequiredService<TenantGenerationMetrics>(),
                    sp.GetRequiredService<IOptions<TenantAuthorizationOptions>>(),
                    Options.Create(new OctoSystemConfiguration { SystemTenantId = "not-the-test-system-tenant" }),
                    sp.GetRequiredService<ILogger<TenantGenerationCheck>>()));
            });
        });
        _hosts[mode] = host;
        return host;
    }

    private void Arrange(WebApplicationFactory<Program> host, DateTime generation)
    {
        Factory.TenantLifecycleStore.ArrangeGeneration(NormalizedSystemTenantId, generation);
        Invalidate(host);
    }

    /// <summary>What the tenant events do in production: drop the cached generation.</summary>
    private void Invalidate(WebApplicationFactory<Program> host) =>
        host.Services.GetRequiredService<ITenantGenerationReader>().Invalidate(NormalizedSystemTenantId);

    private async Task<string> CreateSpaClientAsync()
    {
        var clientId = $"grantgen-spa-{Guid.NewGuid():N}"[..24];
        await EnsureApiScopeAsync();
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId)
            .WithGrantTypes("authorization_code")
            .WithScopes("openid", "profile", "offline_access", ApiScope)
            .WithRedirectUris(RedirectUri)
            .WithAllowOfflineAccess()
            .RequirePkce()
            .Build());
        return clientId;
    }

    private async Task<string> CreateUserAsync()
    {
        var userName = $"grantgen{Guid.NewGuid():N}"[..20];
        await CreateTestUserAsync(userName, $"{userName}@example.com");
        return userName;
    }

    private async Task<RtUser> FindUserAsync(string userName)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<RtUser>>()
            .FindByNameAsync(userName))!;
    }

    private async Task EnsureApiScopeAsync()
    {
        using var scope = CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();
        if (await resourceStore.GetApiScopeByNameAsync(ApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ApiScope,
                DisplayName = "Grant generation API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }
    }

    // --- protocol helpers -----------------------------------------------------------------------------------------------

    private sealed record TokenResult(HttpStatusCode Status, JsonObject? Body);

    private sealed record Tokens(string AccessToken, string RefreshToken);

    private static async Task<HttpClient> SignInAsync(WebApplicationFactory<Program> host, string userName,
        CancellationToken ct)
    {
        var browser = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = true,
            AllowAutoRedirect = false
        });
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login"),
            new { Username = userName, Password = DefaultPassword, RememberLogin = true }, ct);
        response.EnsureSuccessStatusCode();
        (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!.Success.Should().BeTrue();
        return browser;
    }

    private async Task<string> AuthorizeAsync(HttpClient browser, string clientId, CancellationToken ct)
    {
        var authorize = await browser.GetAsync("/connect/authorize" +
                                               $"?client_id={clientId}" +
                                               $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                                               "&response_type=code" +
                                               $"&scope={Uri.EscapeDataString($"openid profile offline_access {ApiScope}")}" +
                                               "&state=s&nonce=n" +
                                               $"&code_challenge={Base64UrlSha256(CodeVerifier)}&code_challenge_method=S256" +
                                               $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}",
            ct);
        ((int)authorize.StatusCode).Should().BeInRange(302, 303);
        var code = HttpUtility.ParseQueryString(authorize.Headers.Location!.Query)["code"];
        code.Should().NotBeNullOrEmpty("authorize must redirect with a code: {0}", authorize.Headers.Location);
        return code!;
    }

    private static Task<TokenResult> RedeemAsync(WebApplicationFactory<Program> host, string clientId, string code,
        CancellationToken ct) =>
        PostTokenAsync(host, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = CodeVerifier
        }, ct);

    private async Task<Tokens> SignInAndRedeemAsync(WebApplicationFactory<Program> host, string clientId,
        string userName, CancellationToken ct)
    {
        var browser = await SignInAsync(host, userName, ct);
        var redeemed = await RedeemAsync(host, clientId, await AuthorizeAsync(browser, clientId, ct), ct);
        redeemed.Status.Should().Be(HttpStatusCode.OK, "code redemption: {0}", ErrorOf(redeemed.Body));
        return new Tokens(redeemed.Body!["access_token"]!.GetValue<string>(),
            redeemed.Body["refresh_token"]!.GetValue<string>());
    }

    private Task<TokenResult> RefreshAsync(WebApplicationFactory<Program> host, string clientId, string refreshToken,
        CancellationToken ct) =>
        PostTokenAsync(host, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = refreshToken,
            ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
        }, ct);

    private static Task<TokenResult> ExchangeAsync(WebApplicationFactory<Program> host, string subjectToken,
        string childTenantId, CancellationToken ct) =>
        PostTokenAsync(host, new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["client_id"] = ExchangeClientId,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["acr_values"] = $"tenant:{childTenantId}"
        }, ct);

    private static async Task<TokenResult> PostTokenAsync(WebApplicationFactory<Program> host,
        Dictionary<string, string> form, CancellationToken ct)
    {
        var response = await host.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(form), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        JsonObject? body = null;
        try
        {
            body = JsonNode.Parse(raw) as JsonObject;
        }
        catch (JsonException)
        {
            // not JSON — the assertions report the status
        }

        return new TokenResult(response.StatusCode, body);
    }

    /// <summary>The OAuth error of a token response — never the response itself, which may carry a token.</summary>
    private static string ErrorOf(JsonObject? body) =>
        body == null
            ? "(no JSON body)"
            : $"{body["error"]?.GetValue<string>() ?? "(none)"}: {body["error_description"]?.GetValue<string>()}";

    private static JsonObject DecodePayload(string jwt) =>
        JsonNode.Parse(new JsonWebToken(jwt).EncodedPayload is { } payload
            ? Encoding.UTF8.GetString(Base64UrlDecode(payload))
            : "{}")!.AsObject();

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }

    private static string Base64UrlSha256(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(value)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // --- child tenant (token exchange) -----------------------------------------------------------------------------------

    private async Task<string> CreateChildTenantAsync(WebApplicationFactory<Program> host)
    {
        var childTenantId = $"grantgen{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>()
                .SetupAsync(childTenantId);
        }

        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        using (var session = await childRepo.GetSessionAsync())
        {
            session.StartTransaction();
            await childRepo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = $"ParentTenant_{NormalizedSystemTenantId}",
                DisplayName = $"Login via {NormalizedSystemTenantId}",
                IsEnabled = true,
                AllowSelfRegistration = true,
                ParentTenantId = NormalizedSystemTenantId
            });
            await session.CommitTransactionAsync();
        }

        foreach (var services in new[] { Factory.Services, host.Services, Host(TenantGenerationEnforcementMode.LogOnly).Services })
        {
            await WaitUntilRegistryKnowsAsync(services, childTenantId);
        }

        return childTenantId;
    }

    private static async Task WaitUntilRegistryKnowsAsync(IServiceProvider services, string tenantId)
    {
        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = services.CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    /// <summary>Explicit provisioning in the child (a mapping with a role) plus the exchanging public client there.</summary>
    private async Task GrantChildRoleAsync(string childTenantId, string sourceUserId, string sourceUserName)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var roleName = $"grantgenrole{Guid.NewGuid():N}"[..20];
        var roleId = OctoObjectId.GenerateNewId();

        using (var session = await childRepo.GetSessionAsync())
        {
            session.StartTransaction();
            await childRepo.InsertOneRtEntityAsync(session, new RtRole
            {
                RtId = roleId,
                Name = roleName,
                NormalizedName = roleName.ToUpperInvariant()
            });
            await childRepo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
            {
                RtId = OctoObjectId.GenerateNewId(),
                SourceTenantId = NormalizedSystemTenantId,
                SourceUserId = sourceUserId,
                SourceUserName = sourceUserName,
                MappedRoleIds = new AttributeStringValueList { roleId.ToString() }
            });
            await session.CommitTransactionAsync();
        }

        var clientStore = new ClientStore(new FixedTenantResolver(childRepo));
        if (await clientStore.FindRtClientByIdAsync(ExchangeClientId) == null)
        {
            await clientStore.CreateAsync(new RtClientBuilder()
                .WithClientId(ExchangeClientId)
                .WithClientName(ExchangeClientId)
                .WithGrantTypes("urn:ietf:params:oauth:grant-type:token-exchange")
                .WithScopes("openid")
                .RequirePkce(false)
                .Build());
        }
    }

    private async Task<int> CountShadowUsersAsync(string childTenantId)
    {
        var repo = (await Factory.Services.GetRequiredService<ISystemContext>()
            .TryFindTenantRepositoryAsync(childTenantId))!;
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var users = await repo.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return users.Items.Count(u => u.UserName?.StartsWith("xt_", StringComparison.Ordinal) == true);
    }

    /// <summary>Collects <c>octo.tenant_auth.generation_checks</c> of one client (labels only, never values).</summary>
    private sealed class GrantCheckCounter : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly List<(string? GrantType, string? Outcome)> _seen = [];

        public GrantCheckCounter(string clientId)
        {
            _listener.InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == TenantGenerationMetrics.MeterName &&
                    instrument.Name == TenantGenerationMetrics.CounterName)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
            {
                string? client = null, transport = null, grantType = null, outcome = null;
                foreach (var tag in tags)
                {
                    switch (tag.Key)
                    {
                        case TenantGenerationMetrics.ClientIdTag: client = tag.Value as string; break;
                        case TenantGenerationMetrics.TransportTag: transport = tag.Value as string; break;
                        case TenantGenerationMetrics.GrantTypeTag: grantType = tag.Value as string; break;
                        case TenantGenerationMetrics.OutcomeTag: outcome = tag.Value as string; break;
                    }
                }

                if (transport == TenantGenerationTransports.Grant && client == clientId)
                {
                    lock (_seen)
                    {
                        _seen.Add((grantType, outcome));
                    }
                }
            });
            _listener.Start();
        }

        public IReadOnlyList<string?> Outcomes(string grantType)
        {
            lock (_seen)
            {
                return _seen.Where(s => s.GrantType == grantType).Select(s => s.Outcome).ToList();
            }
        }

        public void Dispose() => _listener.Dispose();
    }
}
