using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using OtpNet;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
///     AB#7859 — second-factor evidence (<c>amr=mfa</c>) survives the periodic security-stamp revalidation of the cookie
///     session and the refresh-token grant, so a 2FA user is not refused at tenant boundaries after 30 minutes.
/// </summary>
/// <remarks>
///     The security-stamp validator rebuilds the session principal from the user (default every 30 minutes). The
///     factory gives it an adjustable clock (<see cref="CustomWebApplicationFactory.SecurityStampClock" />), so the tests
///     step past the interval instead of waiting. A <c>Set-Cookie</c> on the request after the step proves that the
///     revalidation really ran (the validator renews the cookie when it replaces the principal).
/// </remarks>
public class SecondFactorEvidenceRefreshTests : IntegrationTestBase
{
    private const string ClientId = "amr-refresh-spa";
    private const string RedirectUri = "https://amr-refresh.example/callback";
    private const string CodeVerifier = "amr-refresh-code-verifier-amr-refresh-code-verifier-123";

    private static readonly TimeSpan PastRevalidationInterval = TimeSpan.FromMinutes(31);

    public SecondFactorEvidenceRefreshTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private string SourceTenantId => NormalizedSystemTenantId;

    [Fact]
    public async Task SecurityStampRevalidation_KeepsTheSecondFactorEvidence_OnTheSessionAndOnNewTokens()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"amr_stamp_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var totp = await EnableAuthenticatorAsync(userName, ct);
        var childTenantId = await CreateChildTenantAsync();

        var browser = await LoginWithSecondFactorAsync(userName, totp, ct);
        AmrOf((await GetTokensAsync(browser, ct)).AccessToken).Should().Contain(SecondFactorEvidence.MultiFactorMethod,
            "precondition: a password + TOTP sign-in carries amr=mfa");

        try
        {
            Factory.SecurityStampClock.Advance(PastRevalidationInterval);
            var profile = await browser.GetAsync(ManageApiUrl("profile", SourceTenantId), ct);
            profile.StatusCode.Should().Be(HttpStatusCode.OK, "the security stamp did not change, the session stays valid");
            profile.Headers.Contains("Set-Cookie").Should().BeTrue(
                "the security-stamp validator ran and renewed the cookie (otherwise this test proves nothing)");

            AmrOf((await GetTokensAsync(browser, ct)).AccessToken).Should().Contain(
                SecondFactorEvidence.MultiFactorMethod,
                "a token issued from the revalidated session still carries the second-factor evidence");

            var crossTenantToken = await browser.PostAsJsonAsync(AuthApiUrl("cross-tenant-token", SourceTenantId),
                new CrossTenantTokenRequestDto { TargetTenantId = childTenantId }, ct);
            crossTenantToken.StatusCode.Should().Be(HttpStatusCode.OK,
                "the revalidated session still proves the second factor at the tenant boundary: {0}",
                await crossTenantToken.Content.ReadAsStringAsync(ct));
        }
        finally
        {
            Factory.SecurityStampClock.Reset();
        }
    }

    [Fact]
    public async Task RefreshTokenGrant_KeepsTheSecondFactorEvidence()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"amr_refresh_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var totp = await EnableAuthenticatorAsync(userName, ct);

        var browser = await LoginWithSecondFactorAsync(userName, totp, ct);
        var tokens = await GetTokensAsync(browser, ct);
        tokens.RefreshToken.Should().NotBeNullOrEmpty("offline_access was requested and allowed");

        var refresh = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = ClientId,
                ["refresh_token"] = tokens.RefreshToken!,
                ["acr_values"] = $"tenant:{SourceTenantId}"
            }), ct);
        var raw = await refresh.Content.ReadAsStringAsync(ct);
        refresh.StatusCode.Should().Be(HttpStatusCode.OK, "refresh: {0}", ErrorOf(raw));

        AmrOf(JsonNode.Parse(raw)!["access_token"]!.GetValue<string>()).Should().Contain(
            SecondFactorEvidence.MultiFactorMethod, "the refreshed access token keeps the evidence of the original sign-in");
    }

    #region Helpers

    private static IReadOnlyList<string> AmrOf(string jwt)
    {
        var token = new JsonWebToken(jwt);
        return token.Claims.Where(c => c.Type == SecondFactorEvidence.AuthenticationMethodClaimType)
            .Select(c => c.Value).ToList();
    }

    private async Task<HttpClient> LoginWithSecondFactorAsync(string userName, Totp totp, CancellationToken ct)
    {
        var browser = CreateCookieClient();
        var login = await browser.PostAsJsonAsync(AuthApiUrl("login", SourceTenantId),
            new LoginRequestDto { Username = userName, Password = DefaultPassword }, ct);
        (await login.Content.ReadFromJsonAsync<LoginResultDto>(ct))!.RequiresTwoFactor.Should().BeTrue();
        var second = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", SourceTenantId),
            new TwoFactorLoginRequestDto { Code = totp.ComputeTotp() }, ct);
        (await second.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!.Success.Should().BeTrue();
        return browser;
    }

    private async Task<Totp> EnableAuthenticatorAsync(string userName, CancellationToken ct)
    {
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;
        var setupResponse = await session.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        setupResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var setup = (await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct))!;
        var totp = new Totp(Base32Encoding.ToBytes(setup.SharedKey.Replace(" ", string.Empty).ToUpperInvariant()));
        var verify = await session.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"),
            new { Code = totp.ComputeTotp() }, ct);
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        return totp;
    }

    /// <summary>Authorization code + PKCE (with offline_access) in the source tenant, driven by the browser session.</summary>
    private async Task<(string AccessToken, string? RefreshToken)> GetTokensAsync(HttpClient browser,
        CancellationToken ct)
    {
        using (var scope = CreateScope())
        {
            var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
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
        }

        var codeChallenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(CodeVerifier)));
        var authorizeUrl = "/connect/authorize" +
                           $"?client_id={ClientId}" +
                           $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                           "&response_type=code" +
                           $"&scope={Uri.EscapeDataString("openid profile offline_access")}" +
                           "&state=amr-state&nonce=amr-nonce" +
                           $"&code_challenge={codeChallenge}&code_challenge_method=S256" +
                           $"&acr_values={Uri.EscapeDataString($"tenant:{SourceTenantId}")}";

        var authorize = await browser.GetAsync(authorizeUrl, ct);
        ((int)authorize.StatusCode).Should().BeInRange(302, 303, "authorize: {0}",
            await authorize.Content.ReadAsStringAsync(ct));
        var code = HttpUtility.ParseQueryString(authorize.Headers.Location!.Query)["code"];
        code.Should().NotBeNullOrEmpty("authorize must redirect with a code: {0}", authorize.Headers.Location);

        var tokenResponse = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = ClientId,
                ["code"] = code!,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = CodeVerifier
            }), ct);
        var raw = await tokenResponse.Content.ReadAsStringAsync(ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK, "code redemption: {0}", ErrorOf(raw));
        var body = JsonNode.Parse(raw)!;
        return (body["access_token"]!.GetValue<string>(), body["refresh_token"]?.GetValue<string>());
    }

    /// <summary>The OAuth error of a token response — never the response itself, which may carry a token.</summary>
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

    private async Task<string> CreateChildTenantAsync()
    {
        var childTenantId = $"amrref{Guid.NewGuid():N}"[..20];
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
                Name = $"ParentTenant_{SourceTenantId}",
                DisplayName = $"Login via {SourceTenantId}",
                IsEnabled = true,
                AllowSelfRegistration = true,
                ParentTenantId = SourceTenantId
            });
            await session.CommitTransactionAsync();
        }

        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(childTenantId) != null)
            {
                return childTenantId;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{childTenantId}' did not appear in the tenant registry");
    }

    #endregion
}
