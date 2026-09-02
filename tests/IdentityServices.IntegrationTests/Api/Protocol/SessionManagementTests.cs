using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#4989 OIDC Session Management (Duende parity): pins the <c>idsrv.session</c> cookie
///     lifecycle, the <c>session_state</c> parameter on authorize responses and the
///     <c>/connect/checksession</c> iframe. This is the mechanism through which other tabs and
///     SPAs (angular-oauth2-oidc with <c>sessionChecksEnabled</c>) learn about a logout —
///     without it a logout in one tab leaves every other session running until token expiry.
/// </summary>
public class SessionManagementTests : IntegrationTestBase
{
    public SessionManagementTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Login_IssuesSessionCheckCookie_AndAuthorizeCarriesMatchingSessionState()
    {
        var ct = TestContext.Current.CancellationToken;
        const string password = "Test123$abc";
        const string redirectUri = "https://sessionmgmt.example/callback";
        await CreateTestUserAsync("sessionmgmtuser", password: password);
        await CreateTestClientAsync("sessionmgmt-spa",
            grantTypes: ["authorization_code"],
            allowedScopes: ["openid", "profile"],
            redirectUris: [redirectUri]);

        // https base address: the app pipeline treats requests as HTTPS, so the session-check
        // cookie is issued Secure — over an http base the cookie jar would never replay it.
        var client = Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = true,
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost")
        });
        var loginResponse = await client.PostAsJsonAsync(AuthApiUrl("login"),
            new { Username = "sessionmgmtuser", Password = password, RememberLogin = true }, ct);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // The session-check cookie must be browser-readable (NOT HttpOnly) — the checksession
        // iframe reads it via document.cookie.
        var setCookies = loginResponse.Headers.GetValues("Set-Cookie").ToList();
        var idsrvCookies = setCookies.Where(c => c.StartsWith("idsrv.session")).ToList();
        idsrvCookies.Should().HaveCount(1, "login must issue exactly one OP session-check cookie: {0}",
            string.Join(" || ", idsrvCookies));
        var sessionCookie = idsrvCookies[0];
        sessionCookie.Should().NotContainEquivalentOf("httponly");
        var opbs = sessionCookie!.Split(';')[0].Split('=', 2)[1];
        opbs.Should().NotBeNullOrEmpty();

        var codeVerifier = "session-mgmt-code-verifier-session-mgmt-code-verifier";
        var codeChallenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        var authorizeResponse = await client.GetAsync("/connect/authorize" +
            "?client_id=sessionmgmt-spa" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            "&response_type=code" +
            "&scope=openid%20profile" +
            "&state=sm-state" +
            $"&code_challenge={codeChallenge}" +
            "&code_challenge_method=S256" +
            $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}", ct);

        ((int)authorizeResponse.StatusCode).Should().BeInRange(302, 303,
            "authorize should redirect (body: {0})", await authorizeResponse.Content.ReadAsStringAsync(ct));
        var query = HttpUtility.ParseQueryString(authorizeResponse.Headers.Location!.Query);
        query["code"].Should().NotBeNullOrEmpty();

        var sessionState = query["session_state"];
        sessionState.Should().NotBeNullOrEmpty("successful authorize responses must carry session_state");

        // Independent re-implementation of the hash formula — pins server handler and
        // checksession iframe alike: SHA256("client_id origin opbs salt"), base64url, ".salt".
        var salt = sessionState![(sessionState.LastIndexOf('.') + 1)..];
        var expectedHash = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"sessionmgmt-spa https://sessionmgmt.example {opbs} {salt}")));
        sessionState.Should().Be($"{expectedHash}.{salt}");
    }

    [Fact]
    public async Task Logout_DeletesSessionCheckCookie()
    {
        var ct = TestContext.Current.CancellationToken;
        const string password = "Test123$abc";
        await CreateTestUserAsync("sessionmgmtlogout", password: password);

        var client = await LoginAndGetAuthenticatedClientAsync("sessionmgmtlogout", password, ct);
        client.Should().NotBeNull();

        var logoutResponse = await client!.PostAsJsonAsync(AuthApiUrl("logout"), new { }, ct);
        logoutResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var setCookies = logoutResponse.Headers.GetValues("Set-Cookie").ToList();
        var sessionCookie = setCookies.FirstOrDefault(c => c.StartsWith("idsrv.session"));
        sessionCookie.Should().NotBeNull("logout must expire the OP session-check cookie");
        // A deletion Set-Cookie carries an empty value and a past expiry.
        sessionCookie!.Split(';')[0].Split('=', 2)[1].Should().BeEmpty();
    }

    [Fact]
    public async Task CheckSessionIframe_IsServed()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = CreateAnonymousClient();

        var response = await client.GetAsync("/connect/checksession", ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("text/html");
        var html = await response.Content.ReadAsStringAsync(ct);
        html.Should().Contain("addEventListener('message'");
        html.Should().Contain("idsrv.session");
    }
}
