using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#7959: the device confirmation names the target tenant and the signed-in account (RFC 8628 §5.4), and the
///     application cookie the <c>[IgnoreAntiforgeryToken]</c> verification POST relies on is explicitly
///     <c>SameSite=Lax</c>, while the OIDC session-check cookie stays <c>SameSite=None</c>.
/// </summary>
/// <remarks>Cookie assertions look at the attributes only; a cookie value is never asserted on or printed.</remarks>
public class DeviceConfirmationContextTests : IntegrationTestBase
{
    private const string ClientId = "confirm-context-device-client";
    private const string ApplicationCookiePrefix = ".AspNetCore.Identity.Application.";
    private const string SessionCheckCookiePrefix = "idsrv.session";

    public DeviceConfirmationContextTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Context_NamesTheTargetTenantAndTheSignedInAccount()
    {
        var ct = TestContext.Current.CancellationToken;
        var userCode = await StartDeviceFlowAsync(ct);
        var userName = $"confirm-user-{Guid.NewGuid():N}";
        var email = $"{userName}@confirm.example";
        await CreateTestUserAsync(userName, email: email);
        var browser = await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct);
        browser.Should().NotBeNull("the cookie login of the test user must succeed");

        var response = await browser!.GetAsync($"/connect/deviceverification?user_code={userCode}", ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var context = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject();
        context["tenantId"]!.GetValue<string>().Should().BeEquivalentTo(NormalizedSystemTenantId);
        context["accountUserName"]!.GetValue<string>().Should().Be(userName);
        context["accountEmail"]!.GetValue<string>().Should().Be(email);
        context["clientName"]!.GetValue<string>().Should().Be(ClientId, "client, user code and scopes stay");
        context["userCode"]!.GetValue<string>().Should().Be(userCode);
    }

    [Fact]
    public async Task Context_SessionSubjectMissingInTheTenant_StillNamesTheSessionAccount_ApprovalRefused()
    {
        // Fallback to the session claims (AB#7884 case): the dialog still names who is signed in.
        var ct = TestContext.Current.CancellationToken;
        var userCode = await StartDeviceFlowAsync(ct);
        var userName = $"confirm-gone-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, email: $"{userName}@confirm.example");
        var browser = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            (await userManager.DeleteAsync((await userManager.FindByNameAsync(userName))!)).Succeeded.Should().BeTrue();
        }

        var response = await browser.GetAsync($"/connect/deviceverification?user_code={userCode}", ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var context = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject();
        context["accountUserName"]!.GetValue<string>().Should().Be(userName);
        context["tenantId"]!.GetValue<string>().Should().BeEquivalentTo(NormalizedSystemTenantId);

        var approve = await browser.PostAsync("/connect/deviceverification",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["user_code"] = userCode }), ct);
        var body = JsonNode.Parse(await approve.Content.ReadAsStringAsync(ct))!.AsObject();
        body["success"]!.GetValue<bool>().Should().BeFalse("the subject does not exist in this tenant");
    }

    [Fact]
    public void ApplicationCookie_IsConfiguredSameSiteLaxExplicitly()
    {
        var options = Factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(IdentityConstants.ApplicationScheme);

        options.Cookie.SameSite.Should().Be(SameSiteMode.Lax);
    }

    [Fact]
    public async Task Login_IssuesTheApplicationCookieSameSiteLax_AndTheSessionCheckCookieSameSiteNone()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"samesite-user-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);
        var client = Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost")
        });

        var login = await client.PostAsJsonAsync(AuthApiUrl("login"),
            new { Username = userName, Password = DefaultPassword, RememberLogin = true }, ct);

        login.StatusCode.Should().Be(HttpStatusCode.OK);
        var setCookies = login.Headers.GetValues("Set-Cookie").ToList();
        var applicationCookies = setCookies.Where(c => c.StartsWith(ApplicationCookiePrefix, StringComparison.Ordinal))
            .ToList();
        applicationCookies.Should().NotBeEmpty("the login issues the tenant-scoped application cookie");
        applicationCookies.Select(SameSiteOf).Should().OnlyContain(s => s == "lax");

        var sessionCheckCookies = setCookies
            .Where(c => c.StartsWith(SessionCheckCookiePrefix, StringComparison.Ordinal)).ToList();
        sessionCheckCookies.Should().NotBeEmpty("the session-check cookie for the OIDC iframe is still issued");
        sessionCheckCookies.Select(SameSiteOf).Should().OnlyContain(s => s == "none",
            "silent renew / session check must keep working cross-site");
    }

    /// <summary>The SameSite attribute (lower case) of a Set-Cookie header — never the cookie value.</summary>
    private static string SameSiteOf(string setCookie)
        => setCookie.Split(';').Skip(1).Select(a => a.Trim())
               .Where(a => a.StartsWith("samesite=", StringComparison.OrdinalIgnoreCase))
               .Select(a => a["samesite=".Length..].ToLowerInvariant())
               .FirstOrDefault()
           ?? "(absent)";

    private async Task<string> StartDeviceFlowAsync(CancellationToken ct)
    {
        using (var scope = CreateScope())
        {
            var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
            if (await clientStore.FindRtClientByIdAsync(ClientId) == null)
            {
                await clientStore.CreateAsync(new RtClientBuilder()
                    .WithClientId(ClientId)
                    .WithClientName(ClientId)
                    .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
                    .WithScopes("openid")
                    .RequirePkce(false)
                    .Build());
            }
        }

        var response = await CreateAnonymousClient().PostAsync("/connect/deviceauthorization",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = ClientId,
                ["scope"] = "openid",
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, raw);
        return JsonNode.Parse(raw)!["user_code"]!.GetValue<string>();
    }
}
