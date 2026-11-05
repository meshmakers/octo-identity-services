using System.Net;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#7090: pins the contract the Angular device page relies on at <c>/connect/deviceverification</c>:
///     approving answers HTTP 200 <c>{ success: true }</c>; a user code that was already redeemed is
///     reported by the server (GET → 404, POST → HTTP 200 <c>{ success: false, error: invalid_token }</c>)
///     so the page can show an error state instead of the consent dialog.
/// </summary>
public class DeviceVerificationFeedbackTests : IntegrationTestBase
{
    private const string ClientId = "feedback-device-client";

    public DeviceVerificationFeedbackTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Approve_ReturnsSuccessTrue_AndTheRedeemedCodeIsReportedAsGone()
    {
        var ct = TestContext.Current.CancellationToken;
        var (userCode, deviceCode) = await StartDeviceFlowAsync(ct);
        var user = await CreateTestUserAsync($"device-user-{Guid.NewGuid():N}");
        var browser = await LoginAndGetAuthenticatedClientAsync(user.UserName!, DefaultPassword, ct);
        browser.Should().NotBeNull("the cookie login of the test user must succeed");

        // Pending code: consent context is delivered.
        var context = await browser!.GetAsync($"/connect/deviceverification?user_code={userCode}", ct);
        context.StatusCode.Should().Be(HttpStatusCode.OK, await context.Content.ReadAsStringAsync(ct));

        // First Allow: documented contract { success: true }.
        var approved = await PostVerificationAsync(browser, userCode, deny: false, ct);
        approved.StatusCode.Should().Be(HttpStatusCode.OK);
        var approvedBody = JsonNode.Parse(await approved.Content.ReadAsStringAsync(ct))!.AsObject();
        approvedBody["success"]!.GetValue<bool>().Should().BeTrue();

        // Redeemed code: the page must not get a consent dialog for it any more ...
        var again = await browser.GetAsync($"/connect/deviceverification?user_code={userCode}", ct);
        again.StatusCode.Should().Be(HttpStatusCode.NotFound);

        // ... and a second Allow reports invalid_token as HTTP 200 { success: false } (never silent).
        var second = await PostVerificationAsync(browser, userCode, deny: false, ct);
        second.StatusCode.Should().Be(HttpStatusCode.OK, await second.Content.ReadAsStringAsync(ct));
        var secondBody = JsonNode.Parse(await second.Content.ReadAsStringAsync(ct))!.AsObject();
        secondBody["success"]!.GetValue<bool>().Should().BeFalse();
        secondBody["error"]!.GetValue<string>().Should().Be("invalid_token");
    }

    [Fact]
    public async Task Deny_ReturnsAccessDenied_AndTheCodeIsReportedAsGone()
    {
        var ct = TestContext.Current.CancellationToken;
        var (userCode, deviceCode) = await StartDeviceFlowAsync(ct);
        var user = await CreateTestUserAsync($"device-user-{Guid.NewGuid():N}");
        var browser = await LoginAndGetAuthenticatedClientAsync(user.UserName!, DefaultPassword, ct);
        browser.Should().NotBeNull("the cookie login of the test user must succeed");

        var denied = await PostVerificationAsync(browser!, userCode, deny: true, ct);
        denied.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonNode.Parse(await denied.Content.ReadAsStringAsync(ct))!.AsObject();
        body["success"]!.GetValue<bool>().Should().BeFalse();
        body["error"]!.GetValue<string>().Should().Be("access_denied");

        (await PollTokenErrorAsync(deviceCode, ct)).Should().Be("access_denied", "a denied device code must stop the polling device");

        var again = await browser!.GetAsync($"/connect/deviceverification?user_code={userCode}", ct);
        again.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task UnknownUserCode_IsReportedAsGone_OnGetAndPost()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync($"device-user-{Guid.NewGuid():N}");
        var browser = await LoginAndGetAuthenticatedClientAsync(user.UserName!, DefaultPassword, ct);
        browser.Should().NotBeNull("the cookie login of the test user must succeed");

        var get = await browser!.GetAsync("/connect/deviceverification?user_code=NOPE-0000", ct);
        get.StatusCode.Should().Be(HttpStatusCode.NotFound);

        var post = await PostVerificationAsync(browser, "NOPE-0000", deny: false, ct);
        post.StatusCode.Should().Be(HttpStatusCode.OK, await post.Content.ReadAsStringAsync(ct));
        var body = JsonNode.Parse(await post.Content.ReadAsStringAsync(ct))!.AsObject();
        body["success"]!.GetValue<bool>().Should().BeFalse();
        body["error"]!.GetValue<string>().Should().Be("invalid_token");
    }

    private async Task<(string UserCode, string DeviceCode)> StartDeviceFlowAsync(CancellationToken ct)
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
        var json = JsonNode.Parse(raw)!;
        return (json["user_code"]!.GetValue<string>(), json["device_code"]!.GetValue<string>());
    }

    private async Task<string?> PollTokenErrorAsync(string deviceCode, CancellationToken ct)
    {
        var response = await CreateAnonymousClient().PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["client_id"] = ClientId,
                ["device_code"] = deviceCode,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject();
        return json["error"]?.GetValue<string>() ?? "none (token issued)";
    }

    private static Task<HttpResponseMessage> PostVerificationAsync(
        HttpClient browser, string userCode, bool deny, CancellationToken ct)
    {
        var form = new Dictionary<string, string> { ["user_code"] = userCode };
        if (deny)
        {
            form["deny"] = "true";
        }

        return browser.PostAsync("/connect/deviceverification", new FormUrlEncodedContent(form), ct);
    }
}
