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
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Manage;

/// <summary>
///     AB#7765 (review finding M3): every REST password path — change-password, set-password, admin
///     ResetPassword and the token reset-password — ends the sessions issued before the change. The old
///     refresh token is redeemed against the real token endpoint, so the test pins the observable
///     behaviour (<c>invalid_grant</c>), not just a status flag in the store.
/// </summary>
public class PasswordChangeRevokesSessionsTests : IntegrationTestBase
{
    private const string OldPassword = "Test123!";
    private const string NewPassword = "Str0ng!Passw0rd";
    private const string RedirectUri = "https://m3.example/callback";

    public PasswordChangeRevokesSessionsTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task ChangePassword_RevokesRefreshToken_NewSignInWorks_StampChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var stampBefore = await GetSecurityStampAsync(userName);
        var refreshToken = await IssueRefreshTokenAsync(userName, OldPassword, ct);

        var client = await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct);
        client.Should().NotBeNull();
        var response = await client!.PostAsJsonAsync(ManageApiUrl("change-password"), new ChangePasswordRequestDto
        {
            CurrentPassword = OldPassword, NewPassword = NewPassword, ConfirmPassword = NewPassword
        }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!.Success.Should().BeTrue();
        await AssertRefreshTokenRejectedAsync(refreshToken, ct);
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().NotBeNull();
        (await GetSecurityStampAsync(userName)).Should().NotBe(stampBefore);
    }

    [Fact]
    public async Task ChangePassword_DoesNotRevokeOtherUsersRefreshTokens()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var otherName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        await CreateTestUserAsync(otherName, password: OldPassword);
        var otherRefreshToken = await IssueRefreshTokenAsync(otherName, OldPassword, ct);

        var client = await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct);
        var response = await client!.PostAsJsonAsync(ManageApiUrl("change-password"), new ChangePasswordRequestDto
        {
            CurrentPassword = OldPassword, NewPassword = NewPassword, ConfirmPassword = NewPassword
        }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var redeemed = await RedeemRefreshTokenAsync(otherRefreshToken, ct);
        redeemed.StatusCode.Should().Be(HttpStatusCode.OK, "another user's session is untouched");
    }

    [Fact]
    public async Task SetPassword_RevokesRefreshToken()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var refreshToken = await IssueRefreshTokenAsync(userName, OldPassword, ct);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct);
        client.Should().NotBeNull();

        // Turn the user into one that only has external logins: no local password.
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var user = (await userManager.FindByNameAsync(userName))!;
            (await userManager.RemovePasswordAsync(user)).Succeeded.Should().BeTrue();
        }

        var response = await client!.PostAsJsonAsync(ManageApiUrl("set-password"), new SetPasswordRequestDto
        {
            NewPassword = NewPassword, ConfirmPassword = NewPassword
        }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!.Success.Should().BeTrue();
        await AssertRefreshTokenRejectedAsync(refreshToken, ct);
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().NotBeNull();
    }

    [Fact]
    public async Task AdminResetPassword_RevokesRefreshToken_NewSignInWorks_StampChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var stampBefore = await GetSecurityStampAsync(userName);
        var refreshToken = await IssueRefreshTokenAsync(userName, OldPassword, ct);

        var response = await PostAsync(
            TenantApiUrl($"users/ResetPassword?userName={Uri.EscapeDataString(userName)}&password={Uri.EscapeDataString(NewPassword)}"),
            new { });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        await AssertRefreshTokenRejectedAsync(refreshToken, ct);
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().NotBeNull();
        (await GetSecurityStampAsync(userName)).Should().NotBe(stampBefore);
    }

    [Fact]
    public async Task TokenResetPassword_RevokesRefreshToken_NewSignInWorks_StampChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var email = $"{userName}@example.com";
        await CreateTestUserAsync(userName, email: email, password: OldPassword);
        var stampBefore = await GetSecurityStampAsync(userName);
        var refreshToken = await IssueRefreshTokenAsync(userName, OldPassword, ct);

        string resetToken;
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            resetToken = await userManager.GeneratePasswordResetTokenAsync((await userManager.FindByNameAsync(userName))!);
        }

        var response = await CreateAnonymousClient().PostAsJsonAsync(AuthApiUrl("reset-password"),
            new ResetPasswordRequestDto
            {
                Email = email, Token = resetToken, NewPassword = NewPassword, ConfirmPassword = NewPassword
            }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadFromJsonAsync<ResetPasswordResultDto>(ct))!.Success.Should().BeTrue();
        await AssertRefreshTokenRejectedAsync(refreshToken, ct);
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().NotBeNull();
        (await GetSecurityStampAsync(userName)).Should().NotBe(stampBefore);
    }

    #region Helpers

    private static string NewUserName() => $"m3_{Guid.NewGuid():N}";

    private async Task<string?> GetSecurityStampAsync(string userName)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        return (await userManager.FindByNameAsync(userName))!.SecurityStamp;
    }

    private async Task AssertRefreshTokenRejectedAsync(string refreshToken, CancellationToken ct)
    {
        var response = await RedeemRefreshTokenAsync(refreshToken, ct);
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!.AsObject();
        body["error"]!.GetValue<string>().Should().Be("invalid_grant");
    }

    private async Task<HttpResponseMessage> RedeemRefreshTokenAsync(string refreshToken, CancellationToken ct)
    {
        return await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = ClientId,
                ["refresh_token"] = refreshToken,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
    }

    private const string ClientId = "m3-spa";

    /// <summary>Signs the user in through the real authorization-code + PKCE flow and returns the refresh token.</summary>
    private async Task<string> IssueRefreshTokenAsync(string userName, string password, CancellationToken ct)
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

        var browser = await LoginAndGetAuthenticatedClientAsync(userName, password, ct);
        browser.Should().NotBeNull("cookie login must succeed to drive the authorize flow");

        const string codeVerifier = "m3-code-verifier-m3-code-verifier-1234567890";
        var codeChallenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var authorizeUrl = "/connect/authorize" +
                           $"?client_id={ClientId}" +
                           $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                           "&response_type=code" +
                           $"&scope={Uri.EscapeDataString("openid profile offline_access")}" +
                           "&state=m3-state&nonce=m3-nonce" +
                           $"&code_challenge={codeChallenge}&code_challenge_method=S256" +
                           $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}";
        var authorizeResponse = await browser!.GetAsync(authorizeUrl, ct);
        ((int)authorizeResponse.StatusCode).Should().BeInRange(302, 303);
        var code = HttpUtility.ParseQueryString(authorizeResponse.Headers.Location!.Query)["code"];
        code.Should().NotBeNullOrEmpty();

        var tokenResponse = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = ClientId,
                ["code"] = code!,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = codeVerifier
            }), ct);
        var raw = await tokenResponse.Content.ReadAsStringAsync(ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK, "code redemption failed: {0}", raw);
        return JsonNode.Parse(raw)!["refresh_token"]!.GetValue<string>();
    }

    #endregion
}
