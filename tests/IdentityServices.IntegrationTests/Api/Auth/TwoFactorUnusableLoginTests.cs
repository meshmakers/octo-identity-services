using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Helpers;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
/// AB#7830: a user whose second factor is enabled but who has no authenticator key (as after a tenant clone,
/// which does not export UserTokens) never gets a session with the password alone.
/// </summary>
public class TwoFactorUnusableLoginTests : IntegrationTestBase
{
    public TwoFactorUnusableLoginTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Login_TwoFactorEnabledWithoutAuthenticator_IsRefusedWithoutSession(bool emailConfirmed)
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"2fa_unusable_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword, emailConfirmed: emailConfirmed,
            twoFactorEnabled: true);

        var client = CreateCookieClient();
        var response = await client.PostAsJsonAsync(AuthApiUrl("login"),
            new LoginRequestDto { Username = userName, Password = TestUsers.DefaultPassword }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LoginResultDto>(ct);
        result!.Success.Should().BeFalse();
        result.SecondFactorSetupRequired.Should().BeTrue();
        result.RequiresTwoFactor.Should().BeFalse();
        result.RedirectUrl.Should().BeNull();
        result.ErrorMessage.Should().Contain("second factor must be set up again");
        response.Headers.Contains("Set-Cookie").Should().BeFalse("no authentication cookie may be issued");

        // The cookie client holds no session: an authenticated endpoint refuses it.
        var profile = await client.GetAsync(ManageApiUrl("profile"), ct);
        profile.StatusCode.Should().NotBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Login_TwoFactorEnabledWithoutAuthenticator_WrongPassword_IsPlainFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"2fa_unusable_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword, twoFactorEnabled: true);

        var response = await CreateCookieClient().PostAsJsonAsync(AuthApiUrl("login"),
            new LoginRequestDto { Username = userName, Password = "Wrong-Password-1!" }, ct);

        var result = await response.Content.ReadFromJsonAsync<LoginResultDto>(ct);
        result!.Success.Should().BeFalse();
        result.SecondFactorSetupRequired.Should().BeFalse("the refusal message must not confirm a password");
        response.Headers.Contains("Set-Cookie").Should().BeFalse();
    }

    [Fact]
    public async Task Login_AfterAdminSwitchesTwoFactorOff_SignsIn()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"2fa_unusable_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword, twoFactorEnabled: true);

        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var user = await userManager.FindByNameAsync(userName);
            (await userManager.SetTwoFactorEnabledAsync(user!, false)).Succeeded.Should().BeTrue();
        }

        var response = await CreateCookieClient().PostAsJsonAsync(AuthApiUrl("login"),
            new LoginRequestDto { Username = userName, Password = TestUsers.DefaultPassword }, ct);

        var result = await response.Content.ReadFromJsonAsync<LoginResultDto>(ct);
        result!.Success.Should().BeTrue();
        result.SecondFactorSetupRequired.Should().BeFalse();
    }
}
