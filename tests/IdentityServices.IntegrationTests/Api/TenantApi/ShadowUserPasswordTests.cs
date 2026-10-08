using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#5708: cross-tenant shadow users (<c>xt_</c>) sign in through their home tenant and never get a
///     local password — neither through the admin reset, the e-mail reset nor any other
///     <see cref="UserManager{TUser}" /> path (<see cref="ShadowUserPasswordValidator" /> is registered in
///     the real host's Identity pipeline).
/// </summary>
public class ShadowUserPasswordTests : IntegrationTestBase
{
    private const string NewPassword = "Str0ng!Passw0rd";

    public ShadowUserPasswordTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task AdminResetPassword_OfShadowUser_Returns400WithClearMessage()
    {
        var shadowUserName = await CreateShadowUserAsync();

        var response = await PostAsync(
            TenantApiUrl($"users/ResetPassword?userName={Uri.EscapeDataString(shadowUserName)}&password={Uri.EscapeDataString(NewPassword)}"),
            new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))
            .Should().Contain(ShadowUserPasswordValidator.ErrorMessage);
        (await HasPasswordAsync(shadowUserName)).Should().BeFalse();
    }

    [Fact]
    public async Task EmailResetPassword_OfShadowUser_IsRefused()
    {
        var shadowUserName = await CreateShadowUserAsync();
        var email = $"{shadowUserName}@example.com";
        string token;
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            token = await userManager.GeneratePasswordResetTokenAsync((await userManager.FindByNameAsync(shadowUserName))!);
        }

        var response = await CreateAnonymousClient().PostAsJsonAsync(AuthApiUrl("reset-password"),
            new ResetPasswordRequestDto
            {
                Email = email,
                Token = token,
                NewPassword = NewPassword,
                ConfirmPassword = NewPassword
            }, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<ResetPasswordResultDto>(TestContext.Current.CancellationToken);
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be(ShadowUserPasswordValidator.ErrorMessage);
        (await HasPasswordAsync(shadowUserName)).Should().BeFalse();
    }

    [Fact]
    public async Task AddPassword_OfShadowUser_FailsInTheIdentityPipeline()
    {
        // The self-service set-password and change-password endpoints end in these UserManager calls.
        var shadowUserName = await CreateShadowUserAsync();

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var user = (await userManager.FindByNameAsync(shadowUserName))!;

        var result = await userManager.AddPasswordAsync(user, NewPassword);

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Code == ShadowUserPasswordValidator.ErrorCode);
        (await userManager.HasPasswordAsync((await userManager.FindByNameAsync(shadowUserName))!)).Should().BeFalse();
    }

    [Fact]
    public async Task CreateShadowUserWithPassword_FailsAndPersistsNothing()
    {
        var shadowUserName = $"xt_{NormalizedSystemTenantId}_{Guid.NewGuid():N}";

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var result = await userManager.CreateAsync(
            new RtUserBuilder().WithUserName(shadowUserName).WithEmail($"{shadowUserName}@example.com").Build(),
            NewPassword);

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Code == ShadowUserPasswordValidator.ErrorCode);
        (await userManager.FindByNameAsync(shadowUserName)).Should().BeNull();
    }

    [Fact]
    public async Task AddPassword_OfLocalUser_StillWorks()
    {
        var userName = $"local-{Guid.NewGuid():N}";
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        (await userManager.CreateAsync(
            new RtUserBuilder().WithUserName(userName).WithEmail($"{userName}@example.com").Build())).Succeeded
            .Should().BeTrue();

        var result = await userManager.AddPasswordAsync((await userManager.FindByNameAsync(userName))!, NewPassword);

        result.Succeeded.Should().BeTrue();
    }

    /// <summary>Creates a password-less shadow user the way the cross-tenant provisioning does.</summary>
    private async Task<string> CreateShadowUserAsync()
    {
        var shadowUserName = $"xt_{NormalizedSystemTenantId}_{Guid.NewGuid():N}";
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var result = await userManager.CreateAsync(new RtUserBuilder()
            .WithUserName(shadowUserName)
            .WithEmail($"{shadowUserName}@example.com")
            .WithEmailConfirmed()
            .Build());
        result.Succeeded.Should().BeTrue();
        return shadowUserName;
    }

    private async Task<bool> HasPasswordAsync(string userName)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        return await userManager.HasPasswordAsync((await userManager.FindByNameAsync(userName))!);
    }
}
