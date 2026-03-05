using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Setup;

/// <summary>
/// Integration tests for the SetupApiController endpoints.
/// </summary>
public class SetupApiTests : IntegrationTestBase
{
    public SetupApiTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    #region Status Tests

    [Fact]
    public async Task GetStatus_WhenUsersExist_ReturnsNotFound()
    {
        // Arrange - create a user so setup is no longer needed
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var userName = $"setup_status_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);

        // Act
        var response = await client.GetAsync(SetupApiUrl("status"), ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    #endregion

    #region Create Admin Tests

    [Fact]
    public async Task CreateAdmin_WhenUsersExist_ReturnsNotFound()
    {
        // Arrange - create a user so setup is no longer needed
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var userName = $"setup_create_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);

        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        // Act
        var response = await client.PostAsJsonAsync(SetupApiUrl("create-admin"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task CreateAdmin_WhenPasswordMismatch_ReturnsError()
    {
        // Arrange - ensure no users exist so the setup endpoint is active
        await DeleteAllUsersAsync();
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "DifferentPass!"
        };

        // Act
        var response = await client.PostAsJsonAsync(SetupApiUrl("create-admin"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<SetupResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Passwords do not match");
    }

    #endregion

    #region Helper Methods

    private async Task DeleteAllUsersAsync()
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var users = userManager.Users.ToList();
        foreach (var user in users)
        {
            await userManager.DeleteAsync(user);
        }
    }

    #endregion

    #region URL Helpers

    private static string SetupApiUrl(string endpoint, string tenantId = DefaultTenantId)
    {
        return ApiUrl($"setup/{endpoint}", tenantId);
    }

    #endregion
}
