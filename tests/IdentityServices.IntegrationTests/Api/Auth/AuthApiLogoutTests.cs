using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
/// Integration tests for the AuthApiController logout endpoints.
/// Tests the Single Logout (SLO) functionality including token revocation.
/// </summary>
public class AuthApiLogoutTests : IntegrationTestBase
{
    public AuthApiLogoutTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    #region Logout Context Tests

    [Fact]
    public async Task GetLogoutContext_WithoutLogoutId_ReturnsDefaultContext()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.GetAsync(AuthApiUrl("logout-context"), ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var context = await response.Content.ReadFromJsonAsync<LogoutContextDto>(ct);
        context.Should().NotBeNull();
        context!.LogoutId.Should().BeEmpty();
        context.ShowLogoutPrompt.Should().BeTrue();
    }

    [Fact]
    public async Task GetLogoutContext_WithLogoutId_ReturnsContext()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var logoutId = "test-logout-id";
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.GetAsync($"{AuthApiUrl("logout-context")}?logoutId={logoutId}", ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var context = await response.Content.ReadFromJsonAsync<LogoutContextDto>(ct);
        context.Should().NotBeNull();
        // Context may or may not have additional info depending on the logout ID validity
    }

    #endregion

    #region Logout Tests

    [Fact]
    public async Task Logout_WithAuthenticatedUser_ReturnsSuccess()
    {
        // Arrange
        var ct = TestContext.Current.CancellationToken;
        var request = new LogoutRequestDto { LogoutId = "" };

        // Act
        var response = await Client.PostAsJsonAsync(AuthApiUrl("logout"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LogoutResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
        result.AutomaticRedirectAfterSignOut.Should().BeTrue();
    }

    [Fact]
    public async Task Logout_WithUnauthenticatedUser_ReturnsSuccess()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var request = new LogoutRequestDto { LogoutId = "" };

        // Act
        var response = await client.PostAsJsonAsync(AuthApiUrl("logout"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LogoutResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
    }

    [Fact]
    public async Task Logout_RevokesRefreshTokens()
    {
        // Arrange
        var ct = TestContext.Current.CancellationToken;
        var userName = $"logout_revoke_{Guid.NewGuid():N}";
        var password = "Test123!";

        // Create a test user and get their ID (which will be the subjectId for grants)
        var user = await CreateTestUserAsync(userName, password: password);
        var subjectId = user.RtId.ToString();

        // Create multiple refresh tokens for the user
        await CreatePersistedGrantAsync(subjectId, "test-client");
        await CreatePersistedGrantAsync(subjectId, "test-client");
        await CreatePersistedGrantAsync(subjectId, "another-client");

        // Verify grants exist
        var initialCount = await GetGrantCountForSubjectAsync(subjectId);
        initialCount.Should().Be(3);

        // Login to get an authenticated session with cookies
        var client = await LoginAndGetAuthenticatedClientAsync(userName, password, ct);
        client.Should().NotBeNull("Login should succeed");

        var request = new LogoutRequestDto { LogoutId = "" };

        // Act
        var response = await client!.PostAsJsonAsync(AuthApiUrl("logout"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LogoutResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();

        // Verify all grants were revoked
        var finalCount = await GetGrantCountForSubjectAsync(subjectId);
        finalCount.Should().Be(0);
    }

    [Fact]
    public async Task Logout_WithNoRefreshTokens_CompletesSuccessfully()
    {
        // Arrange
        var subjectId = $"no-tokens-{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Verify no grants exist
        var initialCount = await GetGrantCountForSubjectAsync(subjectId);
        initialCount.Should().Be(0);

        var client = CreateAuthenticatedClient(userId: subjectId);
        var request = new LogoutRequestDto { LogoutId = "" };

        // Act
        var response = await client.PostAsJsonAsync(AuthApiUrl("logout"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LogoutResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
    }

    [Fact]
    public async Task Logout_WithMultipleClientsGrants_RevokesAllGrants()
    {
        // Arrange
        var ct = TestContext.Current.CancellationToken;
        var userName = $"logout_multi_{Guid.NewGuid():N}";
        var password = "Test123!";

        // Create a test user and get their ID
        var user = await CreateTestUserAsync(userName, password: password);
        var subjectId = user.RtId.ToString();

        // Create grants for multiple clients
        await CreatePersistedGrantAsync(subjectId, "client-1");
        await CreatePersistedGrantAsync(subjectId, "client-2");
        await CreatePersistedGrantAsync(subjectId, "client-3");

        var initialCount = await GetGrantCountForSubjectAsync(subjectId);
        initialCount.Should().Be(3);

        // Login to get an authenticated session
        var client = await LoginAndGetAuthenticatedClientAsync(userName, password, ct);
        client.Should().NotBeNull("Login should succeed");

        var request = new LogoutRequestDto { LogoutId = "" };

        // Act
        var response = await client!.PostAsJsonAsync(AuthApiUrl("logout"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LogoutResultDto>(ct);
        result!.Success.Should().BeTrue();

        // All grants from all clients should be revoked
        var finalCount = await GetGrantCountForSubjectAsync(subjectId);
        finalCount.Should().Be(0);
    }

    [Fact]
    public async Task Logout_DoesNotAffectOtherUsersGrants()
    {
        // Arrange
        var ct = TestContext.Current.CancellationToken;
        var userName1 = $"logout_user1_{Guid.NewGuid():N}";
        var userName2 = $"logout_user2_{Guid.NewGuid():N}";
        var password = "Test123!";

        // Create two test users
        var user1 = await CreateTestUserAsync(userName1, password: password);
        var user2 = await CreateTestUserAsync(userName2, password: password);
        var subjectId1 = user1.RtId.ToString();
        var subjectId2 = user2.RtId.ToString();

        // Create grants for two different users
        await CreatePersistedGrantAsync(subjectId1, "test-client");
        await CreatePersistedGrantAsync(subjectId2, "test-client");

        // Login as user1
        var client = await LoginAndGetAuthenticatedClientAsync(userName1, password, ct);
        client.Should().NotBeNull("Login should succeed");

        var request = new LogoutRequestDto { LogoutId = "" };

        // Act
        var response = await client!.PostAsJsonAsync(AuthApiUrl("logout"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // User1's grants should be revoked
        var user1Count = await GetGrantCountForSubjectAsync(subjectId1);
        user1Count.Should().Be(0);

        // User2's grants should still exist
        var user2Count = await GetGrantCountForSubjectAsync(subjectId2);
        user2Count.Should().Be(1);

        // Cleanup
        await DeleteAllGrantsForSubjectAsync(subjectId2);
    }

    #endregion
}
