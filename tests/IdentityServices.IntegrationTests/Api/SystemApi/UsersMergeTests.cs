using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.SystemApi;

/// <summary>
/// Integration tests for the POST system/v1/users/{userName}/merge endpoint.
/// Verifies that external logins can be transferred between users and that
/// the source user is deleted after a successful merge.
/// </summary>
public class UsersMergeTests : IntegrationTestBase
{
    public UsersMergeTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private static string SystemApiUrl(string path) => $"/system/v1/{path.TrimStart('/')}";

    [Fact]
    public async Task MergeUsers_TransfersExternalLoginsAndDeletesSource()
    {
        // Arrange - Create target (local) and source (external) users
        var targetUserName = $"target-{Guid.NewGuid():N}";
        var sourceUserName = $"Google_source-{Guid.NewGuid():N}@example.com";

        var targetUser = await CreateTestUserAsync(targetUserName, email: $"{targetUserName}@example.com");
        var sourceUser = await CreateTestUserAsync(sourceUserName, email: $"source-{Guid.NewGuid():N}@example.com");

        // Add an external login to the source user
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var dbSourceUser = await userManager.FindByNameAsync(sourceUserName);
            dbSourceUser.Should().NotBeNull();

            var loginInfo = new UserLoginInfo("Google", $"google-key-{Guid.NewGuid():N}", "Google");
            await userManager.AddLoginAsync(dbSourceUser!, loginInfo);
            await userManager.UpdateAsync(dbSourceUser!);
        }

        // Act - Merge source into target
        var response = await PostAsync(
            SystemApiUrl($"users/{targetUserName}/merge"),
            new { sourceUserName });

        // Assert - Merge should succeed
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Verify target user now has the external login
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();

            var updatedTarget = await userManager.FindByNameAsync(targetUserName);
            updatedTarget.Should().NotBeNull();

            var logins = await userManager.GetLoginsAsync(updatedTarget!);
            logins.Should().ContainSingle(l => l.LoginProvider == "Google");
        }

        // Verify source user was deleted
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var deletedSource = await userManager.FindByNameAsync(sourceUserName);
            deletedSource.Should().BeNull();
        }
    }

    [Fact]
    public async Task MergeUsers_WithMultipleLogins_TransfersAll()
    {
        // Arrange
        var targetUserName = $"target-multi-{Guid.NewGuid():N}";
        var sourceUserName = $"source-multi-{Guid.NewGuid():N}";

        await CreateTestUserAsync(targetUserName);
        await CreateTestUserAsync(sourceUserName);

        // Add multiple external logins to source
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var dbSourceUser = await userManager.FindByNameAsync(sourceUserName);
            dbSourceUser.Should().NotBeNull();

            await userManager.AddLoginAsync(dbSourceUser!, new UserLoginInfo("Google", "gkey-1", "Google"));
            await userManager.AddLoginAsync(dbSourceUser!, new UserLoginInfo("Microsoft", "mkey-1", "Microsoft"));
            await userManager.UpdateAsync(dbSourceUser!);
        }

        // Act
        var response = await PostAsync(
            SystemApiUrl($"users/{targetUserName}/merge"),
            new { sourceUserName });

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var updatedTarget = await userManager.FindByNameAsync(targetUserName);
            updatedTarget.Should().NotBeNull();

            var logins = await userManager.GetLoginsAsync(updatedTarget!);
            logins.Should().HaveCount(2);
            logins.Should().Contain(l => l.LoginProvider == "Google");
            logins.Should().Contain(l => l.LoginProvider == "Microsoft");
        }
    }

    [Fact]
    public async Task MergeUsers_WithNoLogins_DeletesSourceOnly()
    {
        // Arrange - Source user has no external logins
        var targetUserName = $"target-nologin-{Guid.NewGuid():N}";
        var sourceUserName = $"source-nologin-{Guid.NewGuid():N}";

        await CreateTestUserAsync(targetUserName);
        await CreateTestUserAsync(sourceUserName);

        // Act
        var response = await PostAsync(
            SystemApiUrl($"users/{targetUserName}/merge"),
            new { sourceUserName });

        // Assert - Merge should succeed even with no logins to transfer
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();

        var target = await userManager.FindByNameAsync(targetUserName);
        target.Should().NotBeNull();

        var source = await userManager.FindByNameAsync(sourceUserName);
        source.Should().BeNull("source user should be deleted after merge");
    }

    [Fact]
    public async Task MergeUsers_WithNonExistentTarget_ReturnsNotFound()
    {
        // Arrange
        var sourceUserName = $"source-notfound-{Guid.NewGuid():N}";
        await CreateTestUserAsync(sourceUserName);

        // Act
        var response = await PostAsync(
            SystemApiUrl($"users/nonexistent-target-{Guid.NewGuid():N}/merge"),
            new { sourceUserName });

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task MergeUsers_WithNonExistentSource_ReturnsNotFound()
    {
        // Arrange
        var targetUserName = $"target-nosrc-{Guid.NewGuid():N}";
        await CreateTestUserAsync(targetUserName);

        // Act
        var response = await PostAsync(
            SystemApiUrl($"users/{targetUserName}/merge"),
            new { sourceUserName = $"nonexistent-source-{Guid.NewGuid():N}" });

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task MergeUsers_SameUser_ReturnsBadRequest()
    {
        // Arrange
        var userName = $"self-merge-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);

        // Act
        var response = await PostAsync(
            SystemApiUrl($"users/{userName}/merge"),
            new { sourceUserName = userName });

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task FindByLoginAsync_WorksAfterAddLoginAsync()
    {
        // Minimal test: create user, add login, verify FindByLoginAsync works
        var userName = $"findlogin-test-{Guid.NewGuid():N}";
        var providerKey = $"test-key-{Guid.NewGuid():N}";

        await CreateTestUserAsync(userName);

        // Add external login
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var user = await userManager.FindByNameAsync(userName);
            user.Should().NotBeNull();

            var result = await userManager.AddLoginAsync(user!, new UserLoginInfo("TestProvider", providerKey, "TestProvider"));
            result.Succeeded.Should().BeTrue($"AddLoginAsync should succeed but got: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }

        // Verify FindByLoginAsync works
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();

            // First verify via GetLoginsAsync
            var user = await userManager.FindByNameAsync(userName);
            user.Should().NotBeNull();
            var logins = await userManager.GetLoginsAsync(user!);
            logins.Should().ContainSingle(l => l.LoginProvider == "TestProvider" && l.ProviderKey == providerKey,
                "GetLoginsAsync should find the login");

            // Now verify FindByLoginAsync
            var foundUser = await userManager.FindByLoginAsync("TestProvider", providerKey);
            foundUser.Should().NotBeNull("FindByLoginAsync should find user by login provider and key");
            foundUser!.UserName.Should().Be(userName);
        }
    }

    [Fact]
    public async Task MergeUsers_FindByLoginAsync_FindsTargetAfterMerge()
    {
        // Arrange - This verifies the critical scenario:
        // after merge, logging in with the external provider should find the target user
        var targetUserName = $"target-findlogin-{Guid.NewGuid():N}";
        var sourceUserName = $"source-findlogin-{Guid.NewGuid():N}";
        var providerKey = $"ms-key-{Guid.NewGuid():N}";

        await CreateTestUserAsync(targetUserName, email: $"{targetUserName}@example.com");
        await CreateTestUserAsync(sourceUserName, email: $"{sourceUserName}@example.com");

        // Add external login to source user
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var dbSource = await userManager.FindByNameAsync(sourceUserName);
            dbSource.Should().NotBeNull();

            await userManager.AddLoginAsync(dbSource!, new UserLoginInfo("Microsoft", providerKey, "Microsoft"));
            await userManager.UpdateAsync(dbSource!);
        }

        // Sanity check: FindByLoginAsync should find the source user BEFORE merge
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var preCheck = await userManager.FindByLoginAsync("Microsoft", providerKey);
            preCheck.Should().NotBeNull("FindByLoginAsync should find source user before merge");
            preCheck!.UserName.Should().Be(sourceUserName);
        }

        // Act - Merge source into target
        var response = await PostAsync(
            SystemApiUrl($"users/{targetUserName}/merge"),
            new { sourceUserName });

        // Assert - Merge should succeed
        var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK,
            $"merge should succeed but got {response.StatusCode}: {responseBody}");

        // Verify the login is actually stored on the target user
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();

            // First check: load target user and verify logins via GetLoginsAsync
            var updatedTarget = await userManager.FindByNameAsync(targetUserName);
            updatedTarget.Should().NotBeNull("target user should still exist");

            var targetLogins = await userManager.GetLoginsAsync(updatedTarget!);
            targetLogins.Should().ContainSingle(l =>
                l.LoginProvider == "Microsoft" && l.ProviderKey == providerKey,
                "target user should have the transferred Microsoft login");

            // Critical: FindByLoginAsync must find the target user with the merged login
            // This is the exact code path used during external login callback
            var foundUser = await userManager.FindByLoginAsync("Microsoft", providerKey);
            foundUser.Should().NotBeNull("FindByLoginAsync should find the user after merge");
            foundUser!.UserName.Should().Be(targetUserName,
                "the merged login should be associated with the target user");
        }
    }

    [Fact]
    public async Task MergeUsers_TargetKeepsOwnLogins()
    {
        // Arrange - Target already has its own external login
        var targetUserName = $"target-keeplogin-{Guid.NewGuid():N}";
        var sourceUserName = $"source-keeplogin-{Guid.NewGuid():N}";

        await CreateTestUserAsync(targetUserName);
        await CreateTestUserAsync(sourceUserName);

        // Add login to target
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();

            var dbTarget = await userManager.FindByNameAsync(targetUserName);
            await userManager.AddLoginAsync(dbTarget!, new UserLoginInfo("Facebook", "fb-key", "Facebook"));
            await userManager.UpdateAsync(dbTarget!);

            var dbSource = await userManager.FindByNameAsync(sourceUserName);
            await userManager.AddLoginAsync(dbSource!, new UserLoginInfo("Google", "g-key", "Google"));
            await userManager.UpdateAsync(dbSource!);
        }

        // Act
        var response = await PostAsync(
            SystemApiUrl($"users/{targetUserName}/merge"),
            new { sourceUserName });

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var updatedTarget = await userManager.FindByNameAsync(targetUserName);
            var logins = await userManager.GetLoginsAsync(updatedTarget!);

            logins.Should().HaveCount(2);
            logins.Should().Contain(l => l.LoginProvider == "Facebook", "target should keep its own login");
            logins.Should().Contain(l => l.LoginProvider == "Google", "target should gain source's login");
        }
    }
}
