using System.Net;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
/// Integration tests for the POST {tenantId}/v1/users endpoint (user creation).
/// AB#4503: an invalid password must NOT persist a user; a valid password still creates one.
/// </summary>
public class UsersCreateTests : IntegrationTestBase
{
    public UsersCreateTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task CreateUser_WithPasswordFailingPolicy_PersistsNoUser()
    {
        // Arrange - "test" violates the default policy (too short, no digit, no uppercase, no special char)
        var userName = $"weakpw-{Guid.NewGuid():N}";
        var email = $"{userName}@example.com";
        var body = new { name = userName, email, password = "test" };

        // Act
        var response = await PostAsync(TenantApiUrl("users"), body);

        // Assert - the request is rejected
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // Assert - the rejection is the Identity password policy, not model binding / DTO
        // validation (whose 400 would not carry the "Password*" error codes). This guards
        // against the test passing for the wrong reason if request validation ever changes.
        var payload = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        payload.Should().Contain("Password");

        // Assert - and, crucially, NO user was persisted (this assertion FAILS before the fix)
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var persisted = await userManager.FindByNameAsync(userName);
        persisted.Should().BeNull();
    }

    [Fact]
    public async Task CreateUser_WithValidPassword_CreatesUser()
    {
        // Arrange
        var userName = $"validpw-{Guid.NewGuid():N}";
        var email = $"{userName}@example.com";
        var body = new { name = userName, email, password = DefaultPassword };

        // Act
        var response = await PostAsync(TenantApiUrl("users"), body);

        // Assert - the request succeeds (guards against a 500-after-persist regression)
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        // Assert - user exists afterwards (regression guard for the happy path)
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var persisted = await userManager.FindByNameAsync(userName);
        persisted.Should().NotBeNull();
    }
}
