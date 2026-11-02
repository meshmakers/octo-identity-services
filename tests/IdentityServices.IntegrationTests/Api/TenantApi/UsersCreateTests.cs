using System.Net;
using System.Text.Json;
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
/// AB#8064: an e-mail address another user of the tenant already has is refused with 409 (code USER_ALREADY_EXISTS), like
/// the CK method User.CreateUser-1; tenants that already hold duplicates keep working. The update path (AB#8084) is covered by
/// UsersUpdateEmailTests.
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

    [Fact]
    public async Task CreateUser_WithReservedCrossTenantPrefix_IsRejected()
    {
        // AB#5708: xt_ names are trusted to unwind to another tenant's identity (roles, allowed
        // tenants, token exchange) — only cross-tenant provisioning may create them.
        var userName = $"xt_octosystem_{Guid.NewGuid():N}";
        var body = new { name = userName, email = $"{Guid.NewGuid():N}@example.com", password = DefaultPassword };

        var response = await PostAsync(TenantApiUrl("users"), body);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        (await userManager.FindByNameAsync(userName)).Should().BeNull();
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CreateUser_WithAnEmailAnotherUserHas_Is409_WithTheMethodCode_AndCreatesNothing(bool otherCasing)
    {
        var ct = TestContext.Current.CancellationToken;
        var existingName = $"dupmail-{Guid.NewGuid():N}";
        var existingEmail = $"{existingName}@example.com";
        await CreateTestUserAsync(existingName, email: existingEmail);
        var userName = $"dupmail-new-{Guid.NewGuid():N}";
        var body = new
        {
            name = userName,
            email = otherCasing ? existingEmail.ToUpperInvariant() : existingEmail,
            password = DefaultPassword
        };

        var response = await PostAsync(TenantApiUrl("users"), body);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        problem.RootElement.GetProperty("code").GetString().Should().Be("USER_ALREADY_EXISTS");
        problem.RootElement.GetProperty("field").GetString().Should().Be("email");
        problem.RootElement.GetProperty("title").GetString().Should().NotBeNullOrWhiteSpace();
        problem.RootElement.GetRawText().Should().NotContain(existingEmail, "the answer names the field, not the address");
        (await FindByNameAsync(userName)).Should().BeNull("nothing is stored");
    }

    [Fact]
    public async Task CreateUser_WithADuplicateUserName_KeepsThe400Answer()
    {
        var userName = $"dupname-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);
        var body = new { name = userName, email = $"other-{Guid.NewGuid():N}@example.com", password = DefaultPassword };

        var response = await PostAsync(TenantApiUrl("users"), body);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should()
            .Contain("DuplicateUserName");
    }

    [Fact]
    public async Task CreateUser_TheSameUserTwice_KeepsTheDuplicateUserName400()
    {
        // Name and e-mail both taken: the user name decides, as before the e-mail rule.
        var userName = $"twice-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);
        var body = new { name = userName, email = $"{userName}@example.com", password = DefaultPassword };

        var response = await PostAsync(TenantApiUrl("users"), body);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should()
            .Contain("DuplicateUserName");
    }

    [Fact]
    public async Task CreateUser_WithoutAnEmail_IsNotCheckedForDuplicates()
    {
        var first = $"nomail-{Guid.NewGuid():N}";
        var second = $"nomail-{Guid.NewGuid():N}";

        (await PostAsync(TenantApiUrl("users"), new { name = first, password = DefaultPassword })).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await PostAsync(TenantApiUrl("users"), new { name = second, password = DefaultPassword })).StatusCode.Should()
            .Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ExistingUsersWithTheSameEmail_CanStillBeUpdated_AndSignIn()
    {
        // Tenants created before the rule may hold several users with one e-mail address; only creation is checked
        // (RequireUniqueEmail stays off), so updates and sign-in of those users are unchanged.
        var ct = TestContext.Current.CancellationToken;
        var shared = $"shared-{Guid.NewGuid():N}@example.com";
        var first = await CreateTestUserAsync($"legacy-a-{Guid.NewGuid():N}", email: shared);
        var second = await CreateTestUserAsync($"legacy-b-{Guid.NewGuid():N}", email: shared);

        var update = new { name = second.UserName, email = shared, firstName = "Renamed", lastName = "User" };
        (await PutAsync(TenantApiUrl($"users/{second.UserName}"), update)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await FindByNameAsync(second.UserName!))!.FirstName.Should().Be("Renamed");
        (await LoginAndGetAuthenticatedClientAsync(first.UserName!, DefaultPassword, ct)).Should().NotBeNull();
        (await LoginAndGetAuthenticatedClientAsync(second.UserName!, DefaultPassword, ct)).Should().NotBeNull();
    }

    private async Task<RtUser?> FindByNameAsync(string userName)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
    }
}
