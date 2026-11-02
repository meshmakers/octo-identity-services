using System.Net;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
/// AB#8083: <c>PUT {tenantId}/v1/users/{userName}</c> refuses renaming a user to a user name another user of the tenant
/// already has, with the same 409 answer as the create (<c>code USER_ALREADY_EXISTS</c>, <c>field userName</c>).
/// </summary>
public class UsersUpdateUserNameTests : IntegrationTestBase
{
    public UsersUpdateUserNameTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RenamingToAUserNameAnotherUserHas_Is409_WithTheCreateCode_AndChangesNothing(bool otherCasing)
    {
        var ct = TestContext.Current.CancellationToken;
        var takenName = $"taken-{Guid.NewGuid():N}";
        await CreateTestUserAsync(takenName);
        var ownName = $"mover-{Guid.NewGuid():N}";
        await CreateTestUserAsync(ownName);

        var update = new { name = otherCasing ? takenName.ToUpperInvariant() : takenName, firstName = "Changed" };
        var response = await PutAsync(TenantApiUrl($"users/{ownName}"), update);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        problem.RootElement.GetProperty("code").GetString().Should().Be("USER_ALREADY_EXISTS");
        problem.RootElement.GetProperty("field").GetString().Should().Be("userName");
        problem.RootElement.GetRawText().Should().NotContain(takenName, "the answer names the field, not the name");

        var stored = await FindByNameAsync(ownName);
        stored.Should().NotBeNull("the user keeps its name");
        stored!.FirstName.Should().NotBe("Changed");
    }

    [Fact]
    public async Task RenamingToAFreeUserName_IsAccepted()
    {
        var ownName = $"rename-{Guid.NewGuid():N}";
        await CreateTestUserAsync(ownName);
        var freeName = $"renamed-{Guid.NewGuid():N}";

        (await PutAsync(TenantApiUrl($"users/{ownName}"), new { name = freeName })).StatusCode.Should()
            .Be(HttpStatusCode.OK);

        (await FindByNameAsync(freeName)).Should().NotBeNull();
        (await FindByNameAsync(ownName)).Should().BeNull();
    }

    [Fact]
    public async Task KeepingTheOwnUserName_IsNotAConflict()
    {
        var ownName = $"keep-{Guid.NewGuid():N}";
        await CreateTestUserAsync(ownName);

        (await PutAsync(TenantApiUrl($"users/{ownName}"), new { name = ownName, firstName = "Same" })).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await FindByNameAsync(ownName))!.FirstName.Should().Be("Same");
    }

    private async Task<RtUser?> FindByNameAsync(string userName)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
    }
}
