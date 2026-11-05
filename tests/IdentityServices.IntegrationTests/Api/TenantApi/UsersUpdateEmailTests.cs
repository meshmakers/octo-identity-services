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
/// AB#8084: <c>PUT {tenantId}/v1/users/{userName}</c> refuses changing the e-mail address to one another user of the tenant
/// already has, with the same 409 answer as the create (AB#8064: <c>code USER_ALREADY_EXISTS</c>, <c>field email</c>). Only a
/// change of the address is checked, so users of tenants that already hold duplicates stay editable while they keep it.
/// </summary>
public class UsersUpdateEmailTests : IntegrationTestBase
{
    public UsersUpdateEmailTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ChangingTheEmail_ToOneAnotherUserHas_Is409_WithTheCreateCode_AndChangesNothing(bool otherCasing)
    {
        var ct = TestContext.Current.CancellationToken;
        var taken = $"taken-{Guid.NewGuid():N}@example.com";
        await CreateTestUserAsync($"owner-{Guid.NewGuid():N}", email: taken);
        var ownEmail = $"own-{Guid.NewGuid():N}@example.com";
        var user = await CreateTestUserAsync($"mover-{Guid.NewGuid():N}", email: ownEmail);

        var update = new
        {
            name = user.UserName,
            email = otherCasing ? taken.ToUpperInvariant() : taken,
            firstName = "Changed",
            lastName = "Name"
        };
        var response = await PutAsync(TenantApiUrl($"users/{user.UserName}"), update);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        problem.RootElement.GetProperty("code").GetString().Should().Be("USER_ALREADY_EXISTS");
        problem.RootElement.GetProperty("field").GetString().Should().Be("email");
        problem.RootElement.GetRawText().Should().NotContain(taken, "the answer names the field, not the address");

        var stored = await FindByNameAsync(user.UserName!);
        stored!.Email.Should().Be(ownEmail, "nothing is written");
        stored.FirstName.Should().NotBe("Changed");
    }

    [Fact]
    public async Task AUserWithoutAnEmail_CannotTakeTheAddressOfAnotherUser()
    {
        var taken = $"taken-{Guid.NewGuid():N}@example.com";
        await CreateTestUserAsync($"owner-{Guid.NewGuid():N}", email: taken);
        var user = await CreateTestUserAsync($"nomail-{Guid.NewGuid():N}");
        (await PutAsync(TenantApiUrl($"users/{user.UserName}"), new { name = user.UserName })).StatusCode
            .Should().Be(HttpStatusCode.OK, "the address is cleared first");

        var response = await PutAsync(TenantApiUrl($"users/{user.UserName}"), new { name = user.UserName, email = taken });

        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await FindByNameAsync(user.UserName!))!.Email.Should().BeNull();
    }

    [Fact]
    public async Task ChangingTheEmail_ToAFreeAddress_IsAccepted()
    {
        var user = await CreateTestUserAsync($"free-{Guid.NewGuid():N}", email: $"old-{Guid.NewGuid():N}@example.com");
        var free = $"free-{Guid.NewGuid():N}@example.com";

        (await PutAsync(TenantApiUrl($"users/{user.UserName}"), new { name = user.UserName, email = free })).StatusCode
            .Should().Be(HttpStatusCode.OK);

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        (await userManager.FindByEmailAsync(free))!.RtId.Should().Be(user.RtId, "the normalised address follows the change");
    }

    [Fact]
    public async Task ClearingTheEmail_IsNotChecked()
    {
        var user = await CreateTestUserAsync($"clear-{Guid.NewGuid():N}", email: $"clear-{Guid.NewGuid():N}@example.com");

        (await PutAsync(TenantApiUrl($"users/{user.UserName}"), new { name = user.UserName })).StatusCode
            .Should().Be(HttpStatusCode.OK);

        (await FindByNameAsync(user.UserName!))!.Email.Should().BeNull();
    }

    [Fact]
    public async Task UsersThatAlreadyShareAnAddress_StayEditable_AlsoWithAnotherCasing()
    {
        // Tenants from before the rule may hold several users with one address. Keeping it (also in another casing) is no
        // new conflict and stays allowed; only moving to an address someone else has is refused.
        var shared = $"shared-{Guid.NewGuid():N}@example.com";
        var first = await CreateTestUserAsync($"legacy-a-{Guid.NewGuid():N}", email: shared);
        await CreateTestUserAsync($"legacy-b-{Guid.NewGuid():N}", email: shared);

        (await PutAsync(TenantApiUrl($"users/{first.UserName}"),
                new { name = first.UserName, email = shared, firstName = "Edited", lastName = "User" })).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await PutAsync(TenantApiUrl($"users/{first.UserName}"),
                new { name = first.UserName, email = shared.ToUpperInvariant(), firstName = "Edited", lastName = "Again" }))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var stored = await FindByNameAsync(first.UserName!);
        stored!.LastName.Should().Be("Again");
        stored.Email.Should().Be(shared.ToUpperInvariant());
    }

    [Fact]
    public async Task AUserThatSharesAnAddress_CannotMoveToAnotherTakenAddress()
    {
        var shared = $"shared-{Guid.NewGuid():N}@example.com";
        var user = await CreateTestUserAsync($"legacy-a-{Guid.NewGuid():N}", email: shared);
        await CreateTestUserAsync($"legacy-b-{Guid.NewGuid():N}", email: shared);
        var taken = $"taken-{Guid.NewGuid():N}@example.com";
        await CreateTestUserAsync($"owner-{Guid.NewGuid():N}", email: taken);

        (await PutAsync(TenantApiUrl($"users/{user.UserName}"), new { name = user.UserName, email = taken })).StatusCode
            .Should().Be(HttpStatusCode.Conflict);
    }

    private async Task<RtUser?> FindByNameAsync(string userName)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
    }
}
