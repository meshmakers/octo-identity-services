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
/// AB#5859: <c>GET {tenant}/v1/users/directory</c> — the slim user directory for pickers. Every signed-in
/// user of the tenant may read it without a role; it returns only id and display name, and only for a
/// token issued for the route tenant.
/// </summary>
public class UserDirectoryTests : IntegrationTestBase
{
    public UserDirectoryTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private HttpClient PlainUser()
    {
        var client = CreateAuthenticatedClient(userId: $"plain-{Guid.NewGuid():N}");
        client.DefaultRequestHeaders.Add(TestAuthHandler.NoRolesHeader, "true");
        return client;
    }

    private async Task<RtUser> CreateNamedUserAsync(string userName, string? firstName, string? lastName)
    {
        await CreateTestUserAsync(userName, email: $"{userName}@secret.example");
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var user = await userManager.FindByNameAsync(userName);
        user.Should().NotBeNull();
        user!.FirstName = firstName;
        user.LastName = lastName;
        (await userManager.UpdateAsync(user)).Succeeded.Should().BeTrue();
        return user;
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private static string Url(string query) => $"users/directory?{query}";

    [Fact]
    public async Task PlainUser_WithoutRole_GetsIdAndDisplayNameOnly()
    {
        var marker = $"Dir{Guid.NewGuid():N}"[..20];
        var user = await CreateNamedUserAsync($"dir-{Guid.NewGuid():N}", "Anna", marker);

        var response = await PlainUser().GetAsync(TenantApiUrl(Url($"search={marker}")),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await ReadJsonAsync(response);
        var list = body.GetProperty("list").EnumerateArray().ToList();
        list.Should().ContainSingle();
        var entry = list[0];
        entry.GetProperty("userId").GetString().Should().Be(user.RtId.ToString());
        entry.GetProperty("displayName").GetString().Should().Be($"Anna {marker}");
        entry.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo("userId", "displayName");
        body.GetRawText().Should().NotContain("@secret.example");
    }

    [Fact]
    public async Task DisplayName_FallsBackToUserName()
    {
        var userName = $"noname-{Guid.NewGuid():N}";
        await CreateNamedUserAsync(userName, null, null);

        var response = await PlainUser().GetAsync(TenantApiUrl(Url($"search={userName}")),
            TestContext.Current.CancellationToken);

        var list = (await ReadJsonAsync(response)).GetProperty("list").EnumerateArray().ToList();
        list.Should().ContainSingle().Which.GetProperty("displayName").GetString().Should().Be(userName);
    }

    [Fact]
    public async Task Search_MatchesTheDisplayNameOnly_NotTheHiddenUserNameOrEmail()
    {
        var hiddenUserName = $"hidden-{Guid.NewGuid():N}";
        await CreateNamedUserAsync(hiddenUserName, "Bert", $"Visible{Guid.NewGuid():N}"[..20]);

        var byUserName = await PlainUser().GetAsync(TenantApiUrl(Url($"search={hiddenUserName}")),
            TestContext.Current.CancellationToken);
        var byEmail = await PlainUser().GetAsync(TenantApiUrl(Url($"search={hiddenUserName}@secret")),
            TestContext.Current.CancellationToken);

        (await ReadJsonAsync(byUserName)).GetProperty("list").GetArrayLength().Should().Be(0);
        (await ReadJsonAsync(byEmail)).GetProperty("list").GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task Paging_IsStable_AndReportsTheTotal()
    {
        var marker = $"Page{Guid.NewGuid():N}"[..20];
        await CreateNamedUserAsync($"p1-{Guid.NewGuid():N}", "Carl", marker);
        await CreateNamedUserAsync($"p2-{Guid.NewGuid():N}", "Anton", marker);
        await CreateNamedUserAsync($"p3-{Guid.NewGuid():N}", "Berta", marker);

        var client = PlainUser();
        var first = await client.GetAsync(TenantApiUrl(Url($"search={marker}&skip=0&take=2")),
            TestContext.Current.CancellationToken);
        var second = await client.GetAsync(TenantApiUrl(Url($"search={marker}&skip=2&take=2")),
            TestContext.Current.CancellationToken);

        var firstBody = await ReadJsonAsync(first);
        firstBody.GetProperty("totalCount").GetInt64().Should().Be(3);
        firstBody.GetProperty("list").EnumerateArray().Select(e => e.GetProperty("displayName").GetString())
            .Should().Equal($"Anton {marker}", $"Berta {marker}");
        (await ReadJsonAsync(second)).GetProperty("list").EnumerateArray()
            .Select(e => e.GetProperty("displayName").GetString()).Should().Equal($"Carl {marker}");
        first.Headers.Contains("X-Pagination").Should().BeTrue();
    }

    [Fact]
    public async Task ReadOnlyScope_IsEnough()
    {
        var client = CreateAuthenticatedClient(userId: $"ro-{Guid.NewGuid():N}", scopes: ["octo_api.read_only"]);
        client.DefaultRequestHeaders.Add(TestAuthHandler.NoRolesHeader, "true");

        var response = await client.GetAsync(TenantApiUrl(Url("take=1")), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ForeignTenantToken_Is403_EvenWithAdministratorRoles()
    {
        var client = CreateAuthenticatedClient(userId: $"foreign-{Guid.NewGuid():N}",
            roles: TestAuthDefaults.AdministratorRoles);
        client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, "some-other-tenant");

        var response = await client.GetAsync(TenantApiUrl(Url("take=1")), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ForeignTenantServiceToken_Is403()
    {
        var client = PlainUser();
        client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, $"svc-{Guid.NewGuid():N}");
        client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, "some-other-tenant");

        var response = await client.GetAsync(TenantApiUrl(Url("take=1")), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task WithoutToken_Is401()
    {
        var response = await CreateAnonymousClient().GetAsync(TenantApiUrl(Url("take=1")),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task GetPaged_StillRequiresUserManagement()
    {
        var response = await PlainUser().GetAsync(TenantApiUrl("users/getPaged?skip=0&take=1"),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }
}
