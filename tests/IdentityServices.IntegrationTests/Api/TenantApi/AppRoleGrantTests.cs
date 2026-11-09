using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8564: a caller holding <c>UserManagement</c> (a tenant owner) may grant app roles, the built-in roles a blueprint
///     other than <c>System.Identity.Bootstrap</c> seeds, without holding them: directly, through group membership and
///     through group nesting. Platform roles (the Bootstrap roles, here the real <c>StreamDataAdmin</c>) keep the
///     <c>role-not-held</c> protection of AB#7914/AB#7927, also inside a group that mixes both kinds. Real MongoDB, real
///     identity host; the app and platform roles are judged by the production <c>BootstrapPlatformRoleCatalog</c>.
/// </summary>
public class AppRoleGrantTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    private const string UserManagement = "UserManagement";
    private const string TenantManagement = "TenantManagement";

    /// <summary>A Bootstrap role neither caller below holds.</summary>
    private const string Platform = "StreamDataAdmin";

    /// <summary>The tenant owner of the bug report: a client-credentials caller with the TenantOwners administration roles.</summary>
    private static readonly CallerInfo TenantOwner = Service(TenantManagement, UserManagement);

    #region Direct grant

    [Fact]
    public async Task Direct_TenantOwner_GrantsAnAppRoleToAClient_WithoutHoldingIt()
    {
        var client = await NewClientAsync();
        var app = await NewAppRoleAsync();

        var response = await PutAsync(TenantOwner, $"clients/{client.ClientId}/roles/{app}");

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        (await ClientRoleIdsAsync(client)).Should().Equal(await RoleIdAsync(app));
    }

    [Fact]
    public async Task Direct_TenantOwner_GrantsAnAppRoleToAUser_WithoutHoldingIt()
    {
        var user = await CreateTestUserAsync(NewName("u8564"));
        var app = await NewAppRoleAsync();

        var response = await PutAsync(TenantOwner, $"users/{user.UserName}/roles/{app}");

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Direct_TenantOwner_IsRefusedAPlatformRoleItDoesNotHold()
    {
        var client = await NewClientAsync();
        await EnsurePlatformRoleAsync();

        var response = await PutAsync(TenantOwner, $"clients/{client.ClientId}/roles/{Platform}");

        var problem = await AssertProblemAsync(response, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(Platform);
        (await ClientRoleIdsAsync(client)).Should().BeEmpty();
    }

    [Fact]
    public async Task Direct_ReplacingTheRolesWithAnAppAndAPlatformRole_IsRefusedForThePlatformRoleOnly()
    {
        var client = await NewClientAsync();
        var app = await NewAppRoleAsync();
        var platform = await EnsurePlatformRoleAsync();

        var response = await PutJsonAsync(TenantOwner, $"clients/{client.ClientId}/roles",
            new[] { await RoleIdAsync(app), platform.RtId.ToString() });

        var problem = await AssertProblemAsync(response, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(Platform);
        (await ClientRoleIdsAsync(client)).Should().BeEmpty();
    }

    [Fact]
    public async Task Direct_ACallerWithoutUserManagement_IsRefusedAnAppRoleItDoesNotHold()
    {
        var client = await NewClientAsync();
        var app = await NewAppRoleAsync();

        var response = await PutAsync(Service(TenantManagement), $"clients/{client.ClientId}/roles/{app}");

        var problem = await AssertProblemAsync(response, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(app);
        (await ClientRoleIdsAsync(client)).Should().BeEmpty();
    }

    #endregion

    #region Group membership

    [Fact]
    public async Task Membership_TenantOwner_AddsAClientAndAUserToAGroupWithAnAppRole()
    {
        var group = await NewGroupAsync(await NewAppRoleAsync());
        var client = await NewClientAsync();
        var user = await CreateTestUserAsync(NewName("u8564"));

        var machine = await PutAsync(TenantOwner, $"groups/{group}/members/clients/{client.RtId}");
        var human = await PutAsync(TenantOwner, $"groups/{group}/members/users/{user.RtId}");

        machine.StatusCode.Should().Be(HttpStatusCode.OK,
            await machine.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        human.StatusCode.Should().Be(HttpStatusCode.OK);
        (await MemberClientIdsAsync(group)).Should().Contain(client.RtId.ToString());
        (await MemberUserIdsAsync(group)).Should().Contain(user.RtId.ToString());
    }

    [Fact]
    public async Task Membership_TenantOwner_IsRefusedAGroupWithAPlatformRoleItDoesNotHold()
    {
        var group = await NewGroupAsync((await EnsurePlatformRoleAsync()).Name!);
        var client = await NewClientAsync();

        var response = await PutAsync(TenantOwner, $"groups/{group}/members/clients/{client.RtId}");

        var problem = await AssertProblemAsync(response, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(Platform);
        (await MemberClientIdsAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task Membership_AMixedGroup_NeedsOnlyItsPlatformRolesHeld()
    {
        var app = await NewAppRoleAsync();
        var group = await NewGroupAsync(app, (await EnsurePlatformRoleAsync()).Name!);
        var client = await NewClientAsync();

        var refused = await PutAsync(TenantOwner, $"groups/{group}/members/clients/{client.RtId}");
        var allowed = await PutAsync(Service(TenantManagement, UserManagement, Platform),
            $"groups/{group}/members/clients/{client.RtId}");

        var problem = await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(Platform);
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
        (await MemberClientIdsAsync(group)).Should().Equal(client.RtId.ToString());
    }

    [Fact]
    public async Task Membership_TenantOwner_SetsAnAppRoleOnAGroup_ButNotAPlatformRole()
    {
        var group = await NewGroupAsync();
        var app = await RoleIdAsync(await NewAppRoleAsync());
        var platform = (await EnsurePlatformRoleAsync()).RtId.ToString();

        var refused = await PutJsonAsync(TenantOwner, $"groups/{group}/roles", new[] { app, platform });
        var allowed = await PutJsonAsync(TenantOwner, $"groups/{group}/roles", new[] { app });

        var problem = await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(Platform);
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
        (await GroupRoleIdsAsync(group)).Should().Equal(app);
    }

    [Fact]
    public async Task Membership_ACallerWithoutUserManagement_CannotAddAMemberToAnAppRoleGroup()
    {
        var group = await NewGroupAsync(await NewAppRoleAsync());
        var client = await NewClientAsync();

        var response = await PutAsync(Service(TenantManagement), $"groups/{group}/members/clients/{client.RtId}");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await MemberClientIdsAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task Membership_AddingOneselfToAnAppRoleGroup_StaysASelfGrant()
    {
        var admin = await CreateTestUserAsync(NewName("u8564"));
        var group = await NewGroupAsync(await NewAppRoleAsync());

        var response = await PutAsync(new CallerInfo(admin.RtId.ToString(), null, [TenantManagement, UserManagement]),
            $"groups/{group}/members/users/{admin.RtId}");

        await AssertProblemAsync(response, HttpStatusCode.Forbidden, "self-grant");
        (await MemberUserIdsAsync(group)).Should().BeEmpty();
    }

    #endregion

    #region Group nesting

    [Fact]
    public async Task Nesting_TenantOwner_NestsAGroupWithAnAppRole()
    {
        var parent = await NewGroupAsync();
        var child = await NewGroupAsync(await NewAppRoleAsync());

        var response = await PutAsync(TenantOwner, $"groups/{parent}/members/groups/{child}");

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        (await MemberGroupIdsAsync(parent)).Should().Equal(child.ToString());
    }

    [Fact]
    public async Task Nesting_TenantOwner_IsRefusedAChildGroupWithAPlatformRoleItDoesNotHold()
    {
        var parent = await NewGroupAsync();
        var child = await NewGroupAsync((await EnsurePlatformRoleAsync()).Name!);

        var response = await PutAsync(TenantOwner, $"groups/{parent}/members/groups/{child}");

        var problem = await AssertProblemAsync(response, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(Platform);
        (await MemberGroupIdsAsync(parent)).Should().BeEmpty();
    }

    [Fact]
    public async Task Nesting_AMixedChildGroup_IsRefusedForItsPlatformRoleOnly_AndAllowedWhenThatIsHeld()
    {
        var parent = await NewGroupAsync();
        var app = await NewAppRoleAsync();
        var child = await NewGroupAsync(app, (await EnsurePlatformRoleAsync()).Name!);

        var refused = await PutAsync(TenantOwner, $"groups/{parent}/members/groups/{child}");
        var allowed = await PutAsync(Service(TenantManagement, UserManagement, Platform),
            $"groups/{parent}/members/groups/{child}");

        var problem = await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "role-not-held");
        RoleNames(problem).Should().Equal(Platform);
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Nesting_ACallerWithoutUserManagement_CannotNestAnAppRoleGroup()
    {
        var parent = await NewGroupAsync();
        var child = await NewGroupAsync(await NewAppRoleAsync());

        var response = await PutAsync(Service(TenantManagement), $"groups/{parent}/members/groups/{child}");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await MemberGroupIdsAsync(parent)).Should().BeEmpty();
    }

    #endregion

    #region Client self-grant (AB#8569)

    // Gerald 2026-11-08: the self-grant block holds for app roles too (four-eyes principle). A client-credentials caller is
    // "self" for its own client, as a user session is for its own user; it may still grant app roles to other principals.

    private static CallerInfo AsClient(RtClient client) => new(null, client.ClientId, [TenantManagement, UserManagement]);

    [Fact]
    public async Task ClientSelf_AddingItselfToAGroupWithAnAppRole_IsRefusedAsSelfGrant()
    {
        var group = await NewGroupAsync(await NewAppRoleAsync());
        var self = await NewClientAsync();

        var response = await PutAsync(AsClient(self), $"groups/{group}/members/clients/{self.RtId}");

        // the same answer as for a user (no roleNames for self-grant)
        await AssertProblemAsync(response, HttpStatusCode.Forbidden, "self-grant");
        (await MemberClientIdsAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task ClientSelf_AddingAnAppRoleToItself_IsRefusedAsSelfGrant_SingleAndReplaceAll()
    {
        var self = await NewClientAsync();
        var app = await NewAppRoleAsync();

        var single = await PutAsync(AsClient(self), $"clients/{self.ClientId}/roles/{app}");
        var replaceAll = await PutJsonAsync(AsClient(self), $"clients/{self.ClientId}/roles", new[] { await RoleIdAsync(app) });

        await AssertProblemAsync(single, HttpStatusCode.Forbidden, "self-grant");
        await AssertProblemAsync(replaceAll, HttpStatusCode.Forbidden, "self-grant");
        (await ClientRoleIdsAsync(self)).Should().BeEmpty();
    }

    [Fact]
    public async Task ClientSelf_GrantingAnAppRoleToAnotherClient_IsAllowed_DirectAndThroughAGroup()
    {
        var self = await NewClientAsync();
        var other = await NewClientAsync();
        var app = await NewAppRoleAsync();
        var group = await NewGroupAsync(await NewAppRoleAsync());

        var direct = await PutAsync(AsClient(self), $"clients/{other.ClientId}/roles/{app}");
        var membership = await PutAsync(AsClient(self), $"groups/{group}/members/clients/{other.RtId}");

        direct.StatusCode.Should().Be(HttpStatusCode.OK,
            await direct.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        membership.StatusCode.Should().Be(HttpStatusCode.OK,
            await membership.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        (await ClientRoleIdsAsync(other)).Should().Equal(await RoleIdAsync(app));
        (await MemberClientIdsAsync(group)).Should().Equal(other.RtId.ToString());
    }

    [Fact]
    public async Task ClientSelf_WideningAGroupItIsIn_IsRefusedAsSelfGrant_ByNestingAndByAddingARole()
    {
        var self = await NewClientAsync();
        var parent = await NewGroupAsync();
        await AddClientMemberAsync(parent, self);
        var child = await NewGroupAsync();
        await PutAsync(TenantOwner, $"groups/{parent}/members/groups/{child}");
        var appGroup = await NewGroupAsync(await NewAppRoleAsync());
        var app = await RoleIdAsync(await NewAppRoleAsync());

        var nesting = await PutAsync(AsClient(self), $"groups/{parent}/members/groups/{appGroup}");
        var nestedRole = await PutJsonAsync(AsClient(self), $"groups/{child}/roles", new[] { app });

        await AssertProblemAsync(nesting, HttpStatusCode.Forbidden, "self-grant");
        await AssertProblemAsync(nestedRole, HttpStatusCode.Forbidden, "self-grant");
        (await MemberGroupIdsAsync(parent)).Should().Equal(child.ToString());
        (await GroupRoleIdsAsync(child)).Should().BeEmpty();
    }

    [Fact]
    public async Task ClientSelf_RemovingItsOwnRoleAndMembership_IsAllowed()
    {
        var self = await NewClientAsync();
        var app = await NewAppRoleAsync();
        var group = await NewGroupAsync(await NewAppRoleAsync());
        (await PutAsync(TenantOwner, $"clients/{self.ClientId}/roles/{app}")).StatusCode.Should().Be(HttpStatusCode.OK);
        await AddClientMemberAsync(group, self);

        using var client = RestClient(AsClient(self));
        var role = await client.DeleteAsync(TenantApiUrl($"clients/{self.ClientId}/roles/{app}"),
            TestContext.Current.CancellationToken);
        var membership = await client.DeleteAsync(TenantApiUrl($"groups/{group}/members/clients/{self.RtId}"),
            TestContext.Current.CancellationToken);

        role.StatusCode.Should().Be(HttpStatusCode.OK);
        membership.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ClientRoleIdsAsync(self)).Should().BeEmpty();
        (await MemberClientIdsAsync(group)).Should().BeEmpty();
    }

    #endregion

    #region Helpers

    private sealed record CallerInfo(string? Subject, string? ClientId, string[] Roles);

    private static CallerInfo Service(params string[] roles) => new(null, $"svc8564_{Guid.NewGuid():N}", roles);

    private HttpClient RestClient(CallerInfo caller)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        if (caller.ClientId != null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, caller.ClientId);
        }
        else
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, caller.Subject);
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        }

        foreach (var role in caller.Roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        return client;
    }

    private async Task<HttpResponseMessage> PutAsync(CallerInfo caller, string path)
    {
        using var client = RestClient(caller);
        return await client.PutAsync(TenantApiUrl(path), null, TestContext.Current.CancellationToken);
    }

    private async Task<HttpResponseMessage> PutJsonAsync<T>(CallerInfo caller, string path, T body)
    {
        using var client = RestClient(caller);
        return await client.PutAsJsonAsync(TenantApiUrl(path), body, TestContext.Current.CancellationToken);
    }

    private static async Task<JsonElement> AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status,
        string code)
    {
        response.StatusCode.Should().Be(status, await response.Content.ReadAsStringAsync());
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("code").GetString().Should().Be(code);
        return json;
    }

    private static IEnumerable<string?> RoleNames(JsonElement problem) =>
        problem.GetProperty("roleNames").EnumerateArray().Select(e => e.GetString());

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    /// <summary>An app role: built-in (with an rtWellKnownName) but not one of the System.Identity.Bootstrap roles.</summary>
    private async Task<string> NewAppRoleAsync()
    {
        var name = NewName("app8564");
        using var scope = CreateScope();
        var role = new RtRoleBuilder().WithName(name).Build();
        role.RtWellKnownName = name;
        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().CreateAsync(role)).Succeeded.Should()
            .BeTrue();
        return name;
    }

    /// <summary>The real Bootstrap role <see cref="Platform" /> (seeded by the blueprint; created when the test tenant lacks it).</summary>
    private async Task<RtRole> EnsurePlatformRoleAsync()
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var role = await roleManager.FindByNameAsync(Platform);
        if (role == null)
        {
            role = new RtRoleBuilder().WithName(Platform).Build();
            role.RtWellKnownName = Platform;
            // a parallel test may have created it in the meantime
            await roleManager.CreateAsync(role);
            role = await roleManager.FindByNameAsync(Platform);
        }

        role.Should().NotBeNull();
        role!.RtWellKnownName.Should().Be(Platform);
        return role;
    }

    private async Task<string> RoleIdAsync(string name)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name))!.RtId
            .ToString();
    }

    private async Task<RtClient> NewClientAsync() => await CreateTestClientAsync(NewName("c8564"));

    private async Task<OctoObjectId> NewGroupAsync(params string[] roles)
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        var name = NewName("g8564");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        };
        await store.StoreAsync(group);
        var ids = new List<string>();
        foreach (var role in roles)
        {
            ids.Add(await RoleIdAsync(role));
        }

        await store.SetRoleIdsAsync(group.RtId, ids);
        return group.RtId;
    }

    private async Task<IReadOnlyList<string>> ClientRoleIdsAsync(RtClient client)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IClientRoleStore>().GetDirectRoleIdsAsync(client.RtId);
    }

    private async Task AddClientMemberAsync(OctoObjectId group, RtClient client)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberClientAsync(group, client.RtId.ToString());
    }

    private async Task<IReadOnlyList<string>> MemberUserIdsAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberUserIdsAsync(group);
    }

    private async Task<IReadOnlyList<string>> MemberClientIdsAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberClientIdsAsync(group);
    }

    private async Task<IReadOnlyList<string>> MemberGroupIdsAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberGroupIdsAsync(group);
    }

    private async Task<IReadOnlyList<string>> GroupRoleIdsAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetRoleIdsAsync(group);
    }

    #endregion
}
