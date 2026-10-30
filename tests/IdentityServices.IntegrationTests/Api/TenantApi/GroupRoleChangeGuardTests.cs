using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#7927: the role change guard of AB#7914 on groups, external tenant user mappings and role definitions (REST).
///     Real MongoDB, real identity host. The last-administrator tests first remove every effective <c>UserManagement</c>
///     holder of the test database, so exactly the holders a test creates exist.
/// </summary>
public class GroupRoleChangeGuardTests : IntegrationTestBase
{
    private const string UserManagement = "UserManagement";

    private readonly WebApplicationFactory<Program> _host;
    private readonly List<string> _audit = [];

    public GroupRoleChangeGuardTests(CustomWebApplicationFactory factory) : base(factory)
    {
        var events = Substitute.For<IEventRepository>();
        events.When(e => e.StoreErrorEvent(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<string>(),
                Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                lock (_audit)
                {
                    _audit.Add(call.ArgAt<string>(2));
                }
            });
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services => services.AddSingleton(events)));
    }

    #region Self-grant

    [Fact]
    public async Task SelfGrant_AddingOneselfToAGroupWithRoles_IsRefused_AndNothingIsWritten()
    {
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(await NewRoleAsync());

        var response = await PutAsync(Caller(admin), $"groups/{group}/members/users/{admin.RtId}");

        await AssertProblemAsync(response, HttpStatusCode.Forbidden, "self-grant");
        (await MembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task SelfGrant_AddingOneselfToAGroupWithoutRoles_IsAllowed()
    {
        var admin = await NewUserAsync();
        var group = await NewGroupAsync();

        (await PutAsync(Caller(admin), $"groups/{group}/members/users/{admin.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task SelfGrant_AddingRolesToAGroupTheCallerBelongsTo_DirectlyOrThroughAParentGroup_IsRefused()
    {
        var admin = await NewUserAsync();
        var parent = await NewGroupAsync();
        var child = await NewGroupAsync();
        await AddChildAsync(parent, child);
        await AddMemberAsync(parent, admin);
        var extra = await RoleIdAsync(await NewRoleAsync());

        var viaParent = await PutJsonAsync(Caller(admin), $"groups/{parent}/roles", new[] { extra });
        var viaChild = await PutJsonAsync(Caller(admin), $"groups/{child}/roles", new[] { extra });

        await AssertProblemAsync(viaParent, HttpStatusCode.Forbidden, "self-grant");
        await AssertProblemAsync(viaChild, HttpStatusCode.Forbidden, "self-grant");
        (await RoleIdsAsync(parent)).Should().BeEmpty();
        (await RoleIdsAsync(child)).Should().BeEmpty();
    }

    [Fact]
    public async Task SelfGrant_AddingAChildGroupWithRolesBelowAGroupOfTheCaller_IsRefused()
    {
        var admin = await NewUserAsync();
        var parent = await NewGroupAsync();
        await AddMemberAsync(parent, admin);
        var child = await NewGroupAsync(await NewRoleAsync());

        var response = await PutAsync(Caller(admin), $"groups/{parent}/members/groups/{child}");

        await AssertProblemAsync(response, HttpStatusCode.Forbidden, "self-grant");
    }

    [Fact]
    public async Task SelfGrant_AGroupOfTheCallersShadowUserMapping_CannotGetMoreRoles()
    {
        var (shadow, mapping) = await NewShadowUserWithMappingAsync();
        var group = await NewGroupAsync();
        await AddMappingMemberAsync(group, mapping);
        var extra = await RoleIdAsync(await NewRoleAsync());

        var viaGroup = await PutJsonAsync(shadow, $"groups/{group}/roles", new[] { extra });
        var viaMapping = await PutJsonAsync(shadow, $"externalTenantUserMappings/{mapping}",
            new { roleIds = new[] { extra } });

        await AssertProblemAsync(viaGroup, HttpStatusCode.Forbidden, "self-grant");
        await AssertProblemAsync(viaMapping, HttpStatusCode.Forbidden, "self-grant");
    }

    #endregion

    #region Grant only what you hold

    [Fact]
    public async Task RoleNotHeld_GroupRoles_WithABuiltInRoleTheCallerLacks_IsRefused_ButHeldAndCustomRolesSucceed()
    {
        var caller = await NewUserAsync();
        var secret = await NewRoleAsync(builtIn: true);
        var held = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var group = await NewGroupAsync();

        var refused = await PutJsonAsync(Caller(caller, held), $"groups/{group}/roles",
            new[] { await RoleIdAsync(secret), await RoleIdAsync(held) });
        var allowed = await PutJsonAsync(Caller(caller, held), $"groups/{group}/roles",
            new[] { await RoleIdAsync(held), await RoleIdAsync(custom) });

        var problem = await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "role-not-held");
        problem.GetProperty("roleNames").EnumerateArray().Select(e => e.GetString()).Should().Equal(secret);
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
        (await RoleIdsAsync(group)).Should().BeEquivalentTo(await RoleIdAsync(held), await RoleIdAsync(custom));
    }

    [Fact]
    public async Task RoleNotHeld_AddingAnotherUserOrClientToAGroupWithABuiltInRole_IsRefused()
    {
        var caller = await NewUserAsync();
        var other = await NewUserAsync();
        var client = await NewClientAsync();
        var secret = await NewRoleAsync(builtIn: true);
        var group = await NewGroupAsync(secret);

        var user = await PutAsync(Caller(caller), $"groups/{group}/members/users/{other.RtId}");
        var machine = await PutAsync(Caller(caller), $"groups/{group}/members/clients/{client}");

        await AssertProblemAsync(user, HttpStatusCode.Forbidden, "role-not-held");
        await AssertProblemAsync(machine, HttpStatusCode.Forbidden, "role-not-held");
        (await MembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task RoleNotHeld_TheRolesOfNestedGroupsCount_ForAMemberAndForAChildGroup()
    {
        var caller = await NewUserAsync();
        var other = await NewUserAsync();
        var secret = await NewRoleAsync(builtIn: true);
        var deep = await NewGroupAsync(secret);
        var top = await NewGroupAsync();
        await AddChildAsync(top, deep);
        var target = await NewGroupAsync();

        var member = await PutAsync(Caller(caller), $"groups/{top}/members/users/{other.RtId}");
        var child = await PutAsync(Caller(caller), $"groups/{target}/members/groups/{top}");

        await AssertProblemAsync(member, HttpStatusCode.Forbidden, "role-not-held");
        await AssertProblemAsync(child, HttpStatusCode.Forbidden, "role-not-held");
    }

    [Fact]
    public async Task RoleNotHeld_AddingToAGroupWithHeldOrCustomRoles_Succeeds_AndAnExistingMemberIsNotJudgedAgain()
    {
        var caller = await NewUserAsync();
        var other = await NewUserAsync();
        var held = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var group = await NewGroupAsync(held, custom);

        (await PutAsync(Caller(caller, held), $"groups/{group}/members/users/{other.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);

        // a built-in role the caller lacks, but the member is already there: nothing is granted
        var secret = await NewRoleAsync(builtIn: true);
        var existing = await NewGroupAsync(secret);
        await AddMemberAsync(existing, other);
        (await PutAsync(Caller(caller), $"groups/{existing}/members/users/{other.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RoleNotHeld_MappingCreateAndUpdate_WithABuiltInRoleTheCallerLacks_IsRefused()
    {
        var caller = await NewUserAsync();
        var held = await NewRoleAsync(builtIn: true);
        var secret = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();

        var create = await PostJsonAsync(Caller(caller, held), "externalTenantUserMappings", NewMappingBody(await RoleIdAsync(secret)));
        var ok = await PostJsonAsync(Caller(caller, held), "externalTenantUserMappings",
            NewMappingBody(await RoleIdAsync(held), await RoleIdAsync(custom)));
        ok.StatusCode.Should().Be(HttpStatusCode.Created);
        var mappingId = (await ok.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("id").GetString();
        var update = await PutJsonAsync(Caller(caller, held), $"externalTenantUserMappings/{mappingId}",
            new { roleIds = new[] { await RoleIdAsync(held), await RoleIdAsync(secret) } });
        var same = await PutJsonAsync(Caller(caller, held), $"externalTenantUserMappings/{mappingId}",
            new { roleIds = new[] { await RoleIdAsync(held), await RoleIdAsync(custom) } });

        await AssertProblemAsync(create, HttpStatusCode.Forbidden, "role-not-held");
        await AssertProblemAsync(update, HttpStatusCode.Forbidden, "role-not-held");
        same.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    #endregion

    #region Last user administrator

    [Fact]
    public async Task LastAdministrator_RemovingTheOnlyHolderFromTheGroup_IsRefused_WithASecondHolderItSucceeds()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddMemberAsync(group, admin);
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        await AssertProblemAsync(await DeleteAsync(caller, $"groups/{group}/members/users/{admin.RtId}"),
            HttpStatusCode.Conflict, "last-administrator");
        (await MembersAsync(group)).Should().Equal(admin.RtId.ToString());

        var second = await NewUserAsync(UserManagement);
        (await DeleteAsync(caller, $"groups/{group}/members/users/{admin.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        second.Should().NotBeNull();
    }

    [Fact]
    public async Task LastAdministrator_TheGroupLosesTheRole_IsDeleted_OrALeavesChildGroup_IsRefused()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync();
        var inner = await NewGroupAsync(UserManagement);
        var outer = await NewGroupAsync();
        await AddChildAsync(outer, inner);
        await AddMemberAsync(outer, admin);
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        await AssertProblemAsync(await PutJsonAsync(caller, $"groups/{inner}/roles", Array.Empty<string>()),
            HttpStatusCode.Conflict, "last-administrator");
        await AssertProblemAsync(await DeleteAsync(caller, $"groups/{inner}"), HttpStatusCode.Conflict,
            "last-administrator");
        await AssertProblemAsync(await DeleteAsync(caller, $"groups/{outer}/members/groups/{inner}"),
            HttpStatusCode.Conflict, "last-administrator");
        await AssertProblemAsync(await DeleteAsync(caller, $"groups/{outer}"), HttpStatusCode.Conflict,
            "last-administrator");
        (await RoleIdsAsync(inner)).Should().ContainSingle();
    }

    [Fact]
    public async Task LastAdministrator_WithASecondHolder_EachOperationSucceeds()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddMemberAsync(group, admin);
        await NewUserAsync(UserManagement); // a second, direct holder
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        (await PutJsonAsync(caller, $"groups/{group}/roles", Array.Empty<string>())).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DeleteAsync(caller, $"groups/{group}")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task LastAdministrator_AGroupMemberThatIsAClient_DoesNotCount()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddMemberAsync(group, admin);
        var client = await NewClientAsync();
        await AddClientMemberAsync(group, client);
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        await AssertProblemAsync(await DeleteAsync(caller, $"groups/{group}/members/users/{admin.RtId}"),
            HttpStatusCode.Conflict, "last-administrator");
        // taking the client out is not judged and works
        (await DeleteAsync(caller, $"groups/{group}/members/clients/{client}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task LastAdministrator_AShadowUserThroughAMapping_IsTheLastHolder()
    {
        await ClearAdministratorsAsync();
        var userManagementId = await RoleIdAsync(UserManagement);
        var (_, mapping) = await NewShadowUserWithMappingAsync(userManagementId);
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        await AssertProblemAsync(
            await PutJsonAsync(caller, $"externalTenantUserMappings/{mapping}", new { roleIds = Array.Empty<string>() }),
            HttpStatusCode.Conflict, "last-administrator");
        await AssertProblemAsync(await DeleteAsync(caller, $"externalTenantUserMappings/{mapping}"),
            HttpStatusCode.Conflict, "last-administrator");

        await NewUserAsync(UserManagement);
        (await DeleteAsync(caller, $"externalTenantUserMappings/{mapping}")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task LastAdministrator_AMappingThatIsAMemberOfAGroupWithTheRole_IsTheLastHolder()
    {
        await ClearAdministratorsAsync();
        var (_, mapping) = await NewShadowUserWithMappingAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddMappingMemberAsync(group, mapping);
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        await AssertProblemAsync(await PutJsonAsync(caller, $"groups/{group}/roles", Array.Empty<string>()),
            HttpStatusCode.Conflict, "last-administrator");
        await AssertProblemAsync(await DeleteAsync(caller, $"externalTenantUserMappings/{mapping}"),
            HttpStatusCode.Conflict, "last-administrator");
    }

    [Fact]
    public async Task LastAdministrator_ATenantWithoutAnyHolder_IsNotBlocked()
    {
        await ClearAdministratorsAsync();
        var group = await NewGroupAsync(await NewRoleAsync());
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        (await DeleteAsync(caller, $"groups/{group}")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    #endregion

    #region Built-in roles

    [Fact]
    public async Task BuiltInRole_RenameAndDelete_AreRefused_WithCode_AndNothingChanges()
    {
        var builtIn = await NewRoleAsync(builtIn: true);
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        var rename = await PutJsonAsync(caller, $"roles/{builtIn}", new { name = builtIn + "_renamed" });
        var delete = await DeleteAsync(caller, $"roles/{builtIn}");

        var problem = await AssertProblemAsync(rename, HttpStatusCode.Conflict, "built-in-role");
        problem.GetProperty("title").GetString().Should().Contain(builtIn);
        await AssertProblemAsync(delete, HttpStatusCode.Conflict, "built-in-role");
        (await FindRoleAsync(builtIn)).Should().NotBeNull();
        (await FindRoleAsync(builtIn + "_renamed")).Should().BeNull();
    }

    [Fact]
    public async Task BuiltInRole_UpdateWithTheSameName_IsNoRename_AndCustomRolesCanBeRenamedAndDeleted()
    {
        var builtIn = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var caller = Caller(Guid.NewGuid().ToString("N"), UserManagement);

        (await PutJsonAsync(caller, $"roles/{builtIn}", new { name = builtIn })).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await PutJsonAsync(caller, $"roles/{custom}", new { name = custom + "_new" })).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DeleteAsync(caller, $"roles/{custom}_new")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    #endregion

    #region Audit and unchanged flows

    [Fact]
    public async Task EveryRefusal_WritesOneAuditRecord_WithCallerTargetReasonAndRoleNames_AndNoSecrets()
    {
        var secret = await NewRoleAsync(builtIn: true);
        var other = await NewUserAsync();
        var group = await NewGroupAsync(secret);
        var actor = Guid.NewGuid().ToString("N");
        int Count() { lock (_audit) { return _audit.Count; } }
        var before = Count();

        await AssertProblemAsync(await PutAsync(Caller(actor, UserManagement), $"groups/{group}/members/users/{other.RtId}"),
            HttpStatusCode.Forbidden, "role-not-held");

        Count().Should().Be(before + 1);
        string record;
        lock (_audit)
        {
            record = _audit[^1];
        }

        record.Should().Contain("Identity.RoleChangeRefused").And.Contain("role-not-held").And.Contain(actor)
            .And.Contain(group.ToString()).And.Contain(secret);
        record.ToLowerInvariant().Should().NotContain("bearer").And.NotContain("password").And.NotContain("test-token");
    }

    [Fact]
    public async Task AllowedChanges_ThatStudioAndTheCliMake_KeepWorking()
    {
        // an administrator who holds the group's built-in role adds another user, replaces the roles and takes the user out again
        var admin = await NewUserAsync();
        var other = await NewUserAsync();
        var held = await NewRoleAsync(builtIn: true);
        var group = await NewGroupAsync(held);
        var caller = Caller(admin, held, UserManagement);

        (await PutAsync(caller, $"groups/{group}/members/users/{other.RtId}")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PutJsonAsync(caller, $"groups/{group}/roles", new[] { await RoleIdAsync(held) })).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DeleteAsync(caller, $"groups/{group}/members/users/{other.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        var create = await PostJsonAsync(caller, "groups", new { groupName = NewName("created"), roleIds = new[] { await RoleIdAsync(held) } });
        create.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task TheGuard_IsNotCalledFromTheGroupStore_SoSeedsGrantsAndLoginRulesStayUnchanged()
    {
        using var scope = CreateScope();
        foreach (var type in new[] { typeof(GroupStore), typeof(OctoUserStore), typeof(ExternalTenantUserMappingStore) })
        {
            type.GetConstructors().SelectMany(c => c.GetParameters())
                .Should().NotContain(p => p.ParameterType.Name == "IRoleChangeGuard", type.Name);
        }

        // what the Bootstrap seed, the scratch-tenant grant and the login rules use: the store, not the controller
        var group = await NewGroupAsync(await NewRoleAsync(builtIn: true));
        var user = await NewUserAsync();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberUserAsync(group, user.RtId.ToString());
        (await MembersAsync(group)).Should().Equal(user.RtId.ToString());
    }

    #endregion

    #region Helpers

    private sealed record CallerInfo(string Subject, string[] Roles);

    private static CallerInfo Caller(RtUser user, params string[] roles) =>
        new(user.RtId.ToString(), roles.Length == 0 ? [UserManagement] : roles.Append(UserManagement).ToArray());

    private static CallerInfo Caller(string subject, params string[] roles) => new(subject, roles);

    private HttpClient RestClient(CallerInfo caller)
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, caller.Subject);
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
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

    private async Task<HttpResponseMessage> PostJsonAsync<T>(CallerInfo caller, string path, T body)
    {
        using var client = RestClient(caller);
        return await client.PostAsJsonAsync(TenantApiUrl(path), body, TestContext.Current.CancellationToken);
    }

    private async Task<HttpResponseMessage> DeleteAsync(CallerInfo caller, string path)
    {
        using var client = RestClient(caller);
        return await client.DeleteAsync(TenantApiUrl(path), TestContext.Current.CancellationToken);
    }

    private static async Task<JsonElement> AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status,
        string code)
    {
        response.StatusCode.Should().Be(status);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("code").GetString().Should().Be(code);
        return json;
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private static object NewMappingBody(params string[] roleIds) => new
    {
        sourceTenantId = "parent_" + Guid.NewGuid().ToString("N")[..8],
        sourceUserId = OctoObjectId.GenerateNewId().ToString(),
        sourceUserName = NewName("home"),
        roleIds
    };

    /// <summary>A role; a built-in one carries an rtWellKnownName like the roles of the Bootstrap blueprint.</summary>
    private async Task<string> NewRoleAsync(bool builtIn = false)
    {
        var name = NewName(builtIn ? "b7927" : "c7927");
        using var scope = CreateScope();
        var role = new RtRoleBuilder().WithName(name).Build();
        if (builtIn)
        {
            role.RtWellKnownName = name;
        }

        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().CreateAsync(role)).Succeeded.Should()
            .BeTrue();
        return name;
    }

    private async Task<RtRole> EnsureUserManagementAsync()
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var role = await roleManager.FindByNameAsync(UserManagement);
        if (role == null)
        {
            role = new RtRoleBuilder().WithName(UserManagement).Build();
            role.RtWellKnownName = UserManagement;
            (await roleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
        }

        role.RtWellKnownName.Should().NotBeNullOrEmpty("UserManagement is a built-in role");
        return role;
    }

    private async Task<RtRole?> FindRoleAsync(string name)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name);
    }

    private async Task<string> RoleIdAsync(string name)
    {
        if (name == UserManagement)
        {
            await EnsureUserManagementAsync();
        }

        return (await FindRoleAsync(name))!.RtId.ToString();
    }

    private async Task<RtUser> NewUserAsync(params string[] directRoles)
    {
        if (directRoles.Contains(UserManagement))
        {
            await EnsureUserManagementAsync();
        }

        var user = await CreateTestUserAsync(NewName("u7927"));
        foreach (var role in directRoles)
        {
            using var scope = CreateScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var fresh = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
            (await userManager.AddToRoleAsync(fresh, role.ToUpperInvariant())).Succeeded.Should().BeTrue();
        }

        return user;
    }

    private async Task<OctoObjectId> NewClientAsync() => (await CreateTestClientAsync(NewName("c7927"))).RtId;

    private async Task<OctoObjectId> NewGroupAsync(params string[] roles)
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        var name = NewName("g7927");
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

    private async Task AddMemberAsync(OctoObjectId group, RtUser user)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberUserAsync(group, user.RtId.ToString());
    }

    private async Task AddClientMemberAsync(OctoObjectId group, OctoObjectId client)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberClientAsync(group, client.ToString());
    }

    private async Task AddMappingMemberAsync(OctoObjectId group, OctoObjectId mapping)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>()
            .AddMemberExternalUserAsync(group, mapping.ToString());
    }

    private async Task AddChildAsync(OctoObjectId parent, OctoObjectId child)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberGroupAsync(parent, child.ToString());
    }

    private async Task<IReadOnlyList<string>> MembersAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberUserIdsAsync(group);
    }

    private async Task<IReadOnlyList<string>> RoleIdsAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetRoleIdsAsync(group);
    }

    /// <summary>A cross-tenant shadow user (xt_) of this tenant with its mapping (optionally carrying role ids).</summary>
    private async Task<(CallerInfo Shadow, OctoObjectId Mapping)> NewShadowUserWithMappingAsync(
        params string[] mappedRoleIds)
    {
        var sourceUser = NewName("home");
        var shadowName = CrossTenantShadowUserName.Build(NormalizedSystemTenantId, sourceUser);
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var shadow = new RtUserBuilder().WithUserName(shadowName).WithEmail($"{shadowName}@example.com").Build();
        (await userManager.CreateAsync(shadow)).Succeeded.Should().BeTrue();
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = NormalizedSystemTenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = sourceUser,
            MappedRoleIds = new AttributeStringValueList(mappedRoleIds.ToList())
        };
        await scope.ServiceProvider.GetRequiredService<IExternalTenantUserMappingStore>().StoreAsync(mapping);
        var stored = (await userManager.FindByNameAsync(shadowName))!;
        return (new CallerInfo(stored.RtId.ToString(), [UserManagement]), mapping.RtId);
    }

    /// <summary>Removes every way to hold UserManagement (direct, groups, mappings), so a test starts from a known state.</summary>
    private async Task ClearAdministratorsAsync()
    {
        var role = await EnsureUserManagementAsync();
        var roleId = role.RtId.ToString();
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        foreach (var holder in await userManager.GetUsersInRoleAsync(role.NormalizedName!))
        {
            await userManager.RemoveFromRoleAsync(holder, role.NormalizedName!);
        }

        var groups = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        foreach (var group in await groups.GetAllAsync())
        {
            var roles = await groups.GetRoleIdsAsync(group.RtId);
            if (roles.Contains(roleId))
            {
                await groups.SetRoleIdsAsync(group.RtId, roles.Where(r => r != roleId).ToList());
            }
        }

        var mappings = scope.ServiceProvider.GetRequiredService<IExternalTenantUserMappingStore>();
        foreach (var mapping in await mappings.GetAllAsync())
        {
            if (mapping.MappedRoleIds?.Contains(roleId) == true)
            {
                mapping.MappedRoleIds = new AttributeStringValueList(mapping.MappedRoleIds.Where(r => r != roleId).ToList());
                await mappings.StoreAsync(mapping);
            }
        }
    }

    #endregion
}
