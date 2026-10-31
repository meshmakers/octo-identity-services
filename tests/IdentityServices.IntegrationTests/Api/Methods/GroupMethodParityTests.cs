using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7779: the parity table. Every guard of the REST group endpoints of <c>GroupsController</c> that the group methods
///     repeat is run against the real REST pipeline and against the method handler in the same situation; both must refuse (or
///     allow) alike and leave the same state behind. Each test builds the situation twice (one REST group, one method group).
/// </summary>
public class GroupMethodParityTests(CustomWebApplicationFactory factory) : GroupMethodTestBase(factory)
{
    private static CallerInfo AnyAdmin() => Caller(Guid.NewGuid().ToString("N"), UserManagement);

    private static async Task<JsonElement> ProblemAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        response.StatusCode.Should().Be(status);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("code").GetString().Should().Be(code);
        return json;
    }

    private static void Forbidden(CkMethodOutcome outcome, string reason)
    {
        outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        outcome.Failure.Parameters.Should().Contain("reason", reason);
    }

    // allowed: adding and removing a user
    [Fact]
    public async Task Allowed_AddAndRemoveUser_LeaveTheSameMembersAndEffectiveRoles()
    {
        var role = await NewRoleAsync();
        var (restGroup, methodGroup) = (await NewGroupAsync(role), await NewGroupAsync(role));
        var (restUser, methodUser) = (await NewUserAsync(), await NewUserAsync());

        (await RestPutAsync(AnyAdmin(), $"groups/{restGroup}/members/users/{restUser.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await MethodAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
            methodGroup, Admin(), new GroupAddMemberParameters
            {
                MemberKind = RtGroupMemberKindEnum.User, MemberId = methodUser.RtId.ToString()
            })).IsSuccess.Should().BeTrue();
        (await MembersAsync(restGroup)).Should().HaveCount(1).And.HaveCount((await MembersAsync(methodGroup)).Count);
        (await EffectiveRolesAsync(restUser)).Should().BeEquivalentTo(await EffectiveRolesAsync(methodUser));

        (await RestDeleteAsync(AnyAdmin(), $"groups/{restGroup}/members/users/{restUser.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await MethodAsync<GroupRemoveMemberHandler, GroupRemoveMemberParameters>(
            SystemIdentityCkIds.GroupRemoveMemberMethodId, methodGroup, Admin(),
            new GroupRemoveMemberParameters
            {
                MemberKind = RtGroupMemberKindEnum.User, MemberId = methodUser.RtId.ToString()
            })).IsSuccess.Should().BeTrue();
        (await MembersAsync(restGroup)).Should().BeEmpty();
        (await MembersAsync(methodGroup)).Should().BeEmpty();
        (await EffectiveRolesAsync(restUser)).Should().BeEquivalentTo(await EffectiveRolesAsync(methodUser));
    }

    // allowed: adding and removing a client; removal is not judged by the guard in either transport
    [Fact]
    public async Task Allowed_AddAndRemoveClient_AndRemovalIsNotJudged_InBothTransports()
    {
        var builtIn = await NewRoleAsync(builtIn: true); // the caller holds none of the built-in roles
        var (restGroup, methodGroup) = (await NewGroupAsync(), await NewGroupAsync());
        var (restClient, methodClient) = (await NewClientAsync(), await NewClientAsync());

        (await RestPutAsync(AnyAdmin(), $"groups/{restGroup}/members/clients/{restClient.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await MethodAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
            methodGroup, Admin(), new GroupAddMemberParameters
            {
                MemberKind = RtGroupMemberKindEnum.Client, MemberId = methodClient.RtId.ToString()
            })).IsSuccess.Should().BeTrue();
        (await ClientMembersAsync(restGroup)).Should().HaveCount(1);
        (await ClientMembersAsync(methodGroup)).Should().HaveCount(1);

        // the groups now carry a built-in role the caller does not hold: removing the client is still allowed
        await SetRolesViaStoreAsync(restGroup, builtIn);
        await SetRolesViaStoreAsync(methodGroup, builtIn);
        (await RestDeleteAsync(AnyAdmin(), $"groups/{restGroup}/members/clients/{restClient.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await MethodAsync<GroupRemoveMemberHandler, GroupRemoveMemberParameters>(
            SystemIdentityCkIds.GroupRemoveMemberMethodId, methodGroup, Admin(),
            new GroupRemoveMemberParameters
            {
                MemberKind = RtGroupMemberKindEnum.Client, MemberId = methodClient.RtId.ToString()
            })).IsSuccess.Should().BeTrue();
        (await ClientMembersAsync(restGroup)).Should().BeEmpty();
        (await ClientMembersAsync(methodGroup)).Should().BeEmpty();
    }

    // allowed: SetRoles (REST by ids, the method by names)
    [Fact]
    public async Task Allowed_SetRoles_LeavesTheSameRoleIds()
    {
        var (a, b) = (await NewRoleAsync(), await NewRoleAsync());
        var (restGroup, methodGroup) = (await NewGroupAsync(a), await NewGroupAsync(a));

        (await RestPutJsonAsync(AnyAdmin(), $"groups/{restGroup}/roles", new[] { await RoleIdAsync(b) })).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await MethodAsync<GroupSetRolesHandler, GroupSetRolesParameters>(SystemIdentityCkIds.GroupSetRolesMethodId,
            methodGroup, Admin(), new GroupSetRolesParameters { RoleNames = [b] })).IsSuccess.Should().BeTrue();

        (await RoleIdsAsync(restGroup)).Should().Equal(await RoleIdAsync(b));
        (await RoleIdsAsync(methodGroup)).Should().Equal(await RoleIdAsync(b));
    }

    // guard: the group does not exist
    [Fact]
    public async Task Guard_UnknownGroup()
    {
        var user = await NewUserAsync();
        var missing = OctoObjectId.GenerateNewId();

        (await RestPutAsync(AnyAdmin(), $"groups/{missing}/members/users/{user.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await MethodAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
            missing, Admin(), new GroupAddMemberParameters
            {
                MemberKind = RtGroupMemberKindEnum.User, MemberId = user.RtId.ToString()
            })).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
    }

    // guard: scope and role of the caller
    [Fact]
    public async Task Guard_Caller_NoRole_ReadOnlyScope_AndServiceClient()
    {
        var (restGroup, methodGroup) = (await NewGroupAsync(), await NewGroupAsync());
        var (restUser, methodUser) = (await NewUserAsync(), await NewUserAsync());
        var restPath = $"groups/{restGroup}/members/users/{restUser.RtId}";
        var parameters = new GroupAddMemberParameters
        {
            MemberKind = RtGroupMemberKindEnum.User, MemberId = methodUser.RtId.ToString()
        };

        (await RestPutAsync(Caller("c", "TenantManagement"), restPath)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await MethodAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
            methodGroup, new CkMethodPrincipal("c", ["TenantManagement"], ["octo_api"]), parameters)).Failure!.Code
            .Should().Be("METHOD_FORBIDDEN");

        (await RestPutAsync(Caller("c", UserManagement) with { Scopes = ["octo_api.read_only"] }, restPath)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden);
        (await MethodAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
                methodGroup, new CkMethodPrincipal("c", [UserManagement], ["octo_api.read_only"]), parameters)).Failure!
            .Code.Should().Be("METHOD_FORBIDDEN");

        (await MembersAsync(restGroup)).Should().BeEmpty();
        (await MembersAsync(methodGroup)).Should().BeEmpty();

        // a service client with UserManagement may (client roles, AB#4183)
        using var service = RestClient(Caller("c", UserManagement));
        service.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, $"svc-{Guid.NewGuid():N}");
        (await service.PutAsync(TenantApiUrl(restPath), null, TestContext.Current.CancellationToken)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await MethodAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
            methodGroup, new CkMethodPrincipal(null, [UserManagement], ["octo_api"], "svc"), parameters)).IsSuccess
            .Should().BeTrue();
    }

    // guard AB#7927: self-grant
    [Fact]
    public async Task Guard_SelfGrant_AddingOneselfToAGroupWithRoles_IsRefusedAlike()
    {
        var role = await NewRoleAsync();
        var (restGroup, methodGroup) = (await NewGroupAsync(role), await NewGroupAsync(role));
        var admin = await NewUserAsync();

        await ProblemAsync(await RestPutAsync(Caller(admin), $"groups/{restGroup}/members/users/{admin.RtId}"),
            HttpStatusCode.Forbidden, "self-grant");
        Forbidden(await MethodAsync<GroupAddMemberHandler, GroupAddMemberParameters>(
            SystemIdentityCkIds.GroupAddMemberMethodId, methodGroup,
            new CkMethodPrincipal(admin.RtId.ToString(), [UserManagement], ["octo_api"]),
            new GroupAddMemberParameters { MemberKind = RtGroupMemberKindEnum.User, MemberId = admin.RtId.ToString() }),
            "self-grant");

        (await MembersAsync(restGroup)).Should().BeEmpty();
        (await MembersAsync(methodGroup)).Should().BeEmpty();
    }

    // guard AB#7927: a built-in role the caller does not hold
    [Fact]
    public async Task Guard_RoleNotHeld_SetRolesWithABuiltInRoleTheCallerLacks_IsRefusedAlike()
    {
        var secret = await NewRoleAsync(builtIn: true);
        var (restGroup, methodGroup) = (await NewGroupAsync(), await NewGroupAsync());

        var problem = await ProblemAsync(
            await RestPutJsonAsync(AnyAdmin(), $"groups/{restGroup}/roles", new[] { await RoleIdAsync(secret) }),
            HttpStatusCode.Forbidden, "role-not-held");
        var method = await MethodAsync<GroupSetRolesHandler, GroupSetRolesParameters>(
            SystemIdentityCkIds.GroupSetRolesMethodId, methodGroup, Admin(),
            new GroupSetRolesParameters { RoleNames = [secret] });

        Forbidden(method, "role-not-held");
        problem.ToString().Should().Contain(secret);
        method.Failure!.Parameters.Should().Contain("roleNames", secret);
        (await RoleIdsAsync(restGroup)).Should().BeEmpty();
        (await RoleIdsAsync(methodGroup)).Should().BeEmpty();
    }

    // guard AB#7927: the last user administrator (REST answers 409, the method METHOD_FORBIDDEN; same reason). The two
    // transports run one after the other on a tenant that was cleared of administrators first.
    [Fact]
    public async Task Guard_LastAdministrator_RemovingTheOnlyHolderAndDroppingTheRole_IsRefusedAlike()
    {
        await ClearAdministratorsAsync();
        var restAdmin = await NewUserAsync();
        var restGroup = await NewGroupAsync(UserManagement);
        await AddMemberAsync(restGroup, restAdmin);

        await ProblemAsync(await RestDeleteAsync(AnyAdmin(), $"groups/{restGroup}/members/users/{restAdmin.RtId}"),
            HttpStatusCode.Conflict, "last-administrator");
        await ProblemAsync(await RestPutJsonAsync(AnyAdmin(), $"groups/{restGroup}/roles", Array.Empty<string>()),
            HttpStatusCode.Conflict, "last-administrator");
        (await MembersAsync(restGroup)).Should().Equal(restAdmin.RtId.ToString());
        (await RoleIdsAsync(restGroup)).Should().ContainSingle();

        await ClearAdministratorsAsync();
        var methodAdmin = await NewUserAsync();
        var methodGroup = await NewGroupAsync(UserManagement);
        await AddMemberAsync(methodGroup, methodAdmin);

        Forbidden(await MethodAsync<GroupRemoveMemberHandler, GroupRemoveMemberParameters>(
            SystemIdentityCkIds.GroupRemoveMemberMethodId, methodGroup, Admin(), new GroupRemoveMemberParameters
            {
                MemberKind = RtGroupMemberKindEnum.User, MemberId = methodAdmin.RtId.ToString()
            }), "last-administrator");
        Forbidden(await MethodAsync<GroupSetRolesHandler, GroupSetRolesParameters>(
            SystemIdentityCkIds.GroupSetRolesMethodId, methodGroup, Admin(),
            new GroupSetRolesParameters { RoleNames = [] }), "last-administrator");
        (await MembersAsync(methodGroup)).Should().Equal(methodAdmin.RtId.ToString());
        (await RoleIdsAsync(methodGroup)).Should().ContainSingle();
    }

    #region Helpers

    private Task<CkMethodOutcome> MethodAsync<THandler, TParameters>(string methodId, OctoObjectId group,
        CkMethodPrincipal principal, TParameters parameters)
        where THandler : ICkMethodHandler<TParameters> where TParameters : class =>
        InvokeAsync<THandler, TParameters>(methodId, "System.Identity/Group", group.ToString(), principal, parameters);

    private async Task SetRolesViaStoreAsync(OctoObjectId group, params string[] roles)
    {
        var ids = new List<string>();
        foreach (var role in roles)
        {
            ids.Add(await RoleIdAsync(role));
        }

        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IdentityServerPersistence.SystemStores.IGroupStore>()
            .SetRoleIdsAsync(group, ids);
    }

    #endregion
}
