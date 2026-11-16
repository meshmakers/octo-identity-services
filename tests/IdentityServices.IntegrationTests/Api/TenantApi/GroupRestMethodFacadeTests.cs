using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     The REST group role and membership endpoints are facades of <c>Group.SetRoles</c>, <c>Group.AddMember</c>,
///     <c>Group.RemoveMember</c>, <c>Group.AddChildGroup</c> and <c>Group.RemoveChildGroup</c> (System.Identity 3.3.0).
///     Real MongoDB, real identity host. The REST contract itself stays covered by <see cref="GroupRoleChangeGuardTests" />
///     and the group method suites; these tests prove that REST runs the method: in-process, outside the request (no request
///     state at handler entry), exactly one <c>Identity.Method</c> event per REST call, the same end state as the method called
///     through the dispatcher (the GraphQL path), the REST policy (403), and the cycle refusal with today's status and body.
/// </summary>
public class GroupRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public GroupRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public static TheoryData<string> Endpoints => new()
    {
        "setRoles", "addUser", "removeUser", "addClient", "removeClient", "addGroup", "removeGroup"
    };

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task EveryEndpoint_RunsItsMethodInProcess_OutsideTheRequest_WithExactlyOneIdentityMethodEvent(
        string endpoint)
    {
        var host = Host();
        var group = await NewGroupAsync();
        var caller = FacadeCaller.User(UserManagement);
        using var client = caller.Client(host);
        var (response, methodId) = await CallAsync(client, endpoint, group);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should().BeEmpty();
        var events = _audit.For(methodId, group.RtId.ToString());
        events.Should().ContainSingle();
        events[0]["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        events[0]["callerSubject"].Should().Be(caller.Subject);
        _probe.Calls.Should().BeGreaterThan(0, "the method ran through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task ACallerWithoutTheRestPolicyRole_Is403_AndNoMethodRuns(string endpoint)
    {
        var host = Host();
        var group = await NewGroupAsync();
        using var client = FacadeCaller.User("TenantManagement").Client(host);

        var (response, methodId) = await CallAsync(client, endpoint, group);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        _audit.For(methodId, group.RtId.ToString()).Should().BeEmpty();
    }

    [Fact]
    public async Task AGroupInItself_Is400WithTodaysBody_AndOneGroupCycleEvent()
    {
        var host = Host();
        var group = await NewGroupAsync();
        using var client = FacadeCaller.User(UserManagement).Client(host);

        var response = await client.PutAsync(TenantApiUrl($"groups/{group.RtId}/members/groups/{group.RtId}"), null,
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should()
            .Be("A group cannot be a member of itself.", "the body of the earlier REST answer");
        var events = _audit.For(SystemIdentityCkIds.GroupAddChildGroupMethodId, group.RtId.ToString());
        events.Should().ContainSingle().Which["outcome"].Should().Be(GroupChildGroupErrors.GroupCycle);
        (await ChildGroupsAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task AGroupInADescendant_Is400WithTodaysBody_AndChangesNothing()
    {
        var host = Host();
        var top = await NewGroupAsync();
        var middle = await NewGroupAsync();
        var bottom = await NewGroupAsync();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        (await client.PutAsync(TenantApiUrl($"groups/{top.RtId}/members/groups/{middle.RtId}"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await client.PutAsync(TenantApiUrl($"groups/{middle.RtId}/members/groups/{bottom.RtId}"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);

        var response = await client.PutAsync(TenantApiUrl($"groups/{bottom.RtId}/members/groups/{top.RtId}"), null, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(ct)).Should()
            .Be("Adding this group would create a circular reference.", "the body of the earlier REST answer");
        _audit.For(SystemIdentityCkIds.GroupAddChildGroupMethodId, bottom.RtId.ToString()).Should().ContainSingle()
            .Which["cycle"].Should().Be(GroupChildGroupErrors.CycleDescendant);
        (await ChildGroupsAsync(bottom)).Should().BeEmpty();
    }

    [Fact]
    public async Task RestAndTheMethodThroughTheDispatcher_LeaveTheSameChildGroups_AndRefuseACycleAlike()
    {
        var host = Host();
        var restParent = await NewGroupAsync();
        var methodParent = await NewGroupAsync();
        var child = await NewGroupAsync();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var admin = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);
        var ct = TestContext.Current.CancellationToken;

        (await client.PutAsync(TenantApiUrl($"groups/{restParent.RtId}/members/groups/{child.RtId}"), null, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.GroupAddChildGroupMethodId, methodParent,
            new GroupAddChildGroupParameters { ChildGroupId = child.RtId.ToString() })).Success.Should().BeTrue();
        (await ChildGroupsAsync(restParent)).Should().Equal(await ChildGroupsAsync(methodParent)).And
            .Equal(child.RtId.ToString());

        // a repeated add: REST 200 without a change / CHILD_GROUP_ALREADY_IN_GROUP
        (await client.PutAsync(TenantApiUrl($"groups/{restParent.RtId}/members/groups/{child.RtId}"), null, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.GroupAddChildGroupMethodId, methodParent,
                new GroupAddChildGroupParameters { ChildGroupId = child.RtId.ToString() })).Error!.Code.Should()
            .Be(GroupChildGroupErrors.ChildGroupAlreadyInGroup);

        // the cycle: REST 400 / GROUP_CYCLE
        (await client.PutAsync(TenantApiUrl($"groups/{child.RtId}/members/groups/{restParent.RtId}"), null, ct))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var cycle = await DispatchAsync(host, admin, SystemIdentityCkIds.GroupAddChildGroupMethodId, child,
            new GroupAddChildGroupParameters { ChildGroupId = methodParent.RtId.ToString() });
        cycle.Error!.Code.Should().Be(GroupChildGroupErrors.GroupCycle);
        cycle.Error.Parameters.Should().Contain(GroupChildGroupErrors.CycleKindParameter,
            GroupChildGroupErrors.CycleDescendant);

        (await client.DeleteAsync(TenantApiUrl($"groups/{restParent.RtId}/members/groups/{child.RtId}"), ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.GroupRemoveChildGroupMethodId, methodParent,
            new GroupRemoveChildGroupParameters { ChildGroupId = child.RtId.ToString() })).Success.Should().BeTrue();
        (await ChildGroupsAsync(restParent)).Should().BeEmpty();
        (await ChildGroupsAsync(methodParent)).Should().BeEmpty();
    }

    [Fact]
    public async Task RemovingANonMember_StaysOkWithoutAChange_AndAnUnknownChildGroupIs404()
    {
        var host = Host();
        var group = await NewGroupAsync();
        var other = await NewGroupAsync();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        (await client.DeleteAsync(TenantApiUrl($"groups/{group.RtId}/members/groups/{other.RtId}"), ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await client.DeleteAsync(TenantApiUrl($"groups/{group.RtId}/members/users/{OctoObjectId.GenerateNewId()}"),
            ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await client.PutAsync(TenantApiUrl($"groups/{group.RtId}/members/groups/{OctoObjectId.GenerateNewId()}"), null,
            ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.PutAsync(TenantApiUrl($"groups/{OctoObjectId.GenerateNewId()}/members/groups/{other.RtId}"), null,
            ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task IntendedRestChanges_UnknownRoleIdAndUnknownUser_Are404_AndChangeNothing()
    {
        // Before the facade both were an unhandled engine error (500); the documented answer is 404 without a change.
        var host = Host();
        var group = await NewGroupAsync();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        (await client.PutAsJsonAsync(TenantApiUrl($"groups/{group.RtId}/roles"),
            new[] { OctoObjectId.GenerateNewId().ToString() }, ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.PutAsync(TenantApiUrl($"groups/{group.RtId}/members/users/{OctoObjectId.GenerateNewId()}"), null,
            ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.PutAsync(TenantApiUrl($"groups/{group.RtId}/members/users/not-an-id"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);

        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        (await store.GetRoleIdsAsync(group.RtId)).Should().BeEmpty();
        (await store.GetMemberUserIdsAsync(group.RtId)).Should().BeEmpty();
    }

    [Fact]
    public void TheGroupMethods_RunInThisProcess()
    {
        var transport = Host().Services.GetRequiredService<ICkInProcessMethodTransport>();

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.GroupSetRolesMethodId, SystemIdentityCkIds.GroupAddMemberMethodId,
                     SystemIdentityCkIds.GroupRemoveMemberMethodId, SystemIdentityCkIds.GroupAddChildGroupMethodId,
                     SystemIdentityCkIds.GroupRemoveChildGroupMethodId
                 })
        {
            transport.CanHandle(methodId).Should().BeTrue(methodId);
        }
    }

    #region Helpers

    private WebApplicationFactory<Program> Host()
    {
        var host = Factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddSingleton(_audit.Events);
            services.AddSingleton<ICkInProcessAmbientStateProbe>(_probe);
            services.AddSingleton<IStartupFilter, MarkRequestsStartupFilter>();
        }));
        _hosts.Add(host);
        return host;
    }

    /// <summary>Calls one of the seven endpoints with a valid change; returns the response and the method it serves.</summary>
    private async Task<(HttpResponseMessage Response, string MethodId)> CallAsync(HttpClient client, string endpoint,
        RtGroup group)
    {
        var ct = TestContext.Current.CancellationToken;
        var path = $"groups/{group.RtId}";
        switch (endpoint)
        {
            case "setRoles":
                return (await client.PutAsJsonAsync(TenantApiUrl($"{path}/roles"), new[] { await NewRoleIdAsync() }, ct),
                    SystemIdentityCkIds.GroupSetRolesMethodId);
            case "addUser":
                return (await client.PutAsync(TenantApiUrl($"{path}/members/users/{(await NewUserAsync()).RtId}"), null,
                    ct), SystemIdentityCkIds.GroupAddMemberMethodId);
            case "removeUser":
            {
                var user = await NewUserAsync();
                await WithGroupStoreAsync(s => s.AddMemberUserAsync(group.RtId, user.RtId.ToString()));
                return (await client.DeleteAsync(TenantApiUrl($"{path}/members/users/{user.RtId}"), ct),
                    SystemIdentityCkIds.GroupRemoveMemberMethodId);
            }
            case "addClient":
                return (await client.PutAsync(TenantApiUrl($"{path}/members/clients/{(await NewClientAsync()).ClientId}"),
                    null, ct), SystemIdentityCkIds.GroupAddMemberMethodId);
            case "removeClient":
            {
                var member = await NewClientAsync();
                await WithGroupStoreAsync(s => s.AddMemberClientAsync(group.RtId, member.RtId.ToString()));
                return (await client.DeleteAsync(TenantApiUrl($"{path}/members/clients/{member.ClientId}"), ct),
                    SystemIdentityCkIds.GroupRemoveMemberMethodId);
            }
            case "addGroup":
                return (await client.PutAsync(TenantApiUrl($"{path}/members/groups/{(await NewGroupAsync()).RtId}"), null,
                    ct), SystemIdentityCkIds.GroupAddChildGroupMethodId);
            default:
            {
                var child = await NewGroupAsync();
                await WithGroupStoreAsync(s => s.AddMemberGroupAsync(group.RtId, child.RtId.ToString()));
                return (await client.DeleteAsync(TenantApiUrl($"{path}/members/groups/{child.RtId}"), ct),
                    SystemIdentityCkIds.GroupRemoveChildGroupMethodId);
            }
        }
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync<TParameters>(WebApplicationFactory<Program> host,
        CkMethodPrincipal caller, string methodId, RtGroup target, TParameters parameters)
    {
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = IdentityMethodFacade.GroupCkTypeId,
            TargetRtId = target.RtId.ToString(),
            ParametersJson = JsonSerializer.Serialize(parameters, CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private async Task<RtGroup> NewGroupAsync()
    {
        var name = NewName("gf");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        };
        await WithGroupStoreAsync(s => s.StoreAsync(group));
        return group;
    }

    private async Task<string> NewRoleIdAsync()
    {
        using var scope = CreateScope();
        var role = new RtRoleBuilder().WithName(NewName("rf")).Build();
        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().CreateAsync(role)).Succeeded.Should()
            .BeTrue();
        return role.RtId.ToString();
    }

    private Task<RtUser> NewUserAsync() => CreateTestUserAsync(NewName("uf"));

    private Task<RtClient> NewClientAsync() => CreateTestClientAsync(NewName("cf"));

    private async Task WithGroupStoreAsync(Func<IGroupStore, Task> action)
    {
        using var scope = CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IGroupStore>());
    }

    private async Task<string[]> ChildGroupsAsync(RtGroup group)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberGroupIdsAsync(group.RtId))
            .Order().ToArray();
    }

    #endregion
}
