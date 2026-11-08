using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8412: the REST endpoints <c>PUT users/{user}/roles</c>, <c>PUT/DELETE users/{user}/roles/{role}</c> and
///     <c>POST users/{user}/merge</c> are facades of <c>User.SetRoles</c>, <c>AddRole</c>, <c>RemoveRole</c> and <c>Merge</c>.
///     Real MongoDB, real identity host. The REST contract itself is covered unchanged by <see cref="RoleChangeGuardTests" />,
///     <see cref="UsersMergeTests" /> and <c>UserRoleMethodParityTests</c>; these tests prove that REST runs the method:
///     one <c>Identity.Method</c> audit event per REST call, the same result as the method called through the dispatcher
///     (the path of the GraphQL gateway), in-process, and independent of <c>Methods:Identity:EnablePasswordMethods</c>.
/// </summary>
public class UserRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";

    private readonly List<string> _restAudit = [];
    private readonly List<Dictionary<string, string>> _methodAudit = [];
    private readonly IEventRepository _events;
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public UserRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _events = Substitute.For<IEventRepository>();
        _events.When(e => e.StoreErrorEvent(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<string>(),
                Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                lock (_restAudit)
                {
                    _restAudit.Add(call.ArgAt<string>(2));
                }
            });
        _events.When(e => e.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(),
                Arg.Any<RtEventLevelsEnum>(), Arg.Any<string>(), Arg.Any<string?>(),
                Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                if (call.ArgAt<string?>(4) != IdentityMethodAuditWriter.Category)
                {
                    return;
                }

                lock (_methodAudit)
                {
                    _methodAudit.Add((call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                        .ToDictionary(d => d.Key, d => d.Value));
                }
            });
    }

    public static TheoryData<string> PasswordMethodSwitch => new() { "false", "true" };

    public static TheoryData<string> RoleEndpoints => new() { "add", "remove", "set" };

    /// <summary>Every derived host keeps configuration file watchers; dispose them (CI allows 128 inotify instances).</summary>
    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    #region One Identity.Method event per REST call

    [Theory]
    [MemberData(nameof(RoleEndpoints))]
    public async Task RestRoleChange_WritesExactlyOneIdentityMethodEvent_WithActorTargetAndRolesBeforeAndAfter(
        string endpoint)
    {
        var host = Host();
        var kept = await NewRoleAsync();
        var changed = await NewRoleAsync();
        var target = await NewUserAsync(endpoint == "add" ? [kept] : [kept, changed]);
        var actor = Guid.NewGuid().ToString("N");
        using var client = RestClient(host, actor, [UserManagement]);

        var response = endpoint switch
        {
            "add" => await client.PutAsync(TenantApiUrl($"users/{target.UserName}/roles/{changed}"), null,
                TestContext.Current.CancellationToken),
            "remove" => await client.DeleteAsync(TenantApiUrl($"users/{target.UserName}/roles/{changed}"),
                TestContext.Current.CancellationToken),
            _ => await client.PutAsJsonAsync(TenantApiUrl($"users/{target.UserName}/roles"),
                new[] { await RoleIdAsync(kept) }, TestContext.Current.CancellationToken)
        };

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should().BeEmpty();
        var records = MethodRecordsFor(target);
        records.Should().ContainSingle();
        var record = records[0];
        record["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        record["callerSubject"].Should().Be(actor);
        record["methodId"].Should().Be(endpoint switch
        {
            "add" => SystemIdentityCkIds.UserAddRoleMethodId,
            "remove" => SystemIdentityCkIds.UserRemoveRoleMethodId,
            _ => SystemIdentityCkIds.UserSetRolesMethodId
        });
        var both = string.Join(",", new[] { kept, changed }.Order(StringComparer.OrdinalIgnoreCase));
        record["rolesBefore"].ToUpperInvariant().Should()
            .Be(endpoint == "add" ? kept.ToUpperInvariant() : both.ToUpperInvariant());
        record["rolesAfter"].ToUpperInvariant().Should()
            .Be(endpoint == "add" ? both.ToUpperInvariant() : kept.ToUpperInvariant());
    }

    [Fact]
    public async Task RestRoleRefusal_WritesOneIdentityMethodEvent_AndKeepsTheRoleChangeRefusedRecord()
    {
        var host = Host();
        var secret = await NewRoleAsync(builtIn: true);
        var target = await NewUserAsync([]);
        var actor = Guid.NewGuid().ToString("N");
        using var client = RestClient(host, actor, [UserManagement]);
        int RestCount() { lock (_restAudit) { return _restAudit.Count; } }
        var before = RestCount();

        var response = await client.PutAsync(TenantApiUrl($"users/{target.UserName}/roles/{secret}"), null,
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        problem.GetProperty("code").GetString().Should().Be("role-not-held");
        var records = MethodRecordsFor(target);
        records.Should().ContainSingle();
        records[0]["outcome"].Should().Be("METHOD_FORBIDDEN");
        records[0]["reason"].Should().Be("role-not-held");
        RestCount().Should().Be(before + 1, "the AB#7914 refusal record of REST stays");
        (await DirectRolesAsync(target)).Should().BeEmpty();
    }

    [Fact]
    public async Task RestMerge_WritesExactlyOneIdentityMethodEvent()
    {
        var host = Host();
        var target = await NewUserAsync([]);
        var source = await NewUserAsync([]);
        var actor = Guid.NewGuid().ToString("N");
        using var client = RestClient(host, actor, [UserManagement]);

        var response = await client.PostAsJsonAsync(TenantApiUrl($"users/{target.UserName}/merge"),
            new { sourceUserName = source.UserName }, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var records = MethodRecordsFor(target);
        records.Should().ContainSingle();
        records[0]["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        records[0]["methodId"].Should().Be(SystemIdentityCkIds.UserMergeMethodId);
        records[0]["callerSubject"].Should().Be(actor);
        records[0]["sourceRtId"].Should().Be(source.RtId.ToString());
        (await FindUserAsync(source.UserName!)).Should().BeNull();
    }

    #endregion

    #region REST and the method give the same result

    [Fact]
    public async Task RestAndTheMethodThroughTheDispatcher_LeaveTheSameRoles_AndRefuseAlike()
    {
        var host = Host();
        var a = await NewRoleAsync();
        var b = await NewRoleAsync();
        var restUser = await NewUserAsync([]);
        var methodUser = await NewUserAsync([]);
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);
        var admin = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);
        var ct = TestContext.Current.CancellationToken;

        // AddRole
        (await client.PutAsync(TenantApiUrl($"users/{restUser.UserName}/roles/{a}"), null, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.UserAddRoleMethodId, methodUser,
            new UserAddRoleParameters { RoleName = a })).Success.Should().BeTrue();
        (await DirectRolesAsync(restUser)).Should().Equal(await DirectRolesAsync(methodUser));

        // AddRole of an assigned role: 400 / ROLE_ALREADY_ASSIGNED, nothing changes
        (await client.PutAsync(TenantApiUrl($"users/{restUser.UserName}/roles/{a}"), null, ct)).StatusCode.Should()
            .Be(HttpStatusCode.BadRequest);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.UserAddRoleMethodId, methodUser,
            new UserAddRoleParameters { RoleName = a })).Error!.Code.Should().Be("ROLE_ALREADY_ASSIGNED");

        // SetRoles
        (await client.PutAsJsonAsync(TenantApiUrl($"users/{restUser.UserName}/roles"), new[] { await RoleIdAsync(b) },
            ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.UserSetRolesMethodId, methodUser,
            new UserSetRolesParameters { RoleNames = [b] })).Success.Should().BeTrue();
        (await DirectRolesAsync(restUser)).Should().Equal(await DirectRolesAsync(methodUser)).And
            .Equal(b.ToUpperInvariant());

        // RemoveRole
        (await client.DeleteAsync(TenantApiUrl($"users/{restUser.UserName}/roles/{b}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.UserRemoveRoleMethodId, methodUser,
            new UserRemoveRoleParameters { RoleName = b })).Success.Should().BeTrue();
        (await DirectRolesAsync(restUser)).Should().BeEmpty();
        (await DirectRolesAsync(methodUser)).Should().BeEmpty();

        // self-grant: 403 problem "self-grant" / METHOD_FORBIDDEN reason self-grant
        using var self = RestClient(host, restUser.RtId.ToString(), [UserManagement, "TenantManagement"]);
        var restRefusal = await self.PutAsync(TenantApiUrl($"users/{restUser.UserName}/roles/TenantManagement"), null,
            ct);
        restRefusal.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await restRefusal.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("code").GetString().Should()
            .Be("self-grant");
        var methodRefusal = await DispatchAsync(host,
            new CkMethodPrincipal(methodUser.RtId.ToString(), [UserManagement, "TenantManagement"], ["octo_api"]),
            SystemIdentityCkIds.UserAddRoleMethodId, methodUser, new UserAddRoleParameters { RoleName = "TenantManagement" });
        methodRefusal.Error!.Code.Should().Be("METHOD_FORBIDDEN");
        methodRefusal.Error.Parameters.Should().Contain("reason", "self-grant");
        (await DirectRolesAsync(restUser)).Should().BeEmpty();
        (await DirectRolesAsync(methodUser)).Should().BeEmpty();
    }

    [Fact]
    public async Task RestMergeAndTheMethodThroughTheDispatcher_DeleteTheSource_AndRefuseASelfMergeAlike()
    {
        var host = Host();
        var restTarget = await NewUserAsync([]);
        var restSource = await NewUserAsync([]);
        var methodTarget = await NewUserAsync([]);
        var methodSource = await NewUserAsync([]);
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);
        var admin = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);
        var ct = TestContext.Current.CancellationToken;

        (await client.PostAsJsonAsync(TenantApiUrl($"users/{restTarget.UserName}/merge"),
            new { sourceUserName = restSource.UserName }, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.UserMergeMethodId, methodTarget,
            new UserMergeParameters { SourceUserName = methodSource.UserName! })).Success.Should().BeTrue();
        (await FindUserAsync(restSource.UserName!)).Should().BeNull();
        (await FindUserAsync(methodSource.UserName!)).Should().BeNull();

        var restSelf = await client.PostAsJsonAsync(TenantApiUrl($"users/{restTarget.UserName}/merge"),
            new { sourceUserName = restTarget.UserName }, ct);
        restSelf.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await restSelf.Content.ReadAsStringAsync(ct)).Should().Contain("Cannot merge a user into itself.");
        (await DispatchAsync(host, admin, SystemIdentityCkIds.UserMergeMethodId, methodTarget,
            new UserMergeParameters { SourceUserName = methodTarget.UserName! })).Error!.Code.Should()
            .Be(UserMergeHandler.CannotMergeIntoItself);
    }

    #endregion

    #region Transport and switch

    [Fact]
    public void TheFacadeMethods_RunInThisProcess()
    {
        var transport = Host().Services.GetRequiredService<ICkInProcessMethodTransport>();

        transport.CanHandle(SystemIdentityCkIds.UserSetRolesMethodId).Should().BeTrue();
        transport.CanHandle(SystemIdentityCkIds.UserAddRoleMethodId).Should().BeTrue();
        transport.CanHandle(SystemIdentityCkIds.UserRemoveRoleMethodId).Should().BeTrue();
        transport.CanHandle(SystemIdentityCkIds.UserMergeMethodId).Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(PasswordMethodSwitch))]
    public async Task TheFourEndpoints_Work_WhateverEnablePasswordMethodsSays(string enablePasswordMethods)
    {
        var host = Host(enablePasswordMethods);
        var role = await NewRoleAsync();
        var target = await NewUserAsync([]);
        var source = await NewUserAsync([]);
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);
        var ct = TestContext.Current.CancellationToken;

        (await client.PutAsync(TenantApiUrl($"users/{target.UserName}/roles/{role}"), null, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await client.DeleteAsync(TenantApiUrl($"users/{target.UserName}/roles/{role}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await client.PutAsJsonAsync(TenantApiUrl($"users/{target.UserName}/roles"), new[] { await RoleIdAsync(role) },
            ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DirectRolesAsync(target)).Should().Equal(role.ToUpperInvariant());
        (await client.PostAsJsonAsync(TenantApiUrl($"users/{target.UserName}/merge"),
            new { sourceUserName = source.UserName }, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await FindUserAsync(source.UserName!)).Should().BeNull();
    }

    [Fact]
    public async Task RemoveRole_OfARoleHeldOnlyThroughAGroup_StaysOkWithoutAChange()
    {
        var host = Host();
        var role = await NewRoleAsync();
        var target = await NewUserAsync([]);
        await AddGroupRoleAsync(target, role);
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);
        var ct = TestContext.Current.CancellationToken;

        // REST contract: a group-inherited role counts as held for AddRole (400) and RemoveRole (200, no change)
        (await client.PutAsync(TenantApiUrl($"users/{target.UserName}/roles/{role}"), null, ct)).StatusCode.Should()
            .Be(HttpStatusCode.BadRequest);
        (await client.DeleteAsync(TenantApiUrl($"users/{target.UserName}/roles/{role}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DirectRolesAsync(target)).Should().BeEmpty();
        MethodRecordsFor(target).Should().ContainSingle()
            .Which["outcome"].Should().Be(UserRoleMethodErrors.RoleNotAssigned);
    }

    #endregion

    #region Helpers

    private WebApplicationFactory<Program> Host(string? enablePasswordMethods = null)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (enablePasswordMethods != null)
            {
                b.UseSetting("Methods:Identity:EnablePasswordMethods", enablePasswordMethods);
            }

            b.ConfigureTestServices(services => services.AddSingleton(_events));
        });
        _hosts.Add(host);
        return host;
    }

    private static HttpClient RestClient(WebApplicationFactory<Program> host, string subject, string[] roles)
    {
        var client = host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, subject);
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        foreach (var role in roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        return client;
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync<TParameters>(WebApplicationFactory<Program> host,
        CkMethodPrincipal caller, string methodId, RtUser target, TParameters parameters)
    {
        var dispatcher = host.Services.GetRequiredService<ICkMethodDispatcher>();
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = IdentityMethodFacade.UserCkTypeId,
            TargetRtId = target.RtId.ToString(),
            ParametersJson = JsonSerializer.Serialize(parameters, CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await dispatcher.InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private List<Dictionary<string, string>> MethodRecordsFor(RtUser target)
    {
        lock (_methodAudit)
        {
            return _methodAudit.Where(d => d.GetValueOrDefault("targetRtId") == target.RtId.ToString()).ToList();
        }
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private async Task<string> NewRoleAsync(bool builtIn = false)
    {
        var name = NewName(builtIn ? TestPlatformRoles.Prefix + "b8412" : "c8412");
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

    private async Task<string> RoleIdAsync(string name)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name))!.RtId
            .ToString();
    }

    private async Task<RtUser> NewUserAsync(string[] directRoles)
    {
        var user = await CreateTestUserAsync(NewName("u8412"));
        foreach (var role in directRoles)
        {
            using var scope = CreateScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var fresh = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
            (await userManager.AddToRoleAsync(fresh, role.ToUpperInvariant())).Succeeded.Should().BeTrue();
        }

        return user;
    }

    private async Task AddGroupRoleAsync(RtUser user, string role)
    {
        using var scope = CreateScope();
        var groups = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        var name = NewName("g8412");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name,
            NormalizedGroupName = name.ToUpperInvariant()
        };
        await groups.StoreAsync(group);
        await groups.SetRoleIdsAsync(group.RtId, [await RoleIdAsync(role)]);
        await groups.AddMemberUserAsync(group.RtId, user.RtId.ToString());
    }

    private async Task<string[]> DirectRolesAsync(RtUser user)
    {
        using var scope = CreateScope();
        var store = (OctoUserStore)scope.ServiceProvider.GetRequiredService<IUserStore<RtUser>>();
        return (await store.GetDirectRolesAsync(user)).Select(r => r.ToUpperInvariant()).Order().ToArray();
    }

    private async Task<RtUser?> FindUserAsync(string userName)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
    }

    #endregion
}
