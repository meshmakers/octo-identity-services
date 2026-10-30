using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
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
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#7914: the role change guard of the user role endpoints (REST) and the methods <c>User.SetRoles</c> /
///     <c>AddRole</c> / <c>RemoveRole</c>. Real MongoDB, real identity host. Every scenario of the escalation rules runs
///     against both transports (<see cref="Transports" />) and must answer alike: REST 403/409 problem+json with the
///     <c>code</c> extension, methods <c>METHOD_FORBIDDEN</c> with the parameter <c>reason</c>. The last-administrator
///     tests first remove every effective <c>UserManagement</c> holder of the test database, so exactly the holders
///     a test creates exist.
/// </summary>
public class RoleChangeGuardTests : IntegrationTestBase
{
    private const string UserManagement = "UserManagement";

    private readonly WebApplicationFactory<Program> _host;
    private readonly List<string> _restAudit = [];
    private readonly List<Dictionary<string, string>> _methodAudit = [];

    public RoleChangeGuardTests(CustomWebApplicationFactory factory) : base(factory)
    {
        var events = Substitute.For<IEventRepository>();
        events.When(e => e.StoreErrorEvent(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<string>(),
                Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                lock (_restAudit)
                {
                    _restAudit.Add(call.ArgAt<string>(2));
                }
            });
        events.When(e => e.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(),
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
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services => services.AddSingleton(events)));
    }

    public static TheoryData<string> Transports => new() { "rest", "method" };

    #region Self-grant

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task SelfGrant_AddingARoleToOneself_IsRefused_AndChangesNothing(string transport)
    {
        var admin = await NewUserAsync();
        var custom = await NewRoleAsync();
        var t = Transport(transport);
        var self = new Caller(admin.RtId.ToString(), null, [UserManagement]);

        var add = await t.AddAsync(self, admin, custom);
        var set = await t.SetAsync(self, admin, custom);

        add.Should().Be(Refused("self-grant"));
        set.Should().Be(Refused("self-grant"));
        (await DirectRolesAsync(admin)).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task SelfGrant_SetRolesWithAnExtraRole_IsRefused_ButTheUnchangedListSucceeds_AndOwnRolesCanBeRemoved(
        string transport)
    {
        var a = await NewRoleAsync();
        var b = await NewRoleAsync();
        var admin = await NewUserAsync(a, b);
        var t = Transport(transport);
        var self = new Caller(admin.RtId.ToString(), null, [UserManagement]);
        var extra = await NewRoleAsync();

        (await t.SetAsync(self, admin, a, b, extra)).Should().Be(Refused("self-grant"));
        (await DirectRolesAsync(admin)).Should().BeEquivalentTo(a.ToUpperInvariant(), b.ToUpperInvariant());

        // Studio saves the own profile with the unchanged direct-role list: no difference, nothing refused, nothing written.
        (await t.SetAsync(self, admin, b, a)).Should().Be(Accepted);
        (await DirectRolesAsync(admin)).Should().BeEquivalentTo(a.ToUpperInvariant(), b.ToUpperInvariant());

        // removing one's own role is not an escalation
        (await t.RemoveAsync(self, admin, a)).Should().Be(Accepted);
        (await t.SetAsync(self, admin)).Should().Be(Accepted);
        (await DirectRolesAsync(admin)).Should().BeEmpty();
    }

    #endregion

    #region Grant only what you hold

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task BuiltInRole_TheCallerDoesNotHold_IsRefused_WithTheRoleNames_ButHeldAndCustomRolesAreGranted(
        string transport)
    {
        var secret = await NewRoleAsync(builtIn: true);
        var held = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var target = await NewUserAsync();
        var t = Transport(transport);
        var admin = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement, held]);

        (await t.AddAsync(admin, target, secret)).Should().Be(Refused("role-not-held", secret));
        (await t.SetAsync(admin, target, secret, custom)).Should().Be(Refused("role-not-held", secret));
        (await DirectRolesAsync(target)).Should().BeEmpty();

        (await t.AddAsync(admin, target, held)).Should().Be(Accepted, "the caller holds the built-in role");
        (await t.AddAsync(admin, target, custom)).Should().Be(Accepted, "custom roles are free");
        (await DirectRolesAsync(target)).Should().BeEquivalentTo(held.ToUpperInvariant(), custom.ToUpperInvariant());
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task SetRoles_IsCheckedOnTheDifference_ARoleThatStaysIsNotJudged_AndItMayBeRemoved(string transport)
    {
        var secret = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var target = await NewUserAsync(secret);
        var t = Transport(transport);
        var admin = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);

        (await t.SetAsync(admin, target, secret, custom)).Should().Be(Accepted);
        (await DirectRolesAsync(target)).Should().BeEquivalentTo(secret.ToUpperInvariant(), custom.ToUpperInvariant());

        (await t.SetAsync(admin, target, custom)).Should().Be(Accepted, "removing a role is never an escalation");
        (await DirectRolesAsync(target)).Should().BeEquivalentTo(custom.ToUpperInvariant());

        await AddDirectAsync(target, secret);
        (await t.RemoveAsync(admin, target, secret)).Should().Be(Accepted);
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task ClientCaller_IsCheckedWithTheRolesOfTheClient_AndIsNeverSelf(string transport)
    {
        var builtIn = await NewRoleAsync(builtIn: true);
        var target = await NewUserAsync();
        var t = Transport(transport);
        var withoutRole = new Caller(null, "svc-" + Guid.NewGuid().ToString("N"), [UserManagement]);
        var withRole = new Caller(null, "svc-" + Guid.NewGuid().ToString("N"), [UserManagement, builtIn]);

        (await t.AddAsync(withoutRole, target, builtIn)).Should().Be(Refused("role-not-held", builtIn));
        (await DirectRolesAsync(target)).Should().BeEmpty();
        (await t.AddAsync(withRole, target, builtIn)).Should().Be(Accepted);
        (await DirectRolesAsync(target)).Should().BeEquivalentTo(builtIn.ToUpperInvariant());
    }

    [Fact]
    public async Task Rest_SetRoles_WithAnUnknownRoleId_Is404_AndLeavesTheDirectRolesUnchanged()
    {
        var a = await NewRoleAsync();
        var b = await NewRoleAsync();
        var target = await NewUserAsync(a);
        var admin = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);

        using var client = RestClient(admin);
        var ids = new List<string> { (await RoleIdAsync(b)), "507f1f77bcf86cd799439011" };
        var response = await client.PutAsJsonAsync(TenantApiUrl($"users/{target.UserName}/roles"), ids,
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await DirectRolesAsync(target)).Should().BeEquivalentTo(a.ToUpperInvariant());
    }

    #endregion

    #region Last user administrator

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task LastAdministrator_RemovingUserManagement_IsRefused_ByRemoveAndSet_AndNothingIsWritten(
        string transport)
    {
        await ClearAdministratorsAsync();
        var other = await NewRoleAsync();
        var admin = await NewUserAsync(UserManagement, other);
        var t = Transport(transport);
        var caller = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);

        (await t.RemoveAsync(caller, admin, UserManagement)).Should().Be(Refused("last-administrator"));
        (await t.SetAsync(caller, admin, other)).Should().Be(Refused("last-administrator"));
        (await DirectRolesAsync(admin)).Should().BeEquivalentTo(UserManagement.ToUpperInvariant(),
            other.ToUpperInvariant());

        // keeping UserManagement is fine
        (await t.SetAsync(caller, admin, UserManagement)).Should().Be(Accepted);
        (await DirectRolesAsync(admin)).Should().BeEquivalentTo(UserManagement.ToUpperInvariant());
    }

    [Fact]
    public async Task LastAdministrator_Rest_DeleteAndMergeSource_AreRefused_AndNothingIsWritten()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync(UserManagement);
        var keeper = await NewUserAsync();
        var caller = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);

        using var client = RestClient(caller);
        var delete = await client.DeleteAsync(TenantApiUrl($"users/{admin.UserName}"),
            TestContext.Current.CancellationToken);
        var merge = await client.PostAsJsonAsync(TenantApiUrl($"users/{keeper.UserName}/merge"),
            new { sourceUserName = admin.UserName }, TestContext.Current.CancellationToken);

        await AssertProblemAsync(delete, HttpStatusCode.Conflict, "last-administrator");
        await AssertProblemAsync(merge, HttpStatusCode.Conflict, "last-administrator");
        (await FindUserAsync(admin.UserName!)).Should().NotBeNull();
        (await DirectRolesAsync(admin)).Should().BeEquivalentTo(UserManagement.ToUpperInvariant());
    }

    [Fact]
    public async Task LastAdministrator_Rest_DeleteAndMerge_OfAUserWhoIsNotTheLastHolder_Succeed()
    {
        await ClearAdministratorsAsync();
        var one = await NewUserAsync(UserManagement);
        var two = await NewUserAsync(UserManagement);
        var plain = await NewUserAsync();
        var caller = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);
        using var client = RestClient(caller);

        (await client.DeleteAsync(TenantApiUrl($"users/{one.UserName}"), TestContext.Current.CancellationToken))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        // two is the last holder now, a plain user is no administrator and may be deleted or merged away
        (await client.PostAsJsonAsync(TenantApiUrl($"users/{two.UserName}/merge"), new { sourceUserName = plain.UserName },
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await FindUserAsync(two.UserName!)).Should().NotBeNull();
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task LastAdministrator_ASecondHolder_ThroughAGroup_NestedGroup_OrMapping_AllowsTheRemoval(
        string transport)
    {
        var t = Transport(transport);
        var caller = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);

        // through the TenantOwners-like group
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync(UserManagement);
        var member = await NewUserAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddGroupMemberAsync(group, member);
        (await t.RemoveAsync(caller, admin, UserManagement)).Should().Be(Accepted, "a group member holds it too");

        // through a group that contains a group that carries the role
        await ClearAdministratorsAsync();
        admin = await NewUserAsync(UserManagement);
        var parent = await NewGroupAsync();
        var child = await NewGroupAsync(UserManagement);
        await AddChildGroupAsync(parent, child);
        await AddGroupMemberAsync(parent, await NewUserAsync());
        (await t.RemoveAsync(caller, admin, UserManagement)).Should().Be(Accepted, "a nested group grants it");

        // through an external tenant user mapping of a cross-tenant (xt_) shadow user
        await ClearAdministratorsAsync();
        admin = await NewUserAsync(UserManagement);
        await NewShadowUserWithMappedUserManagementAsync();
        (await t.RemoveAsync(caller, admin, UserManagement)).Should().Be(Accepted, "a shadow user holds it through its mapping");
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task LastAdministrator_AClientHoldingUserManagement_DoesNotCount(string transport)
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync(UserManagement);
        await NewClientWithRoleAsync(UserManagement);
        var group = await NewGroupAsync(UserManagement);
        await AddGroupMemberAsync(group, await NewClientAsync());

        var caller = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);
        (await Transport(transport).RemoveAsync(caller, admin, UserManagement)).Should()
            .Be(Refused("last-administrator"));
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task LastAdministrator_ADirectHolderAndHolderThroughAGroup_IsNotTheLastWhenTheDirectRoleGoes(
        string transport)
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync(UserManagement);
        var group = await NewGroupAsync(UserManagement);
        await AddGroupMemberAsync(group, admin);
        var caller = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);

        // the user still holds UserManagement through the group after the direct edge is gone
        (await Transport(transport).RemoveAsync(caller, admin, UserManagement)).Should().Be(Accepted);
    }

    [Theory]
    [MemberData(nameof(Transports))]
    public async Task LastAdministrator_ATenantWithoutAnyHolder_IsNotBlockedFurther(string transport)
    {
        await ClearAdministratorsAsync();
        var role = await NewRoleAsync();
        var user = await NewUserAsync(role);
        var caller = new Caller(Guid.NewGuid().ToString("N"), null, [UserManagement]);

        (await Transport(transport).RemoveAsync(caller, user, role)).Should().Be(Accepted);
    }

    #endregion

    #region Audit and contract

    [Fact]
    public async Task EveryRestRefusal_WritesOneAuditRecord_WithCallerTargetReasonAndRoleNames_AndNoSecrets()
    {
        var secret = await NewRoleAsync(builtIn: true);
        var target = await NewUserAsync();
        var actor = Guid.NewGuid().ToString("N");
        using var client = RestClient(new Caller(actor, null, [UserManagement]));
        int Count() { lock (_restAudit) { return _restAudit.Count; } }
        var before = Count();

        var response = await client.PutAsync(TenantApiUrl($"users/{target.UserName}/roles/{secret}"), null,
            TestContext.Current.CancellationToken);

        var problem = await AssertProblemAsync(response, HttpStatusCode.Forbidden, "role-not-held");
        problem.GetProperty("roleNames").EnumerateArray().Select(e => e.GetString()).Should().Equal(secret);
        problem.GetProperty("title").GetString().Should().Contain(secret).And.Contain("do not hold");
        Count().Should().Be(before + 1);
        string record;
        lock (_restAudit)
        {
            record = _restAudit[^1];
        }

        record.Should().Contain("Identity.RoleChangeRefused").And.Contain("role-not-held")
            .And.Contain(actor).And.Contain(target.RtId.ToString()).And.Contain(secret);
        record.ToLowerInvariant().Should().NotContain("bearer").And.NotContain("password").And.NotContain("test-token");
    }

    [Fact]
    public async Task EveryMethodRefusal_IsAuditedWithTheOutcomeAndTheReason()
    {
        var secret = await NewRoleAsync(builtIn: true);
        var target = await NewUserAsync();
        var actor = Guid.NewGuid().ToString("N");

        (await Transport("method").AddAsync(new Caller(actor, null, [UserManagement]), target, secret)).Should()
            .Be(Refused("role-not-held", secret));

        Dictionary<string, string> record;
        lock (_methodAudit)
        {
            record = _methodAudit.Last(d => d.GetValueOrDefault("callerSubject") == actor);
        }

        record["outcome"].Should().Be("METHOD_FORBIDDEN");
        record["reason"].Should().Be("role-not-held");
        record["roleNames"].Should().Be(secret);
        record["targetRtId"].Should().Be(target.RtId.ToString());
    }

    [Fact]
    public async Task TheGuard_IsNotCalledFromTheUserStoreOrTheUserManager_SoSetupSeedsAndGrantsStayUnchanged()
    {
        using var scope = CreateScope();
        // role assignments of setup, blueprint seeds, one-time grants, provisioning and login rules go through these types
        foreach (var type in new[] { typeof(OctoUserStore), typeof(OctoUserManager) })
        {
            type.GetConstructors().SelectMany(c => c.GetParameters())
                .Should().NotContain(p => p.ParameterType.Name == "IRoleChangeGuard", type.Name);
        }

        var user = await NewUserAsync();
        var role = await NewRoleAsync(builtIn: true);
        // an assignment through the user manager (what those flows use) is not judged by the guard: self + built-in role
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        (await userManager.AddToRoleAsync(user, role.ToUpperInvariant())).Succeeded.Should().BeTrue();
    }

    #endregion

    #region Helpers

    private static readonly Result Accepted = new(true, null, []);

    private static Result Refused(string reason, params string[] roleNames) => new(false, reason, roleNames);

    private sealed record Caller(string? Subject, string? ClientId, string[] Roles);

    /// <summary>The outcome of one call, the same shape for both transports.</summary>
    private sealed record Result(bool Ok, string? Code, string[] RoleNames)
    {
        public bool Equals(Result? other) => other != null && Ok == other.Ok && Code == other.Code &&
                                              RoleNames.SequenceEqual(other.RoleNames);

        public override int GetHashCode() => HashCode.Combine(Ok, Code);
    }

    private abstract class TransportBase
    {
        public abstract Task<Result> AddAsync(Caller caller, RtUser target, string role);
        public abstract Task<Result> RemoveAsync(Caller caller, RtUser target, string role);
        public abstract Task<Result> SetAsync(Caller caller, RtUser target, params string[] roles);
    }

    private TransportBase Transport(string name) =>
        name == "rest" ? new RestTransport(this) : new MethodTransport(this);

    private sealed class RestTransport(RoleChangeGuardTests test) : TransportBase
    {
        public override async Task<Result> AddAsync(Caller caller, RtUser target, string role)
        {
            using var client = test.RestClient(caller);
            return await ToResultAsync(await client.PutAsync(test.TenantApiUrl($"users/{target.UserName}/roles/{role}"),
                null, TestContext.Current.CancellationToken));
        }

        public override async Task<Result> RemoveAsync(Caller caller, RtUser target, string role)
        {
            using var client = test.RestClient(caller);
            return await ToResultAsync(await client.DeleteAsync(
                test.TenantApiUrl($"users/{target.UserName}/roles/{role}"), TestContext.Current.CancellationToken));
        }

        public override async Task<Result> SetAsync(Caller caller, RtUser target, params string[] roles)
        {
            var ids = new List<string>();
            foreach (var role in roles)
            {
                ids.Add(await test.RoleIdAsync(role));
            }

            using var client = test.RestClient(caller);
            return await ToResultAsync(await client.PutAsJsonAsync(test.TenantApiUrl($"users/{target.UserName}/roles"),
                ids, TestContext.Current.CancellationToken));
        }

        private static async Task<Result> ToResultAsync(HttpResponseMessage response)
        {
            if (response.IsSuccessStatusCode)
            {
                return Accepted;
            }

            if (response.Content.Headers.ContentType?.MediaType != "application/problem+json")
            {
                return new Result(false, ((int)response.StatusCode).ToString(), []);
            }

            var json = await response.Content.ReadFromJsonAsync<JsonElement>();
            var names = json.TryGetProperty("roleNames", out var array)
                ? array.EnumerateArray().Select(e => e.GetString()!).ToArray()
                : [];
            return new Result(false, json.GetProperty("code").GetString(), names);
        }
    }

    private sealed class MethodTransport(RoleChangeGuardTests test) : TransportBase
    {
        public override Task<Result> AddAsync(Caller caller, RtUser target, string role) =>
            test.InvokeAsync<UserAddRoleHandler, UserAddRoleParameters>(caller, target,
                new UserAddRoleParameters { RoleName = role }, SystemIdentityCkIds.UserAddRoleMethodId);

        public override Task<Result> RemoveAsync(Caller caller, RtUser target, string role) =>
            test.InvokeAsync<UserRemoveRoleHandler, UserRemoveRoleParameters>(caller, target,
                new UserRemoveRoleParameters { RoleName = role }, SystemIdentityCkIds.UserRemoveRoleMethodId);

        public override Task<Result> SetAsync(Caller caller, RtUser target, params string[] roles) =>
            test.InvokeAsync<UserSetRolesHandler, UserSetRolesParameters>(caller, target,
                new UserSetRolesParameters { RoleNames = roles }, SystemIdentityCkIds.UserSetRolesMethodId);
    }

    private async Task<Result> InvokeAsync<THandler, TParameters>(Caller caller, RtUser target, TParameters parameters,
        string methodId) where THandler : ICkMethodHandler<TParameters> where TParameters : class
    {
        using var scope = _host.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<THandler>(scope.ServiceProvider);
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = "System.Identity/User",
            TargetRtId = target.RtId.ToString(),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
            ParametersJson = "{}"
        };
        var outcome = await handler.HandleAsync(new CkMethodContext<TParameters>(request, parameters)
        {
            CallerPrincipal = new CkMethodPrincipal(caller.Subject, caller.Roles, ["octo_api"], caller.ClientId)
        }, TestContext.Current.CancellationToken);

        if (outcome.IsSuccess)
        {
            return Accepted;
        }

        outcome.Failure!.Code.Should().Be(caller.Roles.Length > 0 && outcome.Failure.Parameters?.ContainsKey("reason") == true
            ? "METHOD_FORBIDDEN"
            : outcome.Failure.Code);
        var reason = outcome.Failure.Parameters != null && outcome.Failure.Parameters.TryGetValue("reason", out var r)
            ? r
            : outcome.Failure.Code;
        var names = outcome.Failure.Parameters != null && outcome.Failure.Parameters.TryGetValue("roleNames", out var n)
            ? n.Split(',')
            : [];
        return new Result(false, reason, names);
    }

    private HttpClient RestClient(Caller caller)
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, caller.Subject ?? "service");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        foreach (var role in caller.Roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        if (caller.ClientId != null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, caller.ClientId);
        }

        return client;
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

    /// <summary>A role; a built-in one carries an rtWellKnownName like the roles of the Bootstrap blueprint.</summary>
    private async Task<string> NewRoleAsync(bool builtIn = false)
    {
        var name = NewName(builtIn ? "b7914" : "c7914");
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

    /// <summary>The built-in UserManagement role of the tenant (seeded by the blueprint; created when missing).</summary>
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

    private async Task<string> RoleIdAsync(string name)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name))!.RtId
            .ToString();
    }

    /// <summary>A user holding the given direct roles (a name that is not a role yet is created as a custom role).</summary>
    private async Task<RtUser> NewUserAsync(params string[] directRoles)
    {
        if (directRoles.Contains(UserManagement))
        {
            await EnsureUserManagementAsync();
        }

        var user = await CreateTestUserAsync(NewName("u7914"));
        foreach (var role in directRoles)
        {
            await AddDirectAsync(user, role);
        }

        return user;
    }

    private async Task AddDirectAsync(RtUser user, string role)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var fresh = (await userManager.FindByIdAsync(user.RtId.ToString()))!; // the instance may be stale (rtVersion)
        var result = await userManager.AddToRoleAsync(fresh, role.ToUpperInvariant());
        result.Succeeded.Should().BeTrue(string.Join(";", result.Errors.Select(e => e.Code)));
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

    private async Task<OctoObjectId> NewGroupAsync(params string[] roles)
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        var name = NewName("g7914");
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

    private async Task AddGroupMemberAsync(OctoObjectId group, RtUser user)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberUserAsync(group, user.RtId.ToString());
    }

    private async Task AddGroupMemberAsync(OctoObjectId group, OctoObjectId clientRtId)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberClientAsync(group, clientRtId.ToString());
    }

    private async Task AddChildGroupAsync(OctoObjectId parent, OctoObjectId child)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberGroupAsync(parent, child.ToString());
    }

    private async Task<OctoObjectId> NewClientAsync()
    {
        var client = await CreateTestClientAsync(NewName("c7914"));
        return client.RtId;
    }

    private async Task NewClientWithRoleAsync(string role)
    {
        var clientRtId = await NewClientAsync();
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IClientRoleStore>().AddRoleAsync(clientRtId, role);
    }

    /// <summary>A cross-tenant shadow user (xt_) of this tenant whose mapping carries the UserManagement role id.</summary>
    private async Task NewShadowUserWithMappedUserManagementAsync()
    {
        var roleId = (await EnsureUserManagementAsync()).RtId.ToString();
        var sourceUser = NewName("home");
        var shadowName = CrossTenantShadowUserName.Build(NormalizedSystemTenantId, sourceUser);
        using var scope = CreateScope();
        (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>()
            .CreateAsync(new RtUserBuilder().WithUserName(shadowName).WithEmail($"{shadowName}@example.com").Build()))
            .Succeeded.Should().BeTrue();
        await scope.ServiceProvider.GetRequiredService<IExternalTenantUserMappingStore>().StoreAsync(
            new RtExternalTenantUserMapping
            {
                RtId = OctoObjectId.GenerateNewId(),
                SourceTenantId = NormalizedSystemTenantId,
                SourceUserId = OctoObjectId.GenerateNewId().ToString(),
                SourceUserName = sourceUser,
                MappedRoleIds = new AttributeStringValueList([roleId])
            });
    }

    #endregion
}
