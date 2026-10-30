using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Methods.Handlers;
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

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7776: <c>User.SetRoles</c>, <c>User.AddRole</c> and <c>User.RemoveRole</c> served by the identity service. Real
///     MongoDB, the real identity host (default configuration: the role methods are not behind the password switch); the
///     handlers run in a fresh DI scope without an HTTP request, as on the bus. Each refusal of the REST endpoints
///     (<c>UsersController</c>, see <c>UserRoleMethodParityTests</c> for the side by side table) has a test here.
/// </summary>
public class UserRoleMethodTests : IntegrationTestBase
{
    private const string UserManagement = "UserManagement";

    private readonly WebApplicationFactory<Program> _host;
    private readonly List<(string Category, string Level, Dictionary<string, string> Details)> _events = [];

    public UserRoleMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        var events = Substitute.For<IEventRepository>();
        events.When(e => e.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(),
                Arg.Any<RtEventLevelsEnum>(), Arg.Any<string>(), Arg.Any<string?>(),
                Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                lock (_events)
                {
                    _events.Add((call.ArgAt<string?>(4) ?? "", call.ArgAt<RtEventLevelsEnum>(2).ToString(),
                        (call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                        .ToDictionary(d => d.Key, d => d.Value)));
                }
            });

        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddSingleton(events);
        }));
    }

    #region Hosting

    [Fact]
    public void TheRoleHandlers_AreHosted_WithTheDefaultConfiguration_AndTheSwitchOnlyGatesThePasswordMethod()
    {
        using var scope = _host.Services.CreateScope();

        _host.Services.GetService<ICkMethodHandlerInvoker>().Should().NotBeNull();
        scope.ServiceProvider.GetService<UserSetRolesHandler>().Should().NotBeNull();
        scope.ServiceProvider.GetService<UserAddRoleHandler>().Should().NotBeNull();
        scope.ServiceProvider.GetService<UserRemoveRoleHandler>().Should().NotBeNull();
        scope.ServiceProvider.GetService<UserChangePasswordHandler>().Should().BeNull("password methods stay behind the switch");
    }

    #endregion

    #region SetRoles

    [Fact]
    public async Task SetRoles_ReplacesTheDirectRoles_AndTheNextTokenSourceSeesThem()
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);

        var outcome = await SetRolesAsync(user, Admin(), roles[1]);

        outcome.IsSuccess.Should().BeTrue();
        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[1]);
        // what the token claims are built from (OctoTokenClaimsService reads the effective roles of the user store)
        (await EffectiveRolesAsync(user)).Should().Contain(roles[1]).And.NotContain(roles[0]);
    }

    [Fact]
    public async Task SetRoles_KeepsRolesThatStay_AddsNewOnes_AndMatchesNamesCaseInsensitively()
    {
        var (user, roles) = await NewUserWithRolesAsync(3, assign: [0, 1]);

        var outcome = await SetRolesAsync(user, Admin(), roles[1].ToUpperInvariant(), roles[2].ToLowerInvariant(),
            roles[2]);

        outcome.IsSuccess.Should().BeTrue();
        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[1], roles[2]);
    }

    [Fact]
    public async Task SetRoles_EmptyList_RemovesEveryDirectRole()
    {
        var (user, _) = await NewUserWithRolesAsync(2, assign: [0, 1]);

        (await SetRolesAsync(user, Admin())).IsSuccess.Should().BeTrue();

        (await DirectRolesAsync(user)).Should().BeEmpty();
    }

    [Fact]
    public async Task SetRoles_AnUnknownRole_IsRoleNotFound_AndChangesNothing_NotEvenTheKnownRoles()
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);

        var outcome = await SetRolesAsync(user, Admin(), roles[1], "NoSuchRole");

        outcome.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        outcome.Failure.Parameters.Should().Contain("roleName", "NoSuchRole");
        (await DirectRolesAsync(user)).Should().BeEquivalentTo(new[] { roles[0] }, "unlike REST, which removes first, nothing is changed");
    }

    [Fact]
    public async Task SetRoles_OnlyTheDirectRolesOfTheTarget_AreTouched_AnotherUserIsNot()
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);
        var (other, _) = await NewUserWithRolesAsync(0, assign: [], existing: roles);
        await AddRoleDirectAsync(other, roles[0]);

        (await SetRolesAsync(user, Admin(), roles[1])).IsSuccess.Should().BeTrue();

        (await DirectRolesAsync(other)).Should().BeEquivalentTo(roles[0]);
    }

    #endregion

    #region AddRole

    [Fact]
    public async Task AddRole_AssignsTheRole_KeepingTheOthers()
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);

        var outcome = await AddRoleAsync(user, Admin(), roles[1].ToLowerInvariant());

        outcome.IsSuccess.Should().BeTrue();
        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[0], roles[1]);
    }

    [Fact]
    public async Task AddRole_AlreadyAssigned_IsRoleAlreadyAssigned()
    {
        var (user, roles) = await NewUserWithRolesAsync(1, assign: [0]);

        (await AddRoleAsync(user, Admin(), roles[0])).Failure!.Code.Should().Be("ROLE_ALREADY_ASSIGNED");

        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[0]);
    }

    [Fact]
    public async Task AddRole_AnUnknownRole_IsRoleNotFound()
    {
        var (user, _) = await NewUserWithRolesAsync(0, assign: []);

        var outcome = await AddRoleAsync(user, Admin(), "NoSuchRole");

        outcome.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        (await DirectRolesAsync(user)).Should().BeEmpty();
    }

    #endregion

    #region RemoveRole

    [Fact]
    public async Task RemoveRole_RemovesTheRole_KeepingTheOthers()
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0, 1]);

        var outcome = await RemoveRoleAsync(user, Admin(), roles[0].ToUpperInvariant());

        outcome.IsSuccess.Should().BeTrue();
        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[1]);
    }

    [Fact]
    public async Task RemoveRole_NotAssigned_IsRoleNotAssigned()
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);

        (await RemoveRoleAsync(user, Admin(), roles[1])).Failure!.Code.Should().Be("ROLE_NOT_ASSIGNED");

        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[0]);
    }

    [Fact]
    public async Task RemoveRole_AnUnknownRole_IsRoleNotFound()
    {
        var (user, roles) = await NewUserWithRolesAsync(1, assign: [0]);

        (await RemoveRoleAsync(user, Admin(), "NoSuchRole")).Failure!.Code.Should().Be("ROLE_NOT_FOUND");

        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[0]);
    }

    #endregion

    #region Caller guards (the handler repeats the REST write policy on the validated principal)

    public static TheoryData<string, CkMethodPrincipal?> RefusedCallers => new()
    {
        { "no principal", null },
        { "no role", new CkMethodPrincipal("someone", [], ["octo_api"]) },
        { "another administrative role", new CkMethodPrincipal("someone", ["TenantManagement", "AdminPanelManagement"], ["octo_api"]) },
        { "UserManagement without the scope", new CkMethodPrincipal("someone", [UserManagement], []) },
        { "UserManagement with the read-only scope", new CkMethodPrincipal("someone", [UserManagement], ["octo_api.read_only"]) },
        { "UserManagement with a scope of another case", new CkMethodPrincipal("someone", [UserManagement], ["OCTO_API"]) }
    };

    [Theory]
    [MemberData(nameof(RefusedCallers))]
    public async Task EveryMethod_RefusesACallerThatTheRestPolicyWouldRefuse_AndChangesNothing(string caller,
        CkMethodPrincipal? principal)
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);

        var results = new[]
        {
            await SetRolesAsync(user, principal, roles[1]),
            await AddRoleAsync(user, principal, roles[1]),
            await RemoveRoleAsync(user, principal, roles[0])
        };

        foreach (var outcome in results)
        {
            outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN", caller);
            outcome.Failure.Parameters.Should().BeEquivalentTo(new Dictionary<string, string> { ["reason"] = "role-required" });
        }

        (await DirectRolesAsync(user)).Should().BeEquivalentTo(roles[0]);
    }

    [Fact]
    public async Task AnAdministrator_MayGrantAnyRole_ToAnyUser_IncludingHimself_AsRestDoes()
    {
        // Parity, not a feature: REST has no escalation rule beyond the UserManagement role (see the PR for the decision).
        var (admin, roles) = await NewUserWithRolesAsync(1, assign: []);
        var principal = new CkMethodPrincipal(admin.RtId.ToString(), [UserManagement], ["octo_api"]);

        (await AddRoleAsync(admin, principal, roles[0])).IsSuccess.Should().BeTrue();

        (await DirectRolesAsync(admin)).Should().BeEquivalentTo(roles[0]);
    }

    [Fact]
    public async Task AServiceToken_WithUserManagement_IsAllowed_AsRestAllowsClientRoles()
    {
        var (user, roles) = await NewUserWithRolesAsync(1, assign: []);

        var outcome = await AddRoleAsync(user, new CkMethodPrincipal(null, [UserManagement], ["octo_api"], "svc"), roles[0]);

        outcome.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task AForgedCaller_WithoutAValidToken_IsRejectedByTheHost_AndTheHandlerIsNotCalled()
    {
        var ct = TestContext.Current.CancellationToken;
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);
        var invoker = _host.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        foreach (var (methodId, json) in new[]
                 {
                     (SystemIdentityCkIds.UserSetRolesMethodId, JsonSerializer.Serialize(new { roleNames = new[] { roles[1] } })),
                     (SystemIdentityCkIds.UserAddRoleMethodId, JsonSerializer.Serialize(new { roleName = roles[1] })),
                     (SystemIdentityCkIds.UserRemoveRoleMethodId, JsonSerializer.Serialize(new { roleName = roles[0] }))
                 })
        {
            foreach (var token in new string?[] { null, "", "not-a-jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." })
            {
                var request = Request(methodId, user.RtId.ToString(), token, json) with
                {
                    // the informational Caller of a bus message is never believed
                    Caller = new CkMethodCaller { SubjectId = "admin", Roles = [UserManagement] }
                };

                var response = await invoker.InvokeAsync(request, ct);

                response.Success.Should().BeFalse(methodId);
                response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
            }
        }

        (await DirectRolesAsync(user)).Should().BeEquivalentTo(new[] { roles[0] }, "nothing changed");
    }

    #endregion

    #region Target

    [Fact]
    public async Task AMissingTarget_IsTargetNotFound_ForEveryMethod()
    {
        var missing = "507f1f77bcf86cd799439011";

        (await InvokeAsync<UserSetRolesHandler, UserSetRolesParameters>(missing, Admin(),
            new UserSetRolesParameters { RoleNames = [] })).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        (await InvokeAsync<UserAddRoleHandler, UserAddRoleParameters>(missing, Admin(),
            new UserAddRoleParameters { RoleName = "x" })).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        (await InvokeAsync<UserRemoveRoleHandler, UserRemoveRoleParameters>(missing, Admin(),
            new UserRemoveRoleParameters { RoleName = "x" })).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
    }

    [Fact]
    public async Task ATargetThatIsNotAnId_IsTargetNotFound()
    {
        var outcome = await InvokeAsync<UserAddRoleHandler, UserAddRoleParameters>("not-an-id", Admin(),
            new UserAddRoleParameters { RoleName = "x" });

        outcome.Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
    }

    #endregion

    #region Audit

    [Fact]
    public async Task EveryCall_WritesOneAuditEvent_WithActorTargetOutcomeAndTheRolesBeforeAndAfter()
    {
        var (user, roles) = await NewUserWithRolesAsync(2, assign: [0]);
        var actor = Guid.NewGuid().ToString("N");
        var principal = new CkMethodPrincipal(actor, [UserManagement], ["octo_api"]);
        var before = AuditCount();

        await SetRolesAsync(user, principal, roles[1]); // success
        await AddRoleAsync(user, principal, roles[1]); // ROLE_ALREADY_ASSIGNED
        await RemoveRoleAsync(user, new CkMethodPrincipal(actor, [], ["octo_api"]), roles[1]); // METHOD_FORBIDDEN

        var written = AuditEvents().Where(e => e.Details["callerSubject"] == actor).ToList();
        AuditCount().Should().Be(before + 3, "one event per call, success and refusal alike");
        written.Select(e => e.Details["outcome"]).Should()
            .Equal("SUCCESS", "ROLE_ALREADY_ASSIGNED", "METHOD_FORBIDDEN");
        written.Should().OnlyContain(e => e.Details["targetRtId"] == user.RtId.ToString());
        written[0].Level.Should().Be("Information");
        written[0].Details["rolesBefore"].Should().Be(roles[0]);
        written[0].Details["rolesAfter"].Should().Be(roles[1]);
        written[1].Level.Should().Be("Warning");
        written[1].Details["rolesBefore"].Should().Be(roles[1]);
        written[1].Details["rolesAfter"].Should().Be(roles[1], "a refused call changed nothing");
        written[2].Details.Should().NotContainKey("rolesBefore", "a refused caller does not even see the roles");
        written.Select(e => e.Details["methodId"]).Should().Equal(
            SystemIdentityCkIds.UserSetRolesMethodId, SystemIdentityCkIds.UserAddRoleMethodId,
            SystemIdentityCkIds.UserRemoveRoleMethodId);
    }

    #endregion

    #region Helpers

    private int AuditCount() => AuditEvents().Count();

    private IEnumerable<(string Category, string Level, Dictionary<string, string> Details)> AuditEvents()
    {
        lock (_events)
        {
            return _events.Where(e => e.Category == IdentityMethodAuditWriter.Category).ToList();
        }
    }

    private static CkMethodPrincipal Admin() => new(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    /// <summary>Creates <paramref name="roleCount" /> roles (or uses <paramref name="existing" />) and a user holding the roles at <paramref name="assign" />.</summary>
    private async Task<(RtUser User, string[] Roles)> NewUserWithRolesAsync(int roleCount, int[] assign,
        string[]? existing = null)
    {
        var names = existing ?? Enumerable.Range(0, roleCount).Select(_ => NewName("r7776")).ToArray();
        using var scope = CreateScope();
        if (existing == null)
        {
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
            foreach (var name in names)
            {
                (await roleManager.CreateAsync(new RtRoleBuilder().WithName(name).Build())).Succeeded.Should().BeTrue();
            }
        }

        var user = await CreateTestUserAsync(NewName("u7776"));
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        foreach (var index in assign)
        {
            (await userManager.AddToRoleAsync(user, names[index].ToUpperInvariant())).Succeeded.Should().BeTrue();
        }

        return (user, names);
    }

    private async Task AddRoleDirectAsync(RtUser user, string roleName)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>()
            .AddToRoleAsync(user, roleName.ToUpperInvariant());
    }

    private async Task<string[]> DirectRolesAsync(RtUser user)
    {
        using var scope = CreateScope();
        var store = (OctoUserStore)scope.ServiceProvider.GetRequiredService<IUserStore<RtUser>>();
        return (await store.GetDirectRolesAsync(user)).ToArray();
    }

    private async Task<string[]> EffectiveRolesAsync(RtUser user)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().GetRolesAsync(user)).ToArray();
    }

    private Task<CkMethodOutcome> SetRolesAsync(RtUser user, CkMethodPrincipal? principal, params string[] roles) =>
        InvokeAsync<UserSetRolesHandler, UserSetRolesParameters>(user.RtId.ToString(), principal,
            new UserSetRolesParameters { RoleNames = roles });

    private Task<CkMethodOutcome> AddRoleAsync(RtUser user, CkMethodPrincipal? principal, string role) =>
        InvokeAsync<UserAddRoleHandler, UserAddRoleParameters>(user.RtId.ToString(), principal,
            new UserAddRoleParameters { RoleName = role });

    private Task<CkMethodOutcome> RemoveRoleAsync(RtUser user, CkMethodPrincipal? principal, string role) =>
        InvokeAsync<UserRemoveRoleHandler, UserRemoveRoleParameters>(user.RtId.ToString(), principal,
            new UserRemoveRoleParameters { RoleName = role });

    /// <summary>Runs the handler in a new DI scope without an HTTP request, with the principal the host validated.</summary>
    private async Task<CkMethodOutcome> InvokeAsync<THandler, TParameters>(string target, CkMethodPrincipal? principal,
        TParameters parameters)
        where THandler : ICkMethodHandler<TParameters> where TParameters : class
    {
        using var scope = _host.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<THandler>(scope.ServiceProvider);
        var methodId = typeof(THandler) == typeof(UserSetRolesHandler) ? SystemIdentityCkIds.UserSetRolesMethodId
            : typeof(THandler) == typeof(UserAddRoleHandler) ? SystemIdentityCkIds.UserAddRoleMethodId
            : SystemIdentityCkIds.UserRemoveRoleMethodId;
        var context = new CkMethodContext<TParameters>(Request(methodId, target, null, "{}"), parameters)
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, TestContext.Current.CancellationToken);
    }

    private CkMethodRequest Request(string methodId, string target, string? token, string parametersJson) =>
        new(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = "System.Identity/User",
            TargetRtId = target,
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
            CallerAccessToken = token,
            ParametersJson = parametersJson
        };

    #endregion
}
