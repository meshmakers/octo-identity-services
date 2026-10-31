using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Methods.Handlers;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7779: <c>Group.AddMember</c>, <c>Group.RemoveMember</c> and <c>Group.SetRoles</c> served by the identity service. Each
///     refusal of the REST endpoints of <c>GroupsController</c> has a test here; the side by side table is
///     <see cref="GroupMethodParityTests" />.
/// </summary>
public class GroupMethodTests(CustomWebApplicationFactory factory) : GroupMethodTestBase(factory)
{
    #region Hosting

    [Fact]
    public void TheGroupHandlers_AreHosted_WithTheDefaultConfiguration()
    {
        using var scope = Host.Services.CreateScope();

        Host.Services.GetService<ICkMethodHandlerInvoker>().Should().NotBeNull();
        scope.ServiceProvider.GetService<GroupAddMemberHandler>().Should().NotBeNull();
        scope.ServiceProvider.GetService<GroupRemoveMemberHandler>().Should().NotBeNull();
        scope.ServiceProvider.GetService<GroupSetRolesHandler>().Should().NotBeNull();
    }

    #endregion

    #region AddMember

    [Fact]
    public async Task AddMember_User_StoresTheMembership_AndTheNextTokenSourceSeesTheGroupRoles()
    {
        var role = await NewRoleAsync();
        var group = await NewGroupAsync(role);
        var user = await NewUserAsync();

        var outcome = await AddAsync(group, Admin(), RtGroupMemberKindEnum.User, user.RtId.ToString());

        outcome.IsSuccess.Should().BeTrue();
        (await MembersAsync(group)).Should().Equal(user.RtId.ToString());
        // what the token claims are built from (OctoTokenClaimsService reads the effective roles of the user store)
        (await EffectiveRolesAsync(user)).Should().Contain(r => r.Equals(role, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AddMember_Client_StoresTheMembership_ByRtId_AndByOAuthClientId()
    {
        var group = await NewGroupAsync();
        var byRtId = await NewClientAsync();
        var byClientId = await NewClientAsync();

        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.Client, byRtId.RtId.ToString())).IsSuccess.Should().BeTrue();
        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.Client, byClientId.ClientId!)).IsSuccess.Should().BeTrue();

        (await ClientMembersAsync(group)).Should().BeEquivalentTo(byRtId.RtId.ToString(), byClientId.RtId.ToString());
    }

    [Fact]
    public async Task AddMember_AnUnknownMember_IsMemberNotFound_ForUsersAndClients()
    {
        var group = await NewGroupAsync();
        var missing = OctoObjectId.GenerateNewId().ToString();

        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.User, missing)).Failure!.Code.Should().Be("MEMBER_NOT_FOUND");
        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.User, "not-an-id")).Failure!.Code.Should().Be("MEMBER_NOT_FOUND");
        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.User, "")).Failure!.Code.Should().Be("MEMBER_NOT_FOUND");
        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.Client, missing)).Failure!.Code.Should().Be("MEMBER_NOT_FOUND");
        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.Client, "no-such-client")).Failure!.Code.Should()
            .Be("MEMBER_NOT_FOUND");
        // a user id given as client is not a client
        var user = await NewUserAsync();
        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.Client, user.RtId.ToString())).Failure!.Code.Should()
            .Be("MEMBER_NOT_FOUND");
        (await MembersAsync(group)).Should().BeEmpty();
        (await ClientMembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task AddMember_AMemberAlready_IsMemberAlreadyInGroup()
    {
        var group = await NewGroupAsync();
        var user = await NewUserAsync();
        await AddMemberAsync(group, user);

        (await AddAsync(group, Admin(), RtGroupMemberKindEnum.User, user.RtId.ToString())).Failure!.Code.Should()
            .Be("MEMBER_ALREADY_IN_GROUP");
    }

    #endregion

    #region RemoveMember

    [Fact]
    public async Task RemoveMember_User_RemovesTheMembership_AndTheGroupRolesAreNoLongerEffective()
    {
        var role = await NewRoleAsync();
        var group = await NewGroupAsync(role);
        var user = await NewUserAsync();
        await AddMemberAsync(group, user);
        (await EffectiveRolesAsync(user)).Should().Contain(r => r.Equals(role, StringComparison.OrdinalIgnoreCase));

        var outcome = await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.User, user.RtId.ToString());

        outcome.IsSuccess.Should().BeTrue();
        (await MembersAsync(group)).Should().BeEmpty();
        (await EffectiveRolesAsync(user)).Should().NotContain(r => r.Equals(role, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RemoveMember_Client_RemovesTheMembership_WithoutTheGuard()
    {
        var group = await NewGroupAsync(await NewRoleAsync(builtIn: true));
        var client = await NewClientAsync();
        await AddClientMemberAsync(group, client.RtId);

        // a caller who holds none of the built-in roles may still take a client out (REST: no guard for clients)
        var outcome = await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.Client, client.RtId.ToString());

        outcome.IsSuccess.Should().BeTrue();
        (await ClientMembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task RemoveMember_NotAMember_IsMemberNotInGroup_AndAMissingMemberIsMemberNotFound()
    {
        var group = await NewGroupAsync();
        var user = await NewUserAsync();

        (await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.User, user.RtId.ToString())).Failure!.Code.Should()
            .Be("MEMBER_NOT_IN_GROUP");
        (await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.User, OctoObjectId.GenerateNewId().ToString()))
            .Failure!.Code.Should().Be("MEMBER_NOT_FOUND");
        (await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.Client, OctoObjectId.GenerateNewId().ToString()))
            .Failure!.Code.Should().Be("MEMBER_NOT_FOUND");
    }

    #endregion

    #region SetRoles

    [Fact]
    public async Task SetRoles_ReplacesTheRoles_ByName_CaseInsensitive_AndDeduplicated()
    {
        var a = await NewRoleAsync();
        var b = await NewRoleAsync();
        var c = await NewRoleAsync();
        var group = await NewGroupAsync(a, b);

        var outcome = await SetRolesAsync(group, Admin(), b.ToUpperInvariant(), c.ToLowerInvariant(), c);

        outcome.IsSuccess.Should().BeTrue();
        (await RoleIdsAsync(group)).Should().Equal(new[] { await RoleIdAsync(b), await RoleIdAsync(c) }.Order());
    }

    [Fact]
    public async Task SetRoles_EmptyList_RemovesEveryRole()
    {
        var group = await NewGroupAsync(await NewRoleAsync());

        (await SetRolesAsync(group, Admin())).IsSuccess.Should().BeTrue();

        (await RoleIdsAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task SetRoles_AnUnknownRole_IsRoleNotFound_AndChangesNothing()
    {
        var a = await NewRoleAsync();
        var b = await NewRoleAsync();
        var group = await NewGroupAsync(a);

        var outcome = await SetRolesAsync(group, Admin(), b, "NoSuchRole");

        outcome.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        outcome.Failure.Parameters.Should().Contain("roleName", "NoSuchRole");
        (await RoleIdsAsync(group)).Should().Equal(await RoleIdAsync(a));
    }

    [Fact]
    public async Task SetRoles_TheNextTokenSourceOfAMemberSeesTheNewGroupRoles()
    {
        var a = await NewRoleAsync();
        var b = await NewRoleAsync();
        var group = await NewGroupAsync(a);
        var user = await NewUserAsync();
        await AddMemberAsync(group, user);

        (await SetRolesAsync(group, Admin(), b)).IsSuccess.Should().BeTrue();

        var roles = await EffectiveRolesAsync(user);
        roles.Should().Contain(r => r.Equals(b, StringComparison.OrdinalIgnoreCase))
            .And.NotContain(r => r.Equals(a, StringComparison.OrdinalIgnoreCase));
    }

    #endregion

    #region The role change guard (AB#7927), the same decisions as REST

    [Fact]
    public async Task AddMember_SelfGrant_IsRefused_AndNothingIsWritten()
    {
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(await NewRoleAsync());
        var principal = new CkMethodPrincipal(admin.RtId.ToString(), [UserManagement], ["octo_api"]);

        var outcome = await AddAsync(group, principal, RtGroupMemberKindEnum.User, admin.RtId.ToString());

        AssertForbidden(outcome, "self-grant");
        (await MembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task AddMember_SelfGrant_IntoAGroupWithoutRoles_IsAllowed()
    {
        var admin = await NewUserAsync();
        var group = await NewGroupAsync();
        var principal = new CkMethodPrincipal(admin.RtId.ToString(), [UserManagement], ["octo_api"]);

        (await AddAsync(group, principal, RtGroupMemberKindEnum.User, admin.RtId.ToString())).IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task AddMember_AClientIntoAGroupWithABuiltInRoleTheCallerLacks_IsRefused_RoleNotHeld()
    {
        var secret = await NewRoleAsync(builtIn: true);
        var group = await NewGroupAsync(secret);
        var client = await NewClientAsync();

        var outcome = await AddAsync(group, Admin(), RtGroupMemberKindEnum.Client, client.RtId.ToString());

        AssertForbidden(outcome, "role-not-held");
        outcome.Failure!.Parameters.Should().Contain("roleNames", secret);
        (await ClientMembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task SetRoles_ABuiltInRoleTheCallerLacks_IsRefused_ButHeldAndCustomRolesSucceed()
    {
        var secret = await NewRoleAsync(builtIn: true);
        var held = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var group = await NewGroupAsync();
        var principal = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement, held], ["octo_api"]);

        var refused = await SetRolesAsync(group, principal, secret, custom);
        AssertForbidden(refused, "role-not-held");
        refused.Failure!.Parameters.Should().Contain("roleNames", secret);
        (await RoleIdsAsync(group)).Should().BeEmpty();

        (await SetRolesAsync(group, principal, held, custom)).IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task SetRoles_SelfGrant_ThroughAGroupTheCallerBelongsTo_IsRefused()
    {
        var admin = await NewUserAsync();
        var group = await NewGroupAsync();
        await AddMemberAsync(group, admin);
        var extra = await NewRoleAsync();
        var principal = new CkMethodPrincipal(admin.RtId.ToString(), [UserManagement], ["octo_api"]);

        AssertForbidden(await SetRolesAsync(group, principal, extra), "self-grant");
        (await RoleIdsAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task LastAdministrator_RemovingTheOnlyHolderFromTheGroup_IsRefused_WithASecondHolderItSucceeds()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddMemberAsync(group, admin);

        AssertForbidden(await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.User, admin.RtId.ToString()),
            "last-administrator");
        (await MembersAsync(group)).Should().Equal(admin.RtId.ToString());

        await NewUserAsync(UserManagement);
        (await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.User, admin.RtId.ToString())).IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task LastAdministrator_TheGroupLosesTheRole_IsRefused()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddMemberAsync(group, admin);

        AssertForbidden(await SetRolesAsync(group, Admin()), "last-administrator");

        (await RoleIdsAsync(group)).Should().ContainSingle();
    }

    [Fact]
    public async Task LastAdministrator_AClientMemberDoesNotCount_ButItsRemovalIsNotJudged()
    {
        await ClearAdministratorsAsync();
        var admin = await NewUserAsync();
        var group = await NewGroupAsync(UserManagement);
        await AddMemberAsync(group, admin);
        var client = await NewClientAsync();
        await AddClientMemberAsync(group, client.RtId);

        AssertForbidden(await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.User, admin.RtId.ToString()),
            "last-administrator");
        (await RemoveAsync(group, Admin(), RtGroupMemberKindEnum.Client, client.RtId.ToString())).IsSuccess.Should()
            .BeTrue();
    }

    #endregion

    #region Caller guards (the handler repeats the REST write policy on the validated principal)

    public static TheoryData<string, CkMethodPrincipal?> RefusedCallers => new()
    {
        { "no principal", null },
        { "no role", new CkMethodPrincipal("someone", [], ["octo_api"]) },
        { "another administrative role", new CkMethodPrincipal("someone", ["TenantManagement"], ["octo_api"]) },
        { "UserManagement without the scope", new CkMethodPrincipal("someone", [UserManagement], []) },
        { "UserManagement with the read-only scope", new CkMethodPrincipal("someone", [UserManagement], ["octo_api.read_only"]) },
        { "UserManagement with a scope of another case", new CkMethodPrincipal("someone", [UserManagement], ["OCTO_API"]) }
    };

    [Theory]
    [MemberData(nameof(RefusedCallers))]
    public async Task EveryMethod_RefusesACallerThatTheRestPolicyWouldRefuse_AndChangesNothing(string caller,
        CkMethodPrincipal? principal)
    {
        var role = await NewRoleAsync();
        var other = await NewRoleAsync();
        var group = await NewGroupAsync(role);
        var user = await NewUserAsync();
        var member = await NewUserAsync();
        await AddMemberAsync(group, member);

        var results = new[]
        {
            await AddAsync(group, principal, RtGroupMemberKindEnum.User, user.RtId.ToString()),
            await RemoveAsync(group, principal, RtGroupMemberKindEnum.User, member.RtId.ToString()),
            await SetRolesAsync(group, principal, other)
        };

        foreach (var outcome in results)
        {
            AssertForbidden(outcome, "role-required", caller);
        }

        (await MembersAsync(group)).Should().Equal(member.RtId.ToString());
        (await RoleIdsAsync(group)).Should().Equal(await RoleIdAsync(role));
    }

    [Fact]
    public async Task AServiceToken_WithUserManagement_IsAllowed_AsRestAllowsClientRoles()
    {
        var group = await NewGroupAsync();
        var user = await NewUserAsync();

        var outcome = await AddAsync(group, new CkMethodPrincipal(null, [UserManagement], ["octo_api"], "svc"),
            RtGroupMemberKindEnum.User, user.RtId.ToString());

        outcome.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task AForgedCaller_WithoutAValidToken_IsRejectedByTheHost_AndTheHandlerIsNotCalled()
    {
        var ct = TestContext.Current.CancellationToken;
        var role = await NewRoleAsync();
        var other = await NewRoleAsync();
        var group = await NewGroupAsync(role);
        var user = await NewUserAsync();
        var invoker = Host.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        foreach (var (methodId, json) in new[]
                 {
                     (SystemIdentityCkIds.GroupAddMemberMethodId,
                         JsonSerializer.Serialize(new { memberKind = "User", memberId = user.RtId.ToString() })),
                     (SystemIdentityCkIds.GroupRemoveMemberMethodId,
                         JsonSerializer.Serialize(new { memberKind = "User", memberId = user.RtId.ToString() })),
                     (SystemIdentityCkIds.GroupSetRolesMethodId, JsonSerializer.Serialize(new { roleNames = new[] { other } }))
                 })
        {
            foreach (var token in new string?[] { null, "", "not-a-jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." })
            {
                var request = Request(methodId, "System.Identity/Group", group.ToString(), token, json) with
                {
                    // the informational Caller of a bus message is never believed
                    Caller = new CkMethodCaller { SubjectId = "admin", Roles = [UserManagement] }
                };

                var response = await invoker.InvokeAsync(request, ct);

                response.Success.Should().BeFalse(methodId);
                response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
            }
        }

        (await MembersAsync(group)).Should().BeEmpty();
        (await RoleIdsAsync(group)).Should().Equal(await RoleIdAsync(role));
    }

    #endregion

    #region Target

    [Fact]
    public async Task AMissingGroup_IsTargetNotFound_ForEveryMethod()
    {
        var missing = OctoObjectId.GenerateNewId().ToString();
        var user = await NewUserAsync();

        (await AddAsync(missing, Admin(), RtGroupMemberKindEnum.User, user.RtId.ToString())).Failure!.Code.Should()
            .Be("METHOD_TARGET_NOT_FOUND");
        (await RemoveAsync(missing, Admin(), RtGroupMemberKindEnum.User, user.RtId.ToString())).Failure!.Code.Should()
            .Be("METHOD_TARGET_NOT_FOUND");
        (await SetRolesAsync(missing, Admin())).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        (await AddAsync("not-an-id", Admin(), RtGroupMemberKindEnum.User, user.RtId.ToString())).Failure!.Code.Should()
            .Be("METHOD_TARGET_NOT_FOUND");
    }

    #endregion

    #region Audit

    [Fact]
    public async Task EveryCall_WritesOneAuditEvent_WithActorTargetOutcomeAndTheFactsOfTheChange()
    {
        var a = await NewRoleAsync();
        var b = await NewRoleAsync();
        var group = await NewGroupAsync(a);
        var user = await NewUserAsync();
        var actor = Guid.NewGuid().ToString("N");
        var principal = new CkMethodPrincipal(actor, [UserManagement], ["octo_api"]);
        var before = AuditEvents().Count;

        await AddAsync(group, principal, RtGroupMemberKindEnum.User, user.RtId.ToString()); // success
        await AddAsync(group, principal, RtGroupMemberKindEnum.User, user.RtId.ToString()); // MEMBER_ALREADY_IN_GROUP
        await SetRolesAsync(group, principal, b); // success, roles a -> b
        await RemoveAsync(group, new CkMethodPrincipal(actor, [], ["octo_api"]), RtGroupMemberKindEnum.User,
            user.RtId.ToString()); // METHOD_FORBIDDEN

        var written = AuditEvents().Where(e => e.Details["callerSubject"] == actor).ToList();
        AuditEvents().Count.Should().Be(before + 4, "one event per call, success and refusal alike");
        written.Select(e => e.Details["outcome"]).Should().Equal("SUCCESS", "MEMBER_ALREADY_IN_GROUP", "SUCCESS",
            "METHOD_FORBIDDEN");
        written.Should().OnlyContain(e => e.Details["targetRtId"] == group.ToString());
        written.Select(e => e.Details["methodId"]).Should().Equal(SystemIdentityCkIds.GroupAddMemberMethodId,
            SystemIdentityCkIds.GroupAddMemberMethodId, SystemIdentityCkIds.GroupSetRolesMethodId,
            SystemIdentityCkIds.GroupRemoveMemberMethodId);
        written[0].Level.Should().Be("Information");
        written[0].Details.Should().Contain("memberKind", "User").And.Contain("memberId", user.RtId.ToString());
        written[1].Level.Should().Be("Warning");
        written[2].Details.Should().Contain("rolesBefore", a).And.Contain("rolesAfter", b);
        written[3].Details.Should().NotContainKey("memberId", "a refused caller does not get as far as the member");
    }

    [Fact]
    public async Task ARefusalByTheGuard_IsAuditedWithTheReason()
    {
        var secret = await NewRoleAsync(builtIn: true);
        var group = await NewGroupAsync();
        var actor = Guid.NewGuid().ToString("N");

        await SetRolesAsync(group, new CkMethodPrincipal(actor, [UserManagement], ["octo_api"]), secret);

        var written = AuditEvents().Single(e => e.Details["callerSubject"] == actor);
        written.Details.Should().Contain("outcome", "METHOD_FORBIDDEN").And.Contain("reason", "role-not-held")
            .And.Contain("roleNames", secret);
        written.Details["rolesAfter"].Should().BeEmpty("a refused call changed nothing");
    }

    #endregion

    #region Referenced entities are checked with the data-permission API (AB#7035)

    [Fact]
    public async Task AMemberThatTheCallerCannotRead_IsMemberNotFound_AndARoleToo()
    {
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<Meshmakers.Octo.Runtime.Contracts.Repositories.IRuntimeRepository>(),
                Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(), Arg.Any<RtDataAction>(), Arg.Any<bool>(),
                Arg.Any<CancellationToken>())
            .Returns(new RtDataPermissionVerdict(RtDataPermissionDecision.NotVisible,
                RtDataPermissionReason.NoGrant));
        using var restricted = Host.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton(evaluator)));
        var group = await NewGroupAsync();
        var user = await NewUserAsync();
        var role = await NewRoleAsync();

        var add = await InvokeOnAsync<GroupAddMemberHandler, GroupAddMemberParameters>(restricted,
            SystemIdentityCkIds.GroupAddMemberMethodId, group, Admin(),
            new GroupAddMemberParameters { MemberKind = RtGroupMemberKindEnum.User, MemberId = user.RtId.ToString() });
        var set = await InvokeOnAsync<GroupSetRolesHandler, GroupSetRolesParameters>(restricted,
            SystemIdentityCkIds.GroupSetRolesMethodId, group, Admin(), new GroupSetRolesParameters { RoleNames = [role] });

        add.Failure!.Code.Should().Be("MEMBER_NOT_FOUND");
        set.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        (await MembersAsync(group)).Should().BeEmpty();
        (await RoleIdsAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task TheEvaluator_IsAskedWithTheCallersRoles_ForTheReferencedMember()
    {
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<Meshmakers.Octo.Runtime.Contracts.Repositories.IRuntimeRepository>(),
                Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(), Arg.Any<RtDataAction>(), Arg.Any<bool>(),
                Arg.Any<CancellationToken>())
            .Returns(new RtDataPermissionVerdict(RtDataPermissionDecision.Allowed, RtDataPermissionReason.Open));
        using var spied = Host.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton(evaluator)));
        var group = await NewGroupAsync();
        var user = await NewUserAsync();
        var actor = Guid.NewGuid().ToString("N");

        var outcome = await InvokeOnAsync<GroupAddMemberHandler, GroupAddMemberParameters>(spied,
            SystemIdentityCkIds.GroupAddMemberMethodId, group, new CkMethodPrincipal(actor, [UserManagement], ["octo_api"]),
            new GroupAddMemberParameters { MemberKind = RtGroupMemberKindEnum.User, MemberId = user.RtId.ToString() });

        outcome.IsSuccess.Should().BeTrue();
        await evaluator.Received(1).EvaluateAsync(Arg.Any<Meshmakers.Octo.Runtime.Contracts.Repositories.IRuntimeRepository>(),
            Arg.Is<RtSecurityContext>(c => c.SubjectId == actor && c.Roles.Contains(UserManagement)),
            Arg.Is<RtEntityId>(e => e.RtId == user.RtId), RtDataAction.Read, Arg.Any<bool>(),
            Arg.Any<CancellationToken>());
    }

    #endregion

    #region Helpers

    private static void AssertForbidden(CkMethodOutcome outcome, string reason, string? because = null)
    {
        outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN", because);
        outcome.Failure.Parameters.Should().Contain("reason", reason);
    }

    private Task<CkMethodOutcome> AddAsync(OctoObjectId group, CkMethodPrincipal? principal, RtGroupMemberKindEnum kind,
        string memberId) => AddAsync(group.ToString(), principal, kind, memberId);

    private Task<CkMethodOutcome> AddAsync(string group, CkMethodPrincipal? principal, RtGroupMemberKindEnum kind,
        string memberId) =>
        InvokeAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
            "System.Identity/Group", group, principal,
            new GroupAddMemberParameters { MemberKind = kind, MemberId = memberId });

    private Task<CkMethodOutcome> RemoveAsync(OctoObjectId group, CkMethodPrincipal? principal,
        RtGroupMemberKindEnum kind, string memberId) => RemoveAsync(group.ToString(), principal, kind, memberId);

    private Task<CkMethodOutcome> RemoveAsync(string group, CkMethodPrincipal? principal, RtGroupMemberKindEnum kind,
        string memberId) =>
        InvokeAsync<GroupRemoveMemberHandler, GroupRemoveMemberParameters>(SystemIdentityCkIds.GroupRemoveMemberMethodId,
            "System.Identity/Group", group, principal,
            new GroupRemoveMemberParameters { MemberKind = kind, MemberId = memberId });

    private Task<CkMethodOutcome> SetRolesAsync(OctoObjectId group, CkMethodPrincipal? principal, params string[] roles) =>
        SetRolesAsync(group.ToString(), principal, roles);

    private Task<CkMethodOutcome> SetRolesAsync(string group, CkMethodPrincipal? principal, params string[] roles) =>
        InvokeAsync<GroupSetRolesHandler, GroupSetRolesParameters>(SystemIdentityCkIds.GroupSetRolesMethodId,
            "System.Identity/Group", group, principal, new GroupSetRolesParameters { RoleNames = roles });

    private async Task<CkMethodOutcome> InvokeOnAsync<THandler, TParameters>(
        Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> host, string methodId, OctoObjectId target,
        CkMethodPrincipal principal, TParameters parameters)
        where THandler : ICkMethodHandler<TParameters> where TParameters : class
    {
        using var scope = host.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<THandler>(scope.ServiceProvider);
        var context = new CkMethodContext<TParameters>(
            Request(methodId, "System.Identity/Group", target.ToString(), null, "{}"), parameters)
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, TestContext.Current.CancellationToken);
    }

    #endregion
}
