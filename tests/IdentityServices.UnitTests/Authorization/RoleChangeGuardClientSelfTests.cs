using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#8569: a client-credentials caller is "self" for every role change on its own client, with the semantics the guard
///     applies to a user on its own user: a direct grant, a group membership, a role added to a group it is in (directly or
///     through a parent group) and a group nested into a group it is in. A user session that carries the same
///     <c>client_id</c> is not that client. Removals stay free. The REST and method paths are covered end to end by
///     <c>ClientSelfGrantTests</c> and <c>GroupMethodTests</c>.
/// </summary>
public class RoleChangeGuardClientSelfTests
{
    private const string UserManagement = "UserManagement";
    private const string App = "EnergyCommunityManagement";
    private const string SelfClientId = "ec-self";
    private const string OtherClientId = "ec-other";

    private readonly RoleManager<RtRole> _roleManager =
        Substitute.For<RoleManager<RtRole>>(Substitute.For<IRoleStore<RtRole>>(), null, null, null, null);
    private readonly IPlatformRoleCatalog _platformRoles = Substitute.For<IPlatformRoleCatalog>();
    private readonly IGroupStore _groupStore = Substitute.For<IGroupStore>();
    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly List<RtGroup> _groups = [];
    private readonly RoleChangeGuard _sut;

    private readonly RtRole _userManagement;
    private readonly RtRole _app;
    private readonly RtClient _self;
    private readonly RtClient _other;

    /// <summary>The caller's own client is a member (TenantOwners-like, carries UserManagement).</summary>
    private readonly RtGroup _owners;

    /// <summary>Carries the app role; nobody is a member (EnergyCommunityOperators-like).</summary>
    private readonly RtGroup _operators;

    /// <summary>The caller's own client is a member; <see cref="_inner" /> is nested into it.</summary>
    private readonly RtGroup _outer;

    /// <summary>Nested into <see cref="_outer" />, no roles yet.</summary>
    private readonly RtGroup _inner;

    public RoleChangeGuardClientSelfTests()
    {
        _userManagement = AddRole(UserManagement, platform: true);
        _app = AddRole(App, platform: false);

        _self = AddClient(SelfClientId);
        _other = AddClient(OtherClientId);

        _owners = AddGroup([_userManagement], clients: [_self]);
        _operators = AddGroup([_app]);
        _inner = AddGroup([]);
        _outer = AddGroup([], clients: [_self], children: [_inner]);
        _groupStore.GetAllAsync().ReturnsForAnyArgs(_ => _groups.AsEnumerable());

        var userStore = Substitute.For<IUserStore<RtUser>, IUserRoleStore<RtUser>>();
        ((IUserRoleStore<RtUser>)userStore).GetUsersInRoleAsync(default!, default).ReturnsForAnyArgs([]);
        var userManager = Substitute.For<UserManager<RtUser>>(userStore, null, null, null, null, null, null, null, null);
        userManager.Users.Returns(Array.Empty<RtUser>().AsQueryable());
        var mappingStore = Substitute.For<IExternalTenantUserMappingStore>();
        mappingStore.GetAllAsync().ReturnsForAnyArgs([]);

        _sut = new RoleChangeGuard(userManager, _roleManager, _groupStore, Substitute.For<IGroupRoleResolver>(),
            userStore, mappingStore, Substitute.For<ICrossTenantShadowUserChainResolver>(), _platformRoles, _clientStore,
            NullLogger<RoleChangeGuard>.Instance);
    }

    private RtRole AddRole(string name, bool platform)
    {
        var role = new RtRoleBuilder().WithName(name).Build();
        role.RtId = OctoObjectId.GenerateNewId();
        role.RtWellKnownName = name;
        _roleManager.FindByNameAsync(name).Returns(role);
        _roleManager.FindByIdAsync(role.RtId.ToString()).Returns(role);
        _platformRoles.IsPlatformRole(role).Returns(platform);
        return role;
    }

    private RtClient AddClient(string clientId)
    {
        var client = new RtClientBuilder().WithClientId(clientId).WithClientName(clientId).Build();
        client.RtId = OctoObjectId.GenerateNewId();
        _clientStore.FindRtClientByIdAsync(clientId).Returns(client);
        return client;
    }

    private RtGroup AddGroup(RtRole[] roles, RtClient[]? clients = null, RtGroup[]? children = null)
    {
        var group = new RtGroup { RtId = OctoObjectId.GenerateNewId() };
        _groupStore.GetRoleIdsAsync(group.RtId).Returns(roles.Select(r => r.RtId.ToString()).ToList());
        _groupStore.GetMemberClientIdsAsync(group.RtId)
            .Returns((clients ?? []).Select(c => c.RtId.ToString()).ToList());
        _groupStore.GetMemberGroupIdsAsync(group.RtId)
            .Returns((children ?? []).Select(c => c.RtId.ToString()).ToList());
        _groupStore.GetMemberUserIdsAsync(group.RtId).Returns([]);
        _groupStore.GetMemberExternalUserIdsAsync(group.RtId).Returns([]);
        _groups.Add(group);
        return group;
    }

    /// <summary>A client-credentials token of the caller's own client: no subject, client id, UserManagement.</summary>
    private static RoleChangeCaller ClientCaller(string clientId = SelfClientId) => new(null, clientId, [UserManagement]);

    /// <summary>A user session signed in through the client <see cref="SelfClientId" />.</summary>
    private static RoleChangeCaller UserCaller() => new("user-1", SelfClientId, [UserManagement]);

    private static string Id(RtGroup group) => group.RtId.ToString();

    [Fact]
    public void SelfClientId_IsTheClientIdOfAClientCredentialsToken_AndNullForAUserSession()
    {
        ClientCaller().SelfClientId.Should().Be(SelfClientId);
        UserCaller().SelfClientId.Should().BeNull();
        new RoleChangeCaller(null, null, []).SelfClientId.Should().BeNull();
    }

    [Fact]
    public async Task Client_AddingItselfToAGroupWithAnAppRole_IsRefusedAsSelfGrant()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.MemberAdded(Id(_operators), GroupMemberKind.Client, _self.RtId.ToString()),
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.SelfGrant);
        decision.RoleNames.Should().Equal(App);
    }

    [Fact]
    public async Task Client_AddingItselfByItsOAuthClientId_IsRefusedAsSelfGrant()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.MemberAdded(Id(_operators), GroupMemberKind.Client, SelfClientId),
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.SelfGrant);
    }

    [Fact]
    public async Task Client_AddingAnotherClientToAGroupWithAnAppRole_IsAllowed()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.MemberAdded(Id(_operators), GroupMemberKind.Client, _other.RtId.ToString()),
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
        decision.AppRolesNotHeld.Should().Equal(App);
    }

    [Fact]
    public async Task Client_AddingARoleToAGroupItIsIn_IsRefusedAsSelfGrant()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.GroupRoles(Id(_owners), [_userManagement.RtId.ToString(), _app.RtId.ToString()]),
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.SelfGrant);
        decision.RoleNames.Should().Equal(App);
    }

    [Fact]
    public async Task Client_AddingARoleToAGroupNestedIntoAGroupItIsIn_IsRefusedAsSelfGrant()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.GroupRoles(Id(_inner), [_app.RtId.ToString()]), TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.SelfGrant);
        decision.RoleNames.Should().Equal(App);
    }

    [Fact]
    public async Task Client_NestingAGroupWithMoreRolesIntoAGroupItIsIn_IsRefusedAsSelfGrant()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.MemberAdded(Id(_outer), GroupMemberKind.Group, Id(_operators)),
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.SelfGrant);
        decision.RoleNames.Should().Equal(App);
    }

    [Fact]
    public async Task Client_AddingARoleToAGroupItIsNotIn_IsAllowed()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.GroupRoles(Id(_operators), [_app.RtId.ToString(), _userManagement.RtId.ToString()]),
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
    }

    [Fact]
    public async Task Client_RemovingItselfFromAGroup_IsAllowed()
    {
        var decision = await _sut.EvaluateAsync(ClientCaller(),
            new RoleGraphChange.MemberRemoved(Id(_owners), GroupMemberKind.Client, _self.RtId.ToString()),
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
    }

    [Fact]
    public async Task Client_UnknownInTheTenant_IsStillSelfForItsOAuthClientId_AndNotForOthers()
    {
        var caller = ClientCaller("ec-mirror-missing");

        var self = await _sut.EvaluateAsync(caller,
            new RoleGraphChange.MemberAdded(Id(_operators), GroupMemberKind.Client, "ec-mirror-missing"),
            TestContext.Current.CancellationToken);
        var other = await _sut.EvaluateAsync(caller,
            new RoleGraphChange.MemberAdded(Id(_operators), GroupMemberKind.Client, _other.RtId.ToString()),
            TestContext.Current.CancellationToken);

        self.Reason.Should().Be(RoleChangeReasons.SelfGrant);
        other.IsAllowed.Should().BeTrue();
    }

    [Fact]
    public async Task UserSession_WithTheSameClientId_AddingThatClientToAGroup_IsNotASelfGrant()
    {
        var decision = await _sut.EvaluateAsync(UserCaller(),
            new RoleGraphChange.MemberAdded(Id(_operators), GroupMemberKind.Client, _self.RtId.ToString()),
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
        await _clientStore.DidNotReceiveWithAnyArgs().FindRtClientByIdAsync(default!);
    }

    [Fact]
    public async Task ClientGrant_ToItsOwnClient_IsRefusedAsSelfGrant_BeforeTheGrantRule()
    {
        var decision = await _sut.EvaluateClientGrantAsync(ClientCaller(), _self, [App, UserManagement],
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.SelfGrant);
        decision.RoleNames.Should().Equal(App, UserManagement);
    }

    [Fact]
    public async Task ClientGrant_ToAnotherClient_FollowsTheGrantRule()
    {
        var decision = await _sut.EvaluateClientGrantAsync(ClientCaller(), _other, [App],
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
        decision.AppRolesNotHeld.Should().Equal(App);
    }

    [Fact]
    public async Task ClientGrant_ByAUserSessionWithTheSameClientId_IsNotASelfGrant()
    {
        var decision = await _sut.EvaluateClientGrantAsync(UserCaller(), _self, [App],
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
    }

    [Fact]
    public async Task ClientGrant_WithoutAddedRoles_IsAllowed()
    {
        var decision = await _sut.EvaluateClientGrantAsync(ClientCaller(), _self, [],
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
    }
}
