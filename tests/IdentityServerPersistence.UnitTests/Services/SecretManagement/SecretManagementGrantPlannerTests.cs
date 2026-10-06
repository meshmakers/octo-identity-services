using FluentAssertions;
using IdentityServerPersistence.Services.SecretManagement;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SecretManagement;

/// <summary>
///     AB#5544: which existing groups and users receive SecretManagement. Rule: both AdminPanelManagement
///     and TenantManagement (direct or via groups) ⇒ grant; to the group when the roles come from a group,
///     otherwise to the user; TenantOwners always; AdminPanelManagement alone is not enough; nothing removed.
/// </summary>
public class SecretManagementGrantPlannerTests
{
    private const string Apm = "role-apm";
    private const string Tm = "role-tm";
    private const string Sm = "role-sm";
    private const string Other = "role-other";
    private const string Owners = "group-owners";

    private sealed class Graph
    {
        public Dictionary<string, IReadOnlySet<string>> Users { get; } = new();
        public Dictionary<string, IReadOnlySet<string>> GroupRoles { get; } = new();
        public Dictionary<string, IReadOnlySet<string>> Children { get; } = new();
        public Dictionary<string, IReadOnlySet<string>> Members { get; } = new();

        public Graph User(string id, params string[] roles)
        {
            Users[id] = roles.ToHashSet();
            return this;
        }

        public Graph Group(string id, string[] roles, string[]? members = null, string[]? children = null)
        {
            GroupRoles[id] = roles.ToHashSet();
            Members[id] = (members ?? []).ToHashSet();
            Children[id] = (children ?? []).ToHashSet();
            return this;
        }

        public SecretManagementGrantPlan Plan(string? ownersId = Owners) =>
            SecretManagementGrantPlanner.Plan(
                new SecretManagementGrantInput(Users, GroupRoles, Children, Members), Apm, Tm, Sm, ownersId);
    }

    [Fact]
    public void UserWithBothRolesDirect_GetsDirectGrant()
    {
        var plan = new Graph().User("u1", Apm, Tm).Plan();

        plan.UserIds.Should().Equal("u1");
        plan.GroupIds.Should().BeEmpty();
    }

    [Fact]
    public void UserWithOnlyAdminPanelManagement_GetsNothing()
    {
        var plan = new Graph().User("u1", Apm, Other).Plan();

        plan.UserIds.Should().BeEmpty();
        plan.GroupIds.Should().BeEmpty();
    }

    [Fact]
    public void UserWhoAlreadyHasSecretManagement_IsLeftAlone()
    {
        new Graph().User("u1", Apm, Tm, Sm).Plan().UserIds.Should().BeEmpty();
    }

    [Fact]
    public void RolesFromGroup_GrantGoesToGroupNotToMembers()
    {
        var plan = new Graph()
            .User("u1")
            .User("u2", Other)
            .Group("admins", [Apm, Tm], members: ["u1", "u2"])
            .Plan();

        plan.GroupIds.Should().Equal("admins");
        plan.UserIds.Should().BeEmpty("the members receive the role through the group");
    }

    [Fact]
    public void RolesSplitBetweenUserAndGroup_GrantGoesToUser()
    {
        var plan = new Graph()
            .User("u1", Apm)
            .Group("tenant-admins", [Tm], members: ["u1"])
            .Plan();

        plan.GroupIds.Should().BeEmpty("the group alone does not hold both roles");
        plan.UserIds.Should().Equal("u1");
    }

    [Fact]
    public void RolesSplitAcrossTwoGroups_GrantGoesToUser()
    {
        var plan = new Graph()
            .User("u1")
            .Group("g-apm", [Apm], members: ["u1"])
            .Group("g-tm", [Tm], members: ["u1"])
            .Plan();

        plan.GroupIds.Should().BeEmpty();
        plan.UserIds.Should().Equal("u1");
    }

    [Fact]
    public void TenantOwners_AlwaysGetsTheRole_AndItsMembersNeedNoDirectGrant()
    {
        var plan = new Graph()
            .User("owner")
            .Group(Owners, [Other], members: ["owner"])
            .Plan();

        plan.GroupIds.Should().Equal(Owners);
        plan.UserIds.Should().BeEmpty();
    }

    [Fact]
    public void TenantOwnersAlreadyHoldingTheRole_IsLeftAlone()
    {
        new Graph().Group(Owners, [Apm, Tm, Sm]).Plan().GroupIds.Should().BeEmpty();
    }

    [Fact]
    public void MemberOfTenantOwnersWithAdminRoles_GetsItThroughTenantOwners()
    {
        var plan = new Graph()
            .User("u1", Apm, Tm)
            .Group(Owners, [Apm, Tm], members: ["u1"])
            .Plan();

        plan.GroupIds.Should().Equal(Owners);
        plan.UserIds.Should().BeEmpty();
    }

    [Fact]
    public void NestedGroups_GrantLandsOnTheChildThatCarriesTheRoles()
    {
        // GroupRoleResolver semantics: a member of "parent" inherits the roles of parent's child groups.
        var plan = new Graph()
            .User("u1")
            .Group("parent", [], members: ["u1"], children: ["child"])
            .Group("child", [Apm, Tm])
            .Plan();

        plan.GroupIds.Should().Equal("child");
        plan.UserIds.Should().BeEmpty("u1 receives SecretManagement through parent → child");
    }

    [Fact]
    public void GroupWhoseRolesComeFromItselfAndAChild_IsGranted()
    {
        var plan = new Graph()
            .Group("parent", [Apm], children: ["child"])
            .Group("child", [Tm])
            .Plan();

        plan.GroupIds.Should().Equal("parent");
    }

    [Fact]
    public void CyclicChildGroups_DoNotLoopAndGrantOnce()
    {
        var plan = new Graph()
            .User("u1")
            .Group("a", [Apm, Tm], members: ["u1"], children: ["b"])
            .Group("b", [Apm, Tm], children: ["a"])
            .Plan();

        plan.GroupIds.Should().HaveCount(1);
        plan.UserIds.Should().BeEmpty();
    }

    [Fact]
    public void UnknownAdminRoleIds_OnlyTenantOwnersIsGranted()
    {
        var plan = SecretManagementGrantPlanner.Plan(
            new SecretManagementGrantInput(
                new Dictionary<string, IReadOnlySet<string>> { ["u1"] = new HashSet<string> { Apm, Tm } },
                new Dictionary<string, IReadOnlySet<string>> { [Owners] = new HashSet<string>() },
                new Dictionary<string, IReadOnlySet<string>>(),
                new Dictionary<string, IReadOnlySet<string>>()),
            "-", "-", Sm, Owners);

        plan.GroupIds.Should().Equal(Owners);
        plan.UserIds.Should().BeEmpty();
    }

    [Fact]
    public void NoTenantOwnersGroup_NoGroupGrant()
    {
        new Graph().User("u1", Apm).Plan().GroupIds.Should().BeEmpty();
    }
}
