using FluentAssertions;
using IdentityServerPersistence.Services.SecretManagement;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SecretManagement;

/// <summary>
///     AB#5544: which existing users receive SecretManagement. Rule (decision Gerald 2026-10-11): human
///     administrators only — a local user holding both AdminPanelManagement and TenantManagement (direct, via
///     groups or mixed) gets a DIRECT edge; never a group (members include clients and provisioned parent-tenant
///     administrators), never a cross-tenant shadow user; AdminPanelManagement alone is not enough.
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
        public HashSet<string> Excluded { get; } = new();

        public Graph User(string id, params string[] roles)
        {
            Users[id] = roles.ToHashSet();
            return this;
        }

        public Graph ShadowUser(string id, params string[] roles)
        {
            Excluded.Add(id);
            return User(id, roles);
        }

        public Graph Group(string id, string[] roles, string[]? members = null, string[]? children = null)
        {
            GroupRoles[id] = roles.ToHashSet();
            Members[id] = (members ?? []).ToHashSet();
            Children[id] = (children ?? []).ToHashSet();
            return this;
        }

        public SecretManagementGrantPlan Plan() =>
            SecretManagementGrantPlanner.Plan(
                new SecretManagementGrantInput(Users, GroupRoles, Children, Members, Excluded), Apm, Tm, Sm);
    }

    [Fact]
    public void UserWithBothRolesDirect_GetsDirectGrant()
    {
        new Graph().User("u1", Apm, Tm).Plan().UserIds.Should().Equal("u1");
    }

    [Fact]
    public void UserWithOnlyAdminPanelManagement_GetsNothing()
    {
        new Graph().User("u1", Apm, Other).Plan().UserIds.Should().BeEmpty();
    }

    [Fact]
    public void UserWithBothRolesFromOneGroup_GetsADirectEdge_NotTheGroup()
    {
        var plan = new Graph()
            .User("u1")
            .Group("admins", [Apm, Tm], members: ["u1"])
            .Plan();

        // The group is never granted: clients and mappings in it would inherit the role.
        plan.UserIds.Should().Equal("u1");
    }

    [Fact]
    public void TenantOwnersMember_IsGrantedAsAUser_AndTheGroupIsNot()
    {
        var plan = new Graph()
            .User("human")
            .Group(Owners, [Apm, Tm, Other], members: ["human"])
            .Plan();

        plan.UserIds.Should().Equal("human");
    }

    [Fact]
    public void RolesSplitAcrossTwoGroupsOrMixedWithDirect_StillQualify()
    {
        var plan = new Graph()
            .User("split")
            .User("mixed", Tm)
            .Group("g-apm", [Apm], members: ["split", "mixed"])
            .Group("g-tm", [Tm], members: ["split"])
            .Plan();

        plan.UserIds.Should().Equal("mixed", "split");
    }

    [Fact]
    public void RolesFromAChildGroup_AreEffective()
    {
        var plan = new Graph()
            .User("u1")
            .Group("parent", [Apm], members: ["u1"], children: ["child"])
            .Group("child", [Tm])
            .Plan();

        plan.UserIds.Should().Equal("u1");
    }

    [Fact]
    public void CyclicGroups_AreHandled()
    {
        var plan = new Graph()
            .User("u1")
            .Group("a", [Apm], members: ["u1"], children: ["b"])
            .Group("b", [Tm], children: ["a"])
            .Plan();

        plan.UserIds.Should().Equal("u1");
    }

    [Fact]
    public void ShadowUser_ProvisionedParentTenantAdministrator_IsNeverGranted()
    {
        var plan = new Graph()
            .ShadowUser("xt-user", Apm, Tm)
            .User("local", Apm, Tm)
            .Plan();

        plan.UserIds.Should().Equal("local");
    }

    [Fact]
    public void ShadowUser_ThatQualifiesThroughTenantOwners_IsNeverGranted()
    {
        var plan = new Graph()
            .ShadowUser("xt-user")
            .Group(Owners, [Apm, Tm], members: ["xt-user"])
            .Plan();

        plan.UserIds.Should().BeEmpty();
    }

    [Fact]
    public void UserAlreadyHoldingTheRole_DirectOrViaGroup_IsSkipped()
    {
        var plan = new Graph()
            .User("direct", Apm, Tm, Sm)
            .User("viaGroup", Apm, Tm)
            .Group("secret", [Sm], members: ["viaGroup"])
            .Plan();

        plan.UserIds.Should().BeEmpty();
    }

    [Fact]
    public void UnknownAdminRoleIds_GrantNothing()
    {
        var plan = SecretManagementGrantPlanner.Plan(
            new SecretManagementGrantInput(
                new Dictionary<string, IReadOnlySet<string>> { ["u1"] = new HashSet<string> { Apm, Tm } },
                new Dictionary<string, IReadOnlySet<string>>(),
                new Dictionary<string, IReadOnlySet<string>>(),
                new Dictionary<string, IReadOnlySet<string>>()),
            "-", "-", Sm);

        plan.UserIds.Should().BeEmpty();
    }
}
