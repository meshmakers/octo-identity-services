using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>AB#7927: who effectively holds the administrator role, judged over direct roles, groups, nested groups and mappings.</summary>
public class RoleGraphTests
{
    private const string Admin = "role-admin";

    private static RoleGraph NewGraph(params string[] users) => new()
    {
        AdminRoleId = Admin,
        UserIds = [.. users]
    };

    [Fact]
    public void Holders_AreDirectHoldersAndMembersOfAGroupWithTheRole_NestedGroupsIncluded()
    {
        var graph = NewGraph("direct", "member", "deep", "plain");
        graph.DirectHolders.Add("direct");
        graph.Groups["top"] = new GroupNode { Users = ["member"], Children = ["inner"] };
        graph.Groups["inner"] = new GroupNode { Roles = [Admin], Users = [] };
        graph.Groups["outer"] = new GroupNode { Children = ["top"], Users = ["deep"] };

        graph.Holders().Should().BeEquivalentTo("direct", "member", "deep");
    }

    [Fact]
    public void Holders_ClientsAndUnknownUsersDoNotCount()
    {
        var graph = NewGraph("real");
        graph.Groups["g"] = new GroupNode { Roles = [Admin], Users = ["gone", "real"], Clients = ["client"] };

        graph.Holders().Should().BeEquivalentTo("real");
    }

    [Fact]
    public void Holders_AShadowUserThroughItsMappingRolesOrAGroupOfTheMapping()
    {
        var graph = NewGraph("shadowA", "shadowB");
        graph.Mappings["mapA"] = new MappingNode { Roles = [Admin] };
        graph.Mappings["mapB"] = new MappingNode();
        graph.Groups["g"] = new GroupNode { Roles = [Admin], Mappings = ["mapB"] };
        graph.ShadowUserMappings["shadowA"] = ["mapA"];
        graph.ShadowUserMappings["shadowB"] = ["mapB"];

        graph.Holders().Should().BeEquivalentTo("shadowA", "shadowB");

        var after = graph.Clone();
        after.RemoveMapping("mapA");
        after.Holders().Should().BeEquivalentTo("shadowB");
        after.Groups["g"].Roles.Clear();
        after.Holders().Should().BeEmpty();
        graph.Holders().Should().HaveCount(2, "the clone is independent");
    }

    [Fact]
    public void Holders_ACycleOfGroupsTerminates()
    {
        var graph = NewGraph("u");
        graph.Groups["a"] = new GroupNode { Children = ["b"], Users = ["u"] };
        graph.Groups["b"] = new GroupNode { Children = ["a"], Roles = [Admin] };

        graph.Holders().Should().BeEquivalentTo("u");
    }

    [Fact]
    public void WithoutAnAdministratorRole_NobodyHoldsIt()
    {
        var graph = NewGraph("u");
        var withoutRole = new RoleGraph { UserIds = ["u"], DirectHolders = ["u"] };

        withoutRole.Holders().Should().BeEmpty();
        graph.Holders().Should().BeEmpty();
    }

    [Fact]
    public void RemoveGroup_TakesItsReferencesAway()
    {
        var graph = NewGraph("u");
        graph.Groups["parent"] = new GroupNode { Users = ["u"], Children = ["child"] };
        graph.Groups["child"] = new GroupNode { Roles = [Admin] };

        graph.RemoveGroup("child");

        graph.Groups["parent"].Children.Should().BeEmpty();
        graph.Holders().Should().BeEmpty();
    }

    [Fact]
    public void EffectiveRoles_AndTheGroupsReachingASubject_FollowNestedGroups()
    {
        var graph = NewGraph("u");
        graph.Groups["parent"] = new GroupNode { Roles = ["r1"], Users = ["u"], Children = ["child"] };
        graph.Groups["child"] = new GroupNode { Roles = ["r2"] };
        graph.Groups["other"] = new GroupNode { Roles = ["r3"] };

        graph.EffectiveRoles("parent").Should().BeEquivalentTo("r1", "r2");
        graph.GroupsReachingSubject("u", []).Should().BeEquivalentTo("parent", "child");
        graph.GroupsReachingSubject(null, []).Should().BeEmpty();
    }
}
