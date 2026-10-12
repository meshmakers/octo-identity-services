using FluentAssertions;
using IdentityServerPersistence.Services.FileRoles;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.FileRoles;

/// <summary>
///     AB#6578: the pure rule of the human-administrator File-role grant — users holding AdminPanelManagement AND
///     TenantManagement (direct, via groups, via TenantOwners) get a direct FileManagement edge; nobody else.
/// </summary>
public class TenantAdministratorFileRoleGrantPlannerTests
{
    private const string AdminPanel = "660000000000000000000002";
    private const string TenantManagement = "660000000000000000000001";
    private const string FileManagement = "660000000000000000000061";
    private const string FileViewer = "660000000000000000000062";
    private const string Development = "660000000000000000000004";

    [Fact]
    public void UserWithBothAdminRolesDirectly_IsGranted()
    {
        var input = Input(users: new()
        {
            ["u-admin"] = [AdminPanel, TenantManagement],
            ["u-panel-only"] = [AdminPanel],
            ["u-tenant-only"] = [TenantManagement],
            ["u-dev"] = [Development]
        });

        Plan(input).UserIds.Should().Equal("u-admin");
    }

    [Fact]
    public void AdminRolesViaGroups_MixedAndTenantOwners_AreGranted_AsDirectUserEdges()
    {
        var input = Input(
            users: new()
            {
                ["u-owner"] = [],
                ["u-mixed"] = [AdminPanel],
                ["u-nested"] = [],
                ["u-outsider"] = []
            },
            groupRoles: new()
            {
                ["g-owners"] = [AdminPanel, TenantManagement],
                ["g-tenant"] = [TenantManagement],
                ["g-parent"] = [AdminPanel, TenantManagement],
                ["g-child"] = []
            },
            groupChildren: new() { ["g-parent"] = ["g-child"] },
            groupMembers: new()
            {
                ["g-owners"] = ["u-owner"],
                ["g-tenant"] = ["u-mixed"],
                ["g-child"] = ["u-nested"]
            });

        // u-nested is a member of the CHILD only; roles flow from child up to its members, not from the parent down.
        Plan(input).UserIds.Should().Equal("u-mixed", "u-owner");
    }

    [Fact]
    public void ChildGroupRoles_AreEffectiveForTheParentGroupMembers()
    {
        var input = Input(
            users: new() { ["u-member"] = [] },
            groupRoles: new() { ["g-parent"] = [AdminPanel], ["g-child"] = [TenantManagement] },
            groupChildren: new() { ["g-parent"] = ["g-child"] },
            groupMembers: new() { ["g-parent"] = ["u-member"] });

        Plan(input).UserIds.Should().Equal("u-member");
    }

    [Fact]
    public void AdminAlreadyHoldingFileManagement_DirectlyOrViaGroup_IsNotPlanned()
    {
        var input = Input(
            users: new()
            {
                ["u-direct"] = [AdminPanel, TenantManagement, FileManagement],
                ["u-group"] = [AdminPanel, TenantManagement],
                ["u-viewer-only"] = [AdminPanel, TenantManagement, FileViewer]
            },
            groupRoles: new() { ["g-files"] = [FileManagement] },
            groupMembers: new() { ["g-files"] = ["u-group"] });

        Plan(input).UserIds.Should().Equal(new[] { "u-viewer-only" }, "FileViewer cannot write, so the admin still needs FileManagement");
    }

    [Fact]
    public void ShadowUsers_AreNeverGranted_EvenWhenTheyHoldBothRoles()
    {
        var input = Input(
            users: new()
            {
                ["u-xt"] = [AdminPanel, TenantManagement],
                ["u-local"] = [AdminPanel, TenantManagement]
            },
            excluded: ["u-xt"]);

        Plan(input).UserIds.Should().Equal("u-local");
    }

    [Fact]
    public void ClientsAndGroupsAndMappings_AreNeverSubjects()
    {
        // The input has no client or mapping dimension at all, and a group that holds both admin roles is never
        // returned itself — only its (human) user members are, as direct edges.
        var input = Input(
            users: new() { ["u-member"] = [] },
            groupRoles: new() { ["g-admins"] = [AdminPanel, TenantManagement] },
            groupMembers: new() { ["g-admins"] = ["u-member"] });

        var plan = Plan(input);

        plan.UserIds.Should().Equal("u-member");
        plan.UserIds.Should().NotContain("g-admins");
    }

    [Fact]
    public void CyclicGroupHierarchy_Terminates()
    {
        var input = Input(
            users: new() { ["u"] = [] },
            groupRoles: new() { ["g1"] = [AdminPanel], ["g2"] = [TenantManagement] },
            groupChildren: new() { ["g1"] = ["g2"], ["g2"] = ["g1"] },
            groupMembers: new() { ["g1"] = ["u"] });

        Plan(input).UserIds.Should().Equal("u");
    }

    [Fact]
    public void PlanningTwiceOnTheResultOfTheFirstRun_YieldsNoSecondEdge()
    {
        var users = new Dictionary<string, string[]> { ["u-admin"] = [AdminPanel, TenantManagement] };

        var first = Plan(Input(users: users));
        first.UserIds.Should().Equal("u-admin");

        // Apply the plan, then plan again against the new state.
        users["u-admin"] = [AdminPanel, TenantManagement, FileManagement];
        Plan(Input(users: users)).UserIds.Should().BeEmpty();
    }

    [Fact]
    public void TenantWithoutAdminRoles_PlansNothing()
    {
        // The grant passes "-" for an admin role that does not exist in the tenant.
        var input = Input(users: new() { ["u"] = [AdminPanel] });

        TenantAdministratorFileRoleGrantPlanner
            .Plan(input, AdminPanel, "-", FileManagement)
            .UserIds.Should().BeEmpty();
    }

    [Fact]
    public void MarkerKeys_AreSeparate_SoTenantsWithTheReportingMarkerStillGetTheAdministratorGrant()
    {
        IdentityServiceConstants.TenantAdministratorFileRoleGrantKey
            .Should().NotBe(IdentityServiceConstants.FileRoleGrantKey);
    }

    private static TenantAdministratorFileRoleGrantPlan Plan(TenantAdministratorFileRoleGrantInput input) =>
        TenantAdministratorFileRoleGrantPlanner.Plan(input, AdminPanel, TenantManagement, FileManagement);

    private static TenantAdministratorFileRoleGrantInput Input(
        Dictionary<string, string[]>? users = null,
        Dictionary<string, string[]>? groupRoles = null,
        Dictionary<string, string[]>? groupChildren = null,
        Dictionary<string, string[]>? groupMembers = null,
        IEnumerable<string>? excluded = null) =>
        new(Sets(users), Sets(groupRoles), Sets(groupChildren), Sets(groupMembers),
            excluded?.ToHashSet(StringComparer.Ordinal));

    private static Dictionary<string, IReadOnlySet<string>> Sets(Dictionary<string, string[]>? source) =>
        (source ?? new()).ToDictionary(
            kv => kv.Key, kv => (IReadOnlySet<string>)kv.Value.ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal);
}
