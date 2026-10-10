using FluentAssertions;
using IdentityServerPersistence.Services.FileRoles;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.FileRoles;

/// <summary>
///     AB#6180: the pure rule of the one-time File-role grant — every direct holder of ReportingManagement /
///     ReportingViewer receives FileManagement / FileViewer the same way, additive only.
/// </summary>
public class FileRoleGrantPlannerTests
{
    private const string ReportingManagement = "660000000000000000000009";
    private const string ReportingViewer = "66000000000000000000000a";
    private const string FileManagement = "660000000000000000000061";
    private const string FileViewer = "660000000000000000000062";
    private const string Development = "660000000000000000000004";

    private static readonly FileRoleGrantPair[] Pairs =
    [
        new(ReportingManagement, FileManagement),
        new(ReportingViewer, FileViewer)
    ];

    [Fact]
    public void DirectUserHolders_GetTheMatchingFileRole()
    {
        var input = Input(users: new()
        {
            ["u-viewer"] = [ReportingViewer],
            ["u-manager"] = [ReportingManagement],
            ["u-both"] = [ReportingManagement, ReportingViewer],
            ["u-none"] = [Development]
        });

        var plan = FileRoleGrantPlanner.Plan(input, Pairs);

        plan.Edges.Should().Equal(
            new FileRoleGrantEdge(FileRoleGrantSubjectKind.User, "u-both", FileManagement),
            new FileRoleGrantEdge(FileRoleGrantSubjectKind.User, "u-both", FileViewer),
            new FileRoleGrantEdge(FileRoleGrantSubjectKind.User, "u-manager", FileManagement),
            new FileRoleGrantEdge(FileRoleGrantSubjectKind.User, "u-viewer", FileViewer));
        plan.MappingAdditions.Should().BeEmpty();
    }

    [Fact]
    public void Groups_AreGrantedOnTheGroupItself_MembersAreNotExpanded()
    {
        // The planner only sees direct holdings; a member of the group is not listed with the group's roles,
        // so it gets no direct edge — it inherits FileViewer through the group like it inherited ReportingViewer.
        var input = Input(
            users: new() { ["member"] = [] },
            groups: new() { ["viewers"] = [ReportingViewer] });

        var plan = FileRoleGrantPlanner.Plan(input, Pairs);

        plan.Edges.Should().Equal(new FileRoleGrantEdge(FileRoleGrantSubjectKind.Group, "viewers", FileViewer));
    }

    [Fact]
    public void Clients_AreGranted()
    {
        var input = Input(clients: new() { ["service-account"] = [ReportingManagement] });

        var plan = FileRoleGrantPlanner.Plan(input, Pairs);

        plan.Edges.Should().Equal(
            new FileRoleGrantEdge(FileRoleGrantSubjectKind.Client, "service-account", FileManagement));
    }

    [Fact]
    public void SubjectsThatAlreadyHoldTheTargetRole_AreSkipped()
    {
        // E.g. TenantOwners after the 1.5.0 blueprint apply, or a re-run after a crash before the marker.
        var input = Input(
            users: new() { ["u"] = [ReportingViewer, FileViewer, ReportingManagement] },
            groups: new() { ["owners"] = [ReportingManagement, ReportingViewer, FileManagement, FileViewer] });

        var plan = FileRoleGrantPlanner.Plan(input, Pairs);

        plan.Edges.Should().Equal(new FileRoleGrantEdge(FileRoleGrantSubjectKind.User, "u", FileManagement));
    }

    [Fact]
    public void ExternalMappings_GetTheTargetRoleAppended_OnlyWhenMissing()
    {
        var input = Input(mappings: new()
        {
            ["m-viewer"] = [ReportingViewer, Development],
            ["m-done"] = [ReportingViewer, FileViewer],
            ["m-junk"] = ["not-a-role-id"]
        });

        var plan = FileRoleGrantPlanner.Plan(input, Pairs);

        plan.Edges.Should().BeEmpty();
        plan.MappingAdditions.Should().ContainSingle();
        plan.MappingAdditions[0].Key.Should().Be("m-viewer");
        plan.MappingAdditions[0].Value.Should().Equal(FileViewer);
    }

    [Fact]
    public void RoleIds_AreComparedCaseInsensitively()
    {
        // MappedRoleIds is a free string list; an upper-case hex id must still count as the role.
        var input = Input(mappings: new() { ["m"] = [ReportingViewer.ToUpperInvariant(), FileViewer.ToUpperInvariant()] });

        FileRoleGrantPlanner.Plan(input, Pairs).IsEmpty.Should().BeTrue();
    }

    [Fact]
    public void MissingSourcePair_GrantsNothingForThatPair()
    {
        // The grant only adds the pairs whose Reporting role exists in the tenant.
        var input = Input(users: new() { ["u"] = [ReportingViewer, ReportingManagement] });

        var plan = FileRoleGrantPlanner.Plan(input, [new FileRoleGrantPair(ReportingViewer, FileViewer)]);

        plan.Edges.Should().Equal(new FileRoleGrantEdge(FileRoleGrantSubjectKind.User, "u", FileViewer));
    }

    [Fact]
    public void EmptyTenant_PlansNothing()
    {
        FileRoleGrantPlanner.Plan(Input(), Pairs).IsEmpty.Should().BeTrue();
    }

    private static FileRoleGrantInput Input(
        Dictionary<string, string[]>? users = null,
        Dictionary<string, string[]>? groups = null,
        Dictionary<string, string[]>? clients = null,
        Dictionary<string, string[]>? mappings = null)
    {
        return new FileRoleGrantInput(Convert(users), Convert(groups), Convert(clients), Convert(mappings));

        static IReadOnlyDictionary<string, IReadOnlySet<string>> Convert(Dictionary<string, string[]>? source) =>
            (source ?? new Dictionary<string, string[]>()).ToDictionary(
                kv => kv.Key,
                kv => (IReadOnlySet<string>)kv.Value.ToHashSet(StringComparer.Ordinal),
                StringComparer.Ordinal);
    }
}
