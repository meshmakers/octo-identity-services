using FluentAssertions;
using IdentityServerPersistence.Services.PipelineServiceAccounts;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.PipelineServiceAccounts;

/// <summary>
///     AB#6467 / AB#6457 / AB#8581: the pure rule of the pipeline service account grant — only <c>octo-pipeline-sa-*</c>
///     clients are listed, once per baseline role they do not hold yet.
/// </summary>
public class PipelineServiceAccountRoleGrantPlannerTests
{
    private const string FileManagement = "660000000000000000000061";
    private const string StreamDataReader = "66000000000000000000000E";
    private const string CommunicationManagement = "660000000000000000000003";

    private static readonly string[] BaselineRoleIds = [FileManagement, StreamDataReader];

    private static IReadOnlySet<string> Roles(params string[] ids) => ids.ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void ExistingPipelineServiceAccountWithoutTheRoles_IsListedOncePerMissingRole()
    {
        var plan = PipelineServiceAccountRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("octo-pipeline-sa-aaa", Roles(CommunicationManagement)),
            ["c2"] = ("octo-pipeline-sa-bbb", Roles(FileManagement))
        }, BaselineRoleIds);

        // Ordered by client rtId, then role rtId (ordinal: 660…0E before 660…61).
        plan.Should().Equal(
            new PipelineServiceAccountRoleGrantEdge("c1", StreamDataReader),
            new PipelineServiceAccountRoleGrantEdge("c1", FileManagement),
            new PipelineServiceAccountRoleGrantEdge("c2", StreamDataReader));
    }

    [Fact]
    public void AccountThatHoldsTheRoles_IsNotListed_SoARepeatedRunWritesNothing()
    {
        var plan = PipelineServiceAccountRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("octo-pipeline-sa-aaa",
                Roles(CommunicationManagement, FileManagement.ToUpperInvariant(), StreamDataReader.ToLowerInvariant()))
        }, BaselineRoleIds);

        plan.Should().BeEmpty("role ids are compared case-insensitively");
    }

    [Fact]
    public void LegacyAccountWithOtherRoles_IsOnlyGivenTheMissingRole_NothingIsRemoved()
    {
        // The plan only ever inserts; the roles an account already holds are not part of the output at all.
        var plan = PipelineServiceAccountRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("octo-pipeline-sa-legacy", Roles(CommunicationManagement, "custom-role", FileManagement))
        }, [StreamDataReader]);

        plan.Should().Equal(new PipelineServiceAccountRoleGrantEdge("c1", StreamDataReader));
    }

    [Fact]
    public void NoSeededRoles_PlansNothing()
    {
        var plan = PipelineServiceAccountRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("octo-pipeline-sa-aaa", Roles())
        }, []);

        plan.Should().BeEmpty("only roles that exist in the tenant are granted");
    }

    [Fact]
    public void ClientsOutsideThePrefix_AreNeverListed()
    {
        var plan = PipelineServiceAccountRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("customer-integration", Roles()),
            ["c2"] = ("octo-tool", Roles()),
            ["c3"] = ("my-octo-pipeline-sa-x", Roles()),
            ["c4"] = ("OCTO-PIPELINE-SA-upper", Roles())
        }, BaselineRoleIds);

        plan.Should().BeEmpty("only the exact lower-case prefix identifies the controller's accounts");
    }
}
