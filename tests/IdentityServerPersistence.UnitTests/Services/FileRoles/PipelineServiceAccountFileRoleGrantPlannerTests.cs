using FluentAssertions;
using IdentityServerPersistence.Services.FileRoles;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.FileRoles;

/// <summary>
///     AB#6467 / AB#6457: the pure rule of the pipeline service account grant — only <c>octo-pipeline-sa-*</c>
///     clients that do not hold FileManagement yet are listed.
/// </summary>
public class PipelineServiceAccountFileRoleGrantPlannerTests
{
    private const string FileManagement = "660000000000000000000061";
    private const string CommunicationManagement = "660000000000000000000003";

    private static IReadOnlySet<string> Roles(params string[] ids) => ids.ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void ExistingPipelineServiceAccountWithoutTheRole_IsListed()
    {
        var plan = PipelineServiceAccountFileRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("octo-pipeline-sa-aaa", Roles(CommunicationManagement)),
            ["c2"] = ("octo-pipeline-sa-bbb", Roles())
        }, FileManagement);

        plan.Should().Equal("c1", "c2");
    }

    [Fact]
    public void AccountThatHoldsTheRole_IsNotListed_SoARepeatedRunWritesNothing()
    {
        var plan = PipelineServiceAccountFileRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("octo-pipeline-sa-aaa", Roles(CommunicationManagement, FileManagement.ToUpperInvariant()))
        }, FileManagement);

        plan.Should().BeEmpty();
    }

    [Fact]
    public void ClientsOutsideThePrefix_AreNeverListed()
    {
        var plan = PipelineServiceAccountFileRoleGrant.Plan(new Dictionary<string, (string, IReadOnlySet<string>)>
        {
            ["c1"] = ("customer-integration", Roles()),
            ["c2"] = ("octo-tool", Roles()),
            ["c3"] = ("my-octo-pipeline-sa-x", Roles()),
            ["c4"] = ("OCTO-PIPELINE-SA-upper", Roles())
        }, FileManagement);

        plan.Should().BeEmpty("only the exact lower-case prefix identifies the controller's accounts");
    }
}
