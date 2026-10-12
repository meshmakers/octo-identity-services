using FluentAssertions;
using IdentityServerPersistence.Services.FileRoles;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.FileRoles;

/// <summary>AB#6542: report assembly for the pipeline service account FileManagement proof.</summary>
public class PipelineServiceAccountFileRoleReportTests
{
    private const string FileManagement = "660000000000000000000061";
    private const string CommunicationManagement = "660000000000000000000003";

    private static IReadOnlySet<string> Roles(params string[] ids) => ids.ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void AccountWithGrant_IsCovered()
    {
        var r = PipelineServiceAccountFileRoleReport.Build("t", true, FileManagement,
            new Dictionary<string, (string, IReadOnlySet<string>)>
            {
                ["c1"] = ("octo-pipeline-sa-aaa", Roles(CommunicationManagement, FileManagement))
            });

        r.Status.Should().Be(PipelineServiceAccountFileRoleReportStatus.AllCovered);
        r.MissingCount.Should().Be(0);
        r.Accounts.Should().ContainSingle().Which.HasFileManagement.Should().BeTrue();
    }

    [Fact]
    public void AccountWithoutGrant_IsMissing_AndOtherClientsAreIgnored()
    {
        var r = PipelineServiceAccountFileRoleReport.Build("t", true, FileManagement,
            new Dictionary<string, (string, IReadOnlySet<string>)>
            {
                ["c1"] = ("octo-pipeline-sa-aaa", Roles(CommunicationManagement)),
                ["c2"] = ("octo-pipeline-sa-bbb", Roles(FileManagement)),
                ["c3"] = ("some-other-client", Roles())
            });

        r.Status.Should().Be(PipelineServiceAccountFileRoleReportStatus.MissingGrants);
        r.MissingCount.Should().Be(1);
        r.Accounts.Select(a => (a.ClientId, a.HasFileManagement))
            .Should().Equal(("octo-pipeline-sa-aaa", false), ("octo-pipeline-sa-bbb", true));
    }

    [Fact]
    public void NoPipelineAccounts_ReportsNoAccounts()
    {
        var r = PipelineServiceAccountFileRoleReport.Build("t", true, FileManagement,
            new Dictionary<string, (string, IReadOnlySet<string>)> { ["c3"] = ("some-other-client", Roles()) });

        r.Status.Should().Be(PipelineServiceAccountFileRoleReportStatus.NoAccounts);
        r.Accounts.Should().BeEmpty();
    }

    [Fact]
    public void TenantWithoutFilesModel_IsNotApplicable_NotMissing()
    {
        var r = PipelineServiceAccountFileRoleReport.Build("t", false, null,
            new Dictionary<string, (string, IReadOnlySet<string>)> { ["c1"] = ("octo-pipeline-sa-aaa", Roles()) });

        r.Status.Should().Be(PipelineServiceAccountFileRoleReportStatus.NotApplicable);
        r.MissingCount.Should().Be(0);
    }

    [Fact]
    public void MissingRole_IsReportedAsRoleMissing()
    {
        var r = PipelineServiceAccountFileRoleReport.Build("t", true, null,
            new Dictionary<string, (string, IReadOnlySet<string>)> { ["c1"] = ("octo-pipeline-sa-aaa", Roles()) });

        r.Status.Should().Be(PipelineServiceAccountFileRoleReportStatus.RoleMissing);
    }
}
