using FluentAssertions;
using IdentityServerPersistence.Services.PipelineServiceAccounts;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.PipelineServiceAccounts;

/// <summary>AB#8581: the single list of roles identity grants to every pipeline service account.</summary>
public class PipelineServiceAccountBaselineRolesTests
{
    [Fact]
    public void TheBaselineIsFileManagementAndStreamDataReader()
    {
        PipelineServiceAccountBaselineRoles.All.Select(r => r.RoleName).Should()
            .BeEquivalentTo(IdentityServiceConstants.FileManagementRole, IdentityServiceConstants.StreamDataReaderRole);
    }

    [Fact]
    public void TenantSetup_WithoutSystemFiles_GrantsStreamDataReaderOnly()
    {
        PipelineServiceAccountBaselineRoles.ForTenantSetup(tenantHasFilesModel: false).Should()
            .Equal(IdentityServiceConstants.StreamDataReaderRole);
        PipelineServiceAccountBaselineRoles.ForTenantSetup(tenantHasFilesModel: true).Should()
            .BeEquivalentTo(IdentityServiceConstants.FileManagementRole, IdentityServiceConstants.StreamDataReaderRole);
    }

    [Fact]
    public void IdentityDataCommand_GrantsEveryBaselineRole()
    {
        PipelineServiceAccountBaselineRoles.ForIdentityDataCommand().Should()
            .BeEquivalentTo(PipelineServiceAccountBaselineRoles.All.Select(r => r.RoleName));
    }

    [Theory]
    [InlineData("octo-pipeline-sa-6650a1b2c3d4e5f6a7b8c9d0", true)]
    [InlineData("octo-pipeline-sa-", true)]
    [InlineData("OCTO-PIPELINE-SA-x", false)]
    [InlineData("my-octo-pipeline-sa-x", false)]
    [InlineData("octo-tool", false)]
    [InlineData(null, false)]
    public void OnlyTheExactCaseSensitivePrefixIsAPipelineServiceAccount(string? clientId, bool expected)
    {
        PipelineServiceAccountBaselineRoles.IsPipelineServiceAccount(clientId).Should().Be(expected);
    }

    [Fact]
    public void EveryBaselineRoleIsSeededByTheBootstrapBlueprint()
    {
        // The roles are resolved by name in the tenant; a name the seed does not carry would silently grant nothing.
        var rolesSeed = File.ReadAllLines(Path.Combine(FindRepositoryRoot(), "src", "Persistence.IdentityCkModel",
            "Blueprints", "System.Identity.Bootstrap", "seed-data", "roles.yaml"));

        foreach (var role in PipelineServiceAccountBaselineRoles.All)
        {
            rolesSeed.Should().Contain(line => line.Trim() == $"rtWellKnownName: {role.RoleName}", role.RoleName);
        }
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Octo.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Octo.Identity.sln not found");
    }
}
