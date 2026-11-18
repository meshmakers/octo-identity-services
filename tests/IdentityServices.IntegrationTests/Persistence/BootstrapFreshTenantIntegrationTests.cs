using System.Text.RegularExpressions;
using FluentAssertions;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Exchange;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     the creates of <c>Client</c> and <c>DataPermission</c> are static methods since System.Identity 3.8.0, without
///     <c>replacesGenericCreate</c> (a Major on these existing types). A fresh tenant on the 3.8.0 model must therefore still get
///     every seed of <c>System.Identity.Bootstrap</c>: the test creates a new child tenant, runs identity's tenant setup (imports
///     the compiled System.Identity model), installs the complete <c>seed-data</c> of the blueprint through the system import the
///     blueprint apply uses (blueprint variables replaced by test values, as the variable provider does), runs the setup again and
///     checks the seeded clients, data permissions and roles. The test fixtures register no blueprint catalog, so the catalog
///     resolution itself is not part of this test; the import path and the model are. The blueprint seeds no identity provider.
/// </summary>
[Collection("Sequential")]
public class BootstrapFreshTenantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    // The five client seeds of System.Identity.Bootstrap (seed-data/clients/*.yaml, stable rtIds).
    private static readonly string[] SeededClientRtIds =
    [
        "660000000000000000000030", "660000000000000000000031", "660000000000000000000032", "660000000000000000000033",
        "660000000000000000000034"
    ];

    private static readonly Regex BlueprintVariable = new(@"\$\{[A-Za-z0-9_.]+\}", RegexOptions.Compiled);

    private readonly IdentityServicesFixture _fixture;

    public BootstrapFreshTenantIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task AFreshTenant_GetsTheBootstrapClientsDataPermissionsAndRoles_OnSystemIdentity380()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"bsfresh-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await setup.SetupAsync(tenantId);
        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        var repo = tenantContext.GetTenantRepositoryAsAdmin();

        await ImportBootstrapSeedDataAsync(repo);
        await setup.SetupAsync(tenantId);

        using var check = await repo.GetSessionAsync();
        check.StartTransaction();
        foreach (var rtId in SeededClientRtIds)
        {
            var client = await repo.GetRtEntityByRtIdAsync<RtClient>(check, OctoObjectId.Parse(rtId));
            client.Should().NotBeNull($"Bootstrap client {rtId} is seeded");
            client!.ClientId.Should().NotBeNullOrEmpty();
        }

        (await repo.GetRtEntitiesByTypeAsync<RtDataPermission>(check, RtEntityQueryOptions.Create())).Items.Should()
            .NotBeEmpty("the Bootstrap data permissions are seeded");
        (await repo.GetRtEntitiesByTypeAsync<RtRole>(check, RtEntityQueryOptions.Create())).Items.Should()
            .NotBeEmpty("and the roles");
        await check.CommitTransactionAsync();
    }

    /// <summary>
    ///     Every seed file of the blueprint as one logical import: two passes, so an association to an entity of a later file
    ///     is materialised in the second pass (the blueprint applies all files in one import).
    /// </summary>
    private async Task ImportBootstrapSeedDataAsync(ITenantRepository repo)
    {
        var directory = FindRepoFile("src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data");
        var files = Directory.GetFiles(directory, "*.yaml", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
            .ToList();
        files.Should().Contain(f => f.Contains("clients", StringComparison.Ordinal));
        var import = _fixture.GetService<IImportRtModelCommand>();
        for (var pass = 0; pass < 2; pass++)
        {
            foreach (var file in files)
            {
                var yaml = await File.ReadAllTextAsync(file, TestContext.Current.CancellationToken);
                // Values of the blueprint variables (URLs, the tenant slug), as IdentityBlueprintVariableProvider gives them.
                yaml = BlueprintVariable.Replace(yaml, "https://fresh.example.test");
                await import.ImportTextAsync(repo, yaml, ImportStrategy.Upsert);
            }
        }
    }

    private static string FindRepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Octo.Identity.sln")))
        {
            dir = dir.Parent;
        }

        return dir == null
            ? throw new FileNotFoundException("Octo.Identity.sln not found above the test binaries.")
            : Path.Combine(dir.FullName, relativePath);
    }
}
