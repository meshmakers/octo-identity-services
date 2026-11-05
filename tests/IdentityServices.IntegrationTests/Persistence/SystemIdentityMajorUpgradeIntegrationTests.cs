using FluentAssertions;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts.Serialization;
using Meshmakers.Octo.Runtime.Contracts.CkModelMigrations;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#8157: a tenant that holds a published System.Identity 2.x is upgraded to the embedded System.Identity 3.x through the
///     same path the service uses on every tenant setup / resolve (<c>IDefaultConfigurationCreatorService.SetupAsync</c> ->
///     <c>ImportCkModelAsync(embedded)</c> -> migration path finder with the migration-meta of the embedded model). System.Identity 3.0.0
///     shipped without a migration entry from 2.x and the engine refused the upgrade of every tenant ("No migration path found",
///     <c>CkMigrationMajorVersionGuard</c>) and stopped the host. The start model is the real published 2.30.0
///     (<c>TestData/ck-system.identity-2.30.0.json</c>); <c>EveryReleased2xMinor_HasAMigrationPathToTheEmbedded3x</c> asks the
///     migration path finder (real embedded migration-meta) for every 2.x minor from 2.0.0. Real MongoDB.
/// </summary>
public class SystemIdentityMajorUpgradeIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public SystemIdentityMajorUpgradeIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task TenantOnSystemIdentity230_UpgradesToTheEmbedded3x_WhenTheServiceSetsItUp()
    {
        const string startVersion = "2.30.0";
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"idmaj-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        try
        {
            var tenant = await systemContext.FindTenantContextAsync(tenantId);

            var path = Path.Combine(AppContext.BaseDirectory, "TestData", "ck-system.identity-2.30.0.json");
            var published = await _fixture.GetService<ICkJsonSerializer>()
                .DeserializeCompiledModelRootAsync(await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken),
                    path, new OperationResult());
            await tenant.ImportCkModelAsync(published);
            (await tenant.IsCkModelExistingAsync(new CkModelId($"System.Identity-{startVersion}"))).Should().BeTrue();

            // The service's own path: the embedded System.Identity of this build is imported over the old major.
            await setup.SetupAsync(tenantId);

            var embedded = SystemIdentityCkIds.CkModelId;
            embedded.Version.Major.Should().Be(3);
            (await tenant.IsCkModelExistingAsync(embedded)).Should().BeTrue(
                $"the tenant on 2.x ({startVersion}) must end on the embedded {embedded}");
            (await tenant.IsCkModelExistingAsync(new CkModelId($"System.Identity-{startVersion}"))).Should().BeFalse();
        }
        finally
        {
            try
            {
                using var session = await systemContext.GetAdminSessionAsync();
                session.StartTransaction();
                await systemContext.DropChildTenantAsync(session, tenantId);
                await session.CommitTransactionAsync();
            }
            catch
            {
                // best-effort cleanup
            }
        }
    }

    [Theory]
    [MemberData(nameof(AllTwoXMinors))]
    public async Task EveryReleased2xMinor_HasAMigrationPathToTheEmbedded3x(string startVersion)
    {
        await _fixture.InitializeAsync();
        var embedded = SystemIdentityCkIds.CkModelId;

        var path = await _fixture.GetService<ICkModelMigrationService>()
            .FindMigrationPathAsync(new CkModelId($"System.Identity-{startVersion}"), embedded,
                TestContext.Current.CancellationToken);

        path.Should().NotBeNull($"System.Identity-{startVersion} -> {embedded} must not be refused as a schema-only bridge across a major");
        path!.Steps.Should().NotBeEmpty();
        // The migration chain crosses the major (2.x -> 3.0.1, AB#8157); a later 3.x minor (3.1.0, AB#8095) is reached by
        // the schema-only bridge inside the major, so the chain ends in the embedded major at or below the embedded version.
        // That a 2.x tenant really ends on the embedded version is proven by the upgrade test above.
        var end = Version.Parse(path.Steps[^1].ToVersion);
        end.Major.Should().Be(embedded.Version.Major, "the chain must cross the major; only the in-major bridge may follow");
        end.Should().BeLessThanOrEqualTo(new Version(embedded.Version.ToString()));
    }

    public static TheoryData<string> AllTwoXMinors() => new(Enumerable.Range(0, 31).Select(n => $"2.{n}.0"));
}
