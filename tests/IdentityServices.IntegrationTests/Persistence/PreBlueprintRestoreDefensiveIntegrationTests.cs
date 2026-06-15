using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     Pins the Mongo-roundtrip behaviour of
///     <see cref="DefaultConfigurationCreatorService.BuildRoleNameIndex"/>.
///     The unit tests in <c>DefaultConfigurationCreatorServiceBuildRoleNameIndexTests</c>
///     cover the duplicate-tolerant build logic against in-memory <see cref="RtRole"/>
///     objects; this one verifies that the same defence holds when the roles come through
///     the real production read path: BSON-roundtripped roles surfaced via
///     <c>tenantRepository.GetRtEntitiesByTypeAsync&lt;RtRole&gt;</c>.
///     Backs ADO #4177 and the test-2 2026-06-15 incident — see the comment block at the
///     top of <c>RestorePendingRoleAssignmentsAsync</c>. The test fixture deliberately
///     does not register the <c>System.Identity.Bootstrap-1.0.0</c> blueprint catalog
///     (that is a <c>Program.cs</c>-only registration), so we materialise both the
///     blueprint-range role and the pre-blueprint orphan ourselves.
/// </summary>
[Collection("Sequential")]
public class PreBlueprintRestoreDefensiveIntegrationTests
    : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public PreBlueprintRestoreDefensiveIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task BuildRoleNameIndex_DuplicateRoleSurvivesMongoRoundtrip_PrefersBlueprintEntry()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();

        // SetupAsync imports the System.Identity CK model so RtRole entities are storable —
        // without this the InsertOneRtEntityAsync call below throws
        // "RtCkTypeId not found in CkCache". Calling it on the system tenant first satisfies
        // the EnsureSystemCkModelAsync guard inside SetupTenantAsync.
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var childTenantId = $"prebp-{Guid.NewGuid():N}"[..24];
        await CreateChildTenantWithSetupAsync(childTenantId);

        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        childRepo.Should().NotBeNull(
            "the child tenant must exist after setup; without a repository the test surface is gone");

        // Materialise both halves of the test-2 2026-06-15 collision state:
        //  1. Blueprint-range role (stable rtId 660…05) — same rtId the
        //     System.Identity.Bootstrap-1.0.0 seed would land in production.
        //  2. Pre-blueprint orphan with the same Name but a 0x68-prefix rtId. In production
        //     this leftover came from the cleanup migration's RtWellKnownName-only gate
        //     (hotfix #93, fixed by #94); the defensive build is the safety net for any
        //     future variant (operator-created duplicate, blueprint-version bump that
        //     lands a new well-known name colliding with an operator role, etc.).
        // PreBlueprintCleanupMigration is not in the test fixture pipeline, so we insert
        // both rows directly and skip the migration story altogether — the unit under test
        // is BuildRoleNameIndex's tolerance to whatever ends up in Mongo.
        var blueprintRtId = new OctoObjectId("660000000000000000000005");
        var orphanRtId = new OctoObjectId("686a5f60fd3e5972ff5693cd");
        await InsertRoleAsync(childRepo!, blueprintRtId, name: "AdminPanelManagement",
            rtWellKnownName: "AdminPanelManagement");
        await InsertRoleAsync(childRepo!, orphanRtId, name: "AdminPanelManagement",
            rtWellKnownName: null);

        // Read back exactly the way RestorePendingRoleAssignmentsAsync does it.
        var roles = await ReadAllRolesAsync(childRepo!);

        // Both rows must survive the Mongo roundtrip — otherwise the dedup path is never
        // even exercised and a green test would not pin anything.
        roles.Should().Contain(r => r.RtId == blueprintRtId,
            "the blueprint-range role must survive the Mongo roundtrip");
        roles.Should().Contain(r => r.RtId == orphanRtId,
            "the orphan must survive the Mongo roundtrip to reach the dedup logic");
        roles.Count(r => r.Name == "AdminPanelManagement").Should().BeGreaterThanOrEqualTo(2,
            "both roles must be present under the same Name so the dedup path triggers");

        var index = DefaultConfigurationCreatorService.BuildRoleNameIndex(
            roles, childTenantId, NullLogger.Instance);

        index.Should().ContainKey("AdminPanelManagement",
            "BuildRoleNameIndex must surface a winner for the duplicate name, not throw");
        index["AdminPanelManagement"].Should().Be(blueprintRtId,
            "the blueprint-range entry must win; without it the post-blueprint role-restore " +
            "would wire AssignedRole edges to the doomed pre-blueprint rtId");
    }

    private async Task CreateChildTenantWithSetupAsync(string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();
        try
        {
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
    }

    private static async Task InsertRoleAsync(
        ITenantRepository repo, OctoObjectId rtId, string name, string? rtWellKnownName)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            var role = new RtRole
            {
                RtId = rtId,
                Name = name,
                NormalizedName = name.ToUpperInvariant(),
            };
            if (rtWellKnownName != null)
            {
                role.RtWellKnownName = rtWellKnownName;
            }
            await repo.InsertOneRtEntityAsync(session, role);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    private static async Task<IReadOnlyList<RtRole>> ReadAllRolesAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtRole>(
            session, RtEntityQueryOptions.Create());
        return result.Items.ToList();
    }
}
