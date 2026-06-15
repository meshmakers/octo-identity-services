using FluentAssertions;
using IdentityServerPersistence.Services.Migrations;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Engine.Repositories.Query;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.Migrations;

/// <summary>
///     Regression coverage for the two hotfix iterations of <see cref="PreBlueprintCleanupMigration"/>:
///     <list type="number">
///         <item>over-deletion (incident #1, test-2 2026-06-15): operator-created entities outside
///             the 660… range must survive — every test here asserts a counter-example for a
///             custom Role / ClientId / GroupName whose name is NOT on the imperative-seed
///             whitelist.</item>
///         <item>under-deletion / duplicate-key crash (incident #2, test-2 2026-06-15): the
///             first hotfix gated by <c>RtWellKnownName</c>, but pre-PR-#4 imperative-seed
///             entities always had that column null. The corrected gate checks the primary name
///             attribute (<c>RtRole.Name</c>, <c>RtClient.ClientId</c>, <c>RtGroup.GroupName</c>)
///             against a per-type whitelist. The first three tests cover Role; the trailing two
///             cover Client (ClientId selector) and Group (GroupName selector) so a future
///             regression on the selector wiring is caught even if only one entity type is the
///             actual victim in production.</item>
///     </list>
/// </summary>
public class PreBlueprintCleanupMigrationTests
{
    private readonly PreBlueprintCleanupMigration _sut = new(
        NullLogger<PreBlueprintCleanupMigration>.Instance);

    private readonly ITenantContext _tenantContext = Substitute.For<ITenantContext>();
    private readonly ITenantRepository _tenantRepository = Substitute.For<ITenantRepository>();
    private readonly IOctoAdminSession _adminSession = Substitute.For<IOctoAdminSession>();
    private readonly FakeOctoSession _session = new();

    private static readonly OctoObjectId BlueprintRoleRtId =
        new("660000000000000000000005"); // AdminPanelManagement in the blueprint seed
    private static readonly OctoObjectId BlueprintClientRtId =
        new("660000000000000000000020"); // RefineryStudioClient slot
    private static readonly OctoObjectId BlueprintGroupRtId =
        new("660000000000000000000040"); // TenantOwners slot

    public PreBlueprintCleanupMigrationTests()
    {
        _tenantContext.TenantId.Returns("test-tenant");
        _tenantContext.GetTenantRepositoryAsAdmin().Returns(_tenantRepository);
        _tenantRepository.GetSessionAsync().Returns(Task.FromResult<IOctoSession>(_session));

        // Every CapturePendingRoleAssignments / DeleteOrphanIdentityAssociations call path needs
        // an empty IResultSet on every type the migration touches. Each test below overrides only
        // the type whose gate is under test.
        SetupEmpty<RtUser>();
        SetupEmpty<RtExternalTenantUserMapping>();
        SetupEmpty<RtRole>();
        SetupEmpty<RtIdentityResource>();
        SetupEmpty<RtApiScope>();
        SetupEmpty<RtApiResource>();
        SetupEmpty<RtClient>();
        SetupEmpty<RtGroup>();
    }

    // -------- Role -----------------------------------------------------------------------------

    [Fact]
    public async Task MigrateAsync_PreBlueprintRoleWithNullRtWellKnownName_IsDeletedByNameGate()
    {
        // The exact shape that the broken hotfix #93 left on disk on test-2 2026-06-15:
        // attributes.name = imperative-seed value, rtWellKnownName = null because the legacy
        // CreateDefaultRoles path never wrote that column. The corrected gate must still
        // recognise this as imperative-seed residue.
        var preBlueprintAdminPanelMgmt = new RtRole
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693cd"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
            // RtWellKnownName intentionally not set — this is the bug-reproduction shape.
        };

        SetupRoles(preBlueprintAdminPanelMgmt);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.Received(1).DeleteOneRtEntityByRtIdAsync<RtRole>(
            _session, preBlueprintAdminPanelMgmt.RtId, DeleteOptions.Erase);
    }

    [Fact]
    public async Task MigrateAsync_OperatorRoleOutsideWhitelist_IsPreserved()
    {
        // Operator-created role — same shape (rtWellKnownName null, random rtId) but the Name is
        // NOT in KnownPreBlueprintRoleNames. Must survive the migration. Without per-type
        // partitioning a single-set whitelist could collide with API-scope names like "octo_api".
        var operatorRole = new RtRole
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693ff"),
            Name = "DataPlatformOperator",
            NormalizedName = "DATAPLATFORMOPERATOR",
        };

        SetupRoles(operatorRole);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtRole>(
            _session, operatorRole.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task MigrateAsync_BlueprintRole_IsPreservedRegardlessOfName()
    {
        // Already in the 660… range — never touched. This guards against a future refactor that
        // accidentally swaps the order of the range check and the name check.
        var blueprintRole = new RtRole
        {
            RtId = BlueprintRoleRtId,
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
            RtWellKnownName = "AdminPanelManagement",
        };

        SetupRoles(blueprintRole);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtRole>(
            _session, blueprintRole.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task MigrateAsync_MixedRoles_DeletesOnlyImperativeSeedNames()
    {
        var blueprintAdminPanelMgmt = new RtRole
        {
            RtId = BlueprintRoleRtId,
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
            RtWellKnownName = "AdminPanelManagement",
        };
        var preBlueprintAdminPanelMgmt = new RtRole
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693cd"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
        };
        var operatorRole = new RtRole
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693ff"),
            Name = "DataPlatformOperator",
            NormalizedName = "DATAPLATFORMOPERATOR",
        };

        SetupRoles(blueprintAdminPanelMgmt, preBlueprintAdminPanelMgmt, operatorRole);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.Received(1).DeleteOneRtEntityByRtIdAsync<RtRole>(
            _session, preBlueprintAdminPanelMgmt.RtId, DeleteOptions.Erase);
        await _tenantRepository.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtRole>(
            _session, blueprintAdminPanelMgmt.RtId, Arg.Any<DeleteOptions>());
        await _tenantRepository.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtRole>(
            _session, operatorRole.RtId, Arg.Any<DeleteOptions>());
    }

    // -------- Client (ClientId selector, not Name) ----------------------------------------------

    [Fact]
    public async Task MigrateAsync_PreBlueprintClientByClientId_IsDeleted()
    {
        // RtClient uses ClientId, not Name. The per-type selector wiring must use it.
        var preBlueprintOctoToolClient = new RtClient
        {
            RtId = new OctoObjectId("686a5f5ffd3e5972ff5693c7"),
            ClientId = "OctoToolClient",
            ClientName = "Octo Tool Client",
        };

        SetupClients(preBlueprintOctoToolClient);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.Received(1).DeleteOneRtEntityByRtIdAsync<RtClient>(
            _session, preBlueprintOctoToolClient.RtId, DeleteOptions.Erase);
    }

    [Fact]
    public async Task MigrateAsync_OperatorClientWithCustomClientId_IsPreserved()
    {
        // ci-deploy-test-2 is the exact client name the broken hotfix had to be written for.
        // Asserting it survives ensures we never re-ship the over-deletion bug for the entity
        // type that originally tripped it.
        var ciDeployClient = new RtClient
        {
            RtId = new OctoObjectId("6a0dda9dd644fadf1297a417"),
            ClientId = "ci-deploy-test-2",
            ClientName = "CI Deploy (test-2)",
        };

        SetupClients(ciDeployClient);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtClient>(
            _session, ciDeployClient.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task MigrateAsync_BlueprintClient_IsPreserved()
    {
        var blueprintRefineryStudioClient = new RtClient
        {
            RtId = BlueprintClientRtId,
            ClientId = "RefineryStudioClient",
            ClientName = "Refinery Studio Client",
            RtWellKnownName = "RefineryStudioClient",
        };

        SetupClients(blueprintRefineryStudioClient);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtClient>(
            _session, blueprintRefineryStudioClient.RtId, Arg.Any<DeleteOptions>());
    }

    // -------- Group (GroupName selector) --------------------------------------------------------

    [Fact]
    public async Task MigrateAsync_PreBlueprintGroupByGroupName_IsDeleted()
    {
        var preBlueprintTenantOwners = new RtGroup
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693e0"),
            GroupName = "TenantOwners",
            NormalizedGroupName = "TENANTOWNERS",
        };

        SetupGroups(preBlueprintTenantOwners);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.Received(1).DeleteOneRtEntityByRtIdAsync<RtGroup>(
            _session, preBlueprintTenantOwners.RtId, DeleteOptions.Erase);
    }

    [Fact]
    public async Task MigrateAsync_OperatorGroupWithCustomGroupName_IsPreserved()
    {
        var operatorGroup = new RtGroup
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693e1"),
            GroupName = "FdaUsers", // common AD-mapped operator group on production
            NormalizedGroupName = "FDAUSERS",
        };

        SetupGroups(operatorGroup);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtGroup>(
            _session, operatorGroup.RtId, Arg.Any<DeleteOptions>());
    }

    // -------- Helpers --------------------------------------------------------------------------

    private void SetupEmpty<TEntity>() where TEntity : RtEntity, new()
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync<TEntity>(_session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<TEntity>>(
                new ResultSet<TEntity>(Array.Empty<TEntity>(), 0, null, null)));
    }

    private void SetupRoles(params RtRole[] roles)
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtRole>(_session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtRole>>(
                new ResultSet<RtRole>(roles, roles.Length, null, null)));
    }

    private void SetupClients(params RtClient[] clients)
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtClient>(_session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtClient>>(
                new ResultSet<RtClient>(clients, clients.Length, null, null)));
    }

    private void SetupGroups(params RtGroup[] groups)
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtGroup>(_session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtGroup>>(
                new ResultSet<RtGroup>(groups, groups.Length, null, null)));
    }
}
