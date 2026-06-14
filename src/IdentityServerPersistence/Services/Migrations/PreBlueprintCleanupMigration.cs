using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
///     Phase 3 PR #4 cleanup: deletes pre-blueprint Identity entities so the
///     <c>System.Identity.Bootstrap-1.0.0</c> blueprint's stable-rtId seed (rtIds in the
///     <c>660…00..660…FF</c> range) is the single source of truth.
/// </summary>
/// <remarks>
///     <para>
///         Before PR #4 the imperative seed in <c>DefaultConfigurationCreatorService</c> created
///         every <see cref="RtRole"/> / <see cref="RtIdentityResource"/> / <see cref="RtApiScope"/>
///         / <see cref="RtApiResource"/> / <see cref="RtClient"/> / <see cref="RtGroup"/> with a
///         random <see cref="OctoObjectId"/> (created via <c>OctoObjectId.GenerateNewId()</c> or
///         IdentityServer-derived stores). Phase 3 PR #2 then introduced stable rtIds in the
///         <c>660…01..40</c> range for the blueprint seed.
///     </para>
///     <para>
///         If both seeds run against the same tenant (a freshly-deployed PR #4 against a tenant
///         that was provisioned by the imperative seed) the result is duplicate entities with the
///         same OIDC <c>Name</c> but different rtIds. Duende's <c>ValidateNameUniqueness</c>
///         then crashes IdentityServer with <em>"Duplicate identity scopes found"</em>, taking
///         every OIDC flow with it.
///     </para>
///     <para>
///         This migration runs once per tenant via the standard <see cref="MigrationService"/>
///         framework (tracked under <c>IdentityServiceMigrations</c> in
///         <see cref="IdentityServiceConstants.IdentityMigrationVersionKey"/>) and deletes every
///         entity whose rtId is <strong>not</strong> in the blueprint's stable range. Anything in
///         the <c>660…00..660…FF</c> range was authored by the blueprint and survives; anything
///         else is pre-blueprint residue and goes.
///     </para>
///     <para>
///         Ordering inside <c>SetupTenantAsync</c>: the migration runs <em>before</em>
///         <c>ApplyServiceManagedBlueprintsAsync</c>, so the sequence on a pre-blueprint tenant
///         is: clean OLD → blueprint apply → clean DB with only stable-rtId entities.
///         <see cref="IClientMirrorProvisioningService"/> rebuilds the auto-provisioned mirror
///         <see cref="RtClient"/> rows on the same startup, so child tenants do not stay without
///         their parent-tenant client mirrors for longer than the rest of the startup loop.
///     </para>
/// </remarks>
[Migration(17, 18, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Phase 3 PR #4: clean up pre-blueprint Identity entities so System.Identity.Bootstrap is single source of truth")]
// ReSharper disable once UnusedType.Global
internal class PreBlueprintCleanupMigration(
    ILogger<PreBlueprintCleanupMigration> logger) : IMigration
{
    /// <summary>
    ///     Inclusive lower bound of the stable rtId range used by
    ///     <c>System.Identity.Bootstrap-1.0.0</c> seed entities. The first byte of every blueprint
    ///     rtId is <c>0x66</c>; everything strictly less than this value is pre-blueprint.
    /// </summary>
    private static readonly OctoObjectId BlueprintRangeStart =
        new("660000000000000000000000");

    /// <summary>
    ///     Exclusive upper bound. ObjectId comparison is byte-by-byte, so anything &gt;= this is
    ///     outside the blueprint range.
    /// </summary>
    private static readonly OctoObjectId BlueprintRangeEndExclusive =
        new("670000000000000000000000");

    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
            using var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var totalDeleted = 0;
            totalDeleted += await DeletePreBlueprintEntitiesAsync<RtRole>(
                tenantRepository, session, tenantContext.TenantId);
            totalDeleted += await DeletePreBlueprintEntitiesAsync<RtIdentityResource>(
                tenantRepository, session, tenantContext.TenantId);
            totalDeleted += await DeletePreBlueprintEntitiesAsync<RtApiScope>(
                tenantRepository, session, tenantContext.TenantId);
            totalDeleted += await DeletePreBlueprintEntitiesAsync<RtApiResource>(
                tenantRepository, session, tenantContext.TenantId);
            totalDeleted += await DeletePreBlueprintEntitiesAsync<RtClient>(
                tenantRepository, session, tenantContext.TenantId);
            totalDeleted += await DeletePreBlueprintEntitiesAsync<RtGroup>(
                tenantRepository, session, tenantContext.TenantId);

            await session.CommitTransactionAsync();

            logger.LogInformation(
                "Pre-blueprint cleanup completed for tenant '{TenantId}': {Deleted} entities deleted. " +
                "System.Identity.Bootstrap blueprint will land its stable-rtId seed on the next ApplyBlueprint call.",
                tenantContext.TenantId, totalDeleted);

            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Pre-blueprint cleanup failed for tenant '{TenantId}'", tenantContext.TenantId);
            return MigrationResult.Failure($"Pre-blueprint cleanup failed: {e.Message}");
        }
    }

    /// <summary>
    ///     Loads every entity of <typeparamref name="TEntity"/>, keeps the ones whose rtId is in
    ///     the blueprint range, and deletes the rest one by one. Each delete uses
    ///     <see cref="DeleteOptions.Erase"/> so the entity is fully removed (not soft-deleted) —
    ///     the blueprint apply that runs immediately after must see a clean collection so its
    ///     stable-rtId upsert lands as an Insert, not as a duplicate-key conflict.
    /// </summary>
    private async Task<int> DeletePreBlueprintEntitiesAsync<TEntity>(
        ITenantRepository tenantRepository,
        IOctoSession session,
        string tenantId)
        where TEntity : RtEntity, new()
    {
        var result = await tenantRepository
            .GetRtEntitiesByTypeAsync<TEntity>(session, RtEntityQueryOptions.Create());

        var deleted = 0;
        foreach (var entity in result.Items)
        {
            if (IsBlueprintRtId(entity.RtId))
            {
                continue;
            }

            await tenantRepository.DeleteOneRtEntityByRtIdAsync<TEntity>(
                session, entity.RtId, DeleteOptions.Erase);
            deleted++;
        }

        if (deleted > 0)
        {
            logger.LogInformation(
                "Pre-blueprint cleanup: deleted {Count} {Type} entities outside the stable rtId range for tenant '{TenantId}'",
                deleted, typeof(TEntity).Name, tenantId);
        }

        return deleted;
    }

    /// <summary>
    ///     True when <paramref name="rtId"/>'s underlying <see cref="OctoObjectId"/> falls inside
    ///     the blueprint's stable range. ObjectId comparison is byte-by-byte; the first byte of
    ///     every blueprint rtId is <c>0x66</c>.
    /// </summary>
    private static bool IsBlueprintRtId(OctoObjectId rtId)
    {
        return rtId.CompareTo(BlueprintRangeStart) >= 0
               && rtId.CompareTo(BlueprintRangeEndExclusive) < 0;
    }
}
