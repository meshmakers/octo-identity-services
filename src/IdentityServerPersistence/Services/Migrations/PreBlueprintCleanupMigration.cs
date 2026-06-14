using IdentityServerPersistence.SystemStores;
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

            // Phase 1 of Phase 3 PR #4 cutover: capture User → Role and
            // ExternalTenantUserMapping → Role assignments BY NAME before any deletion. Persisted
            // in SystemConfiguration[PendingPostBlueprintRoleAssignmentsKey] and consumed by
            // DefaultConfigurationCreatorService.SetupTenantAsync after the blueprint has created
            // the NEW Role entities with stable rtIds.
            var pending = await CapturePendingRoleAssignmentsAsync(
                tenantRepository, session, tenantContext, adminSession);

            // Order matters: clean the associations FIRST while their targets still exist.
            // The engine's ApplyChangesAsync validates target existence even for delete edges,
            // so deleting Role/Client/Group entities BEFORE their inbound edges would fail with
            // "Entity '...' does not exist" on the orphan-edge sweep.
            var orphanedAssociations = await DeleteOrphanIdentityAssociationsAsync(
                tenantRepository, session, tenantContext.TenantId);

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
                "Pre-blueprint cleanup completed for tenant '{TenantId}': {Deleted} entities deleted, " +
                "{OrphanAssociations} orphan associations removed, " +
                "{PendingUsers} users + {PendingMappings} external mappings queued for post-blueprint " +
                "role reassignment. System.Identity.Bootstrap blueprint will land its stable-rtId " +
                "seed on the next ApplyBlueprint call.",
                tenantContext.TenantId, totalDeleted, orphanedAssociations,
                pending.UserRoles.Count, pending.ExternalMappingRoles.Count);

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

    /// <summary>
    ///     Walks every RtAssociation in the tenant, drops the rows whose target points at a
    ///     System.Identity entity outside the blueprint's stable rtId range. Covers the User →
    ///     Role assignments that the deleted user-store rows still carried, as well as any
    ///     surviving Group → Role / Group → User associations that the entity-cleanup pass
    ///     left dangling (the entity rows are gone but the inbound edges survived).
    /// </summary>
    private async Task<int> DeleteOrphanIdentityAssociationsAsync(
        ITenantRepository tenantRepository,
        IOctoSession session,
        string tenantId)
    {
        // The engine exposes outbound-association reads per origin entity, not a bulk
        // "give me every association" query. Walk Users (the CK type that owns an outbound
        // AssignedRole edge per the System.Identity schema) and drop edges whose target sits
        // outside the blueprint's stable rtId range. Group → Role edges are owned by RtGroup;
        // the only group that survives this migration is the new TenantOwners (rtId 660…40,
        // recreated by the blueprint), so any pre-existing group-side orphan is already gone
        // with the entity itself. ExternalTenantUserMapping does NOT carry AssignedRole
        // associations (the schema disallows it) — its role assignments live in the
        // MappedRoleIds attribute and are remapped in the capture/restore steps instead.
        var deleted = 0;
        deleted += await CleanRoleEdgesForOriginTypeAsync<RtUser>(
            tenantRepository, session, tenantId);

        if (deleted > 0)
        {
            logger.LogInformation(
                "Pre-blueprint cleanup: deleted {Count} orphan AssignedRole associations for tenant '{TenantId}'",
                deleted, tenantId);
        }

        return deleted;
    }

    private static async Task<int> CleanRoleEdgesForOriginTypeAsync<TOrigin>(
        ITenantRepository tenantRepository,
        IOctoSession session,
        string tenantId)
        where TOrigin : RtEntity, new()
    {
        var origins = await tenantRepository
            .GetRtEntitiesByTypeAsync<TOrigin>(session, RtEntityQueryOptions.Create());

        var deleted = 0;
        foreach (var origin in origins.Items)
        {
            var queryOptions = RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId);
            var edges = await tenantRepository.GetRtAssociationsAsync(
                session, origin.ToRtEntityId(), queryOptions);

            foreach (var edge in edges.Items)
            {
                if (IsBlueprintRtId(edge.TargetRtId))
                {
                    continue;
                }

                var update = AssociationUpdateInfo.CreateDelete(
                    new RtEntityId(edge.OriginCkTypeId, edge.OriginRtId),
                    new RtEntityId(edge.TargetCkTypeId, edge.TargetRtId),
                    edge.AssociationRoleId!);
                var opResult = new OperationResult();
                await tenantRepository.ApplyChangesAsync(session, new[] { update }, opResult);
                deleted++;
            }
        }

        return deleted;
    }

    /// <summary>
    ///     Captures the role NAMES every <see cref="RtUser"/> and
    ///     <see cref="RtExternalTenantUserMapping"/> currently holds via its outbound
    ///     <c>AssignedRole</c> edges, persists the map in
    ///     <c>SystemConfiguration[PendingPostBlueprintRoleAssignmentsKey]</c>, and returns it for
    ///     logging. The post-blueprint restore in
    ///     <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> reads the same key and
    ///     re-attaches each user to the new stable-rtId role with the matching name.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The migration deletes the OLD Role entities after this captures, so reading role
    ///         names must happen BEFORE the entity sweep — otherwise the lookups all return null
    ///         and every user permanently loses every role they had.
    ///     </para>
    ///     <para>
    ///         The capture pre-skips edges that already point at stable-rtId roles
    ///         (<c>660…01..0E</c>) because those came from a half-applied blueprint state and
    ///         don't need restoration.
    ///     </para>
    /// </remarks>
    private async Task<PendingPostBlueprintRoleAssignments> CapturePendingRoleAssignmentsAsync(
        ITenantRepository tenantRepository,
        IOctoSession session,
        ITenantContext tenantContext,
        IOctoAdminSession adminSession)
    {
        var pending = new PendingPostBlueprintRoleAssignments();

        await CaptureRoleNamesForOriginTypeAsync<RtUser>(
            tenantRepository, session, pending.UserRoles);
        await CaptureMappedRoleNamesForExternalMappingsAsync(
            tenantRepository, session, pending.ExternalMappingRoles);

        if (pending.UserRoles.Count > 0 || pending.ExternalMappingRoles.Count > 0)
        {
            await tenantContext.SetConfigurationAsync(
                adminSession,
                IdentityServiceConstants.PendingPostBlueprintRoleAssignmentsKey,
                pending);
        }

        return pending;
    }

    private static async Task CaptureRoleNamesForOriginTypeAsync<TOrigin>(
        ITenantRepository tenantRepository,
        IOctoSession session,
        Dictionary<string, List<string>> target)
        where TOrigin : RtEntity, new()
    {
        var origins = await tenantRepository
            .GetRtEntitiesByTypeAsync<TOrigin>(session, RtEntityQueryOptions.Create());

        foreach (var origin in origins.Items)
        {
            var queryOptions = RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId);
            var edges = await tenantRepository.GetRtAssociationsAsync(
                session, origin.ToRtEntityId(), queryOptions);

            var names = new List<string>();
            foreach (var edge in edges.Items)
            {
                // Pre-skip stable-rtId targets — those came from a partially-applied blueprint
                // and don't need restoration. Only OLD random-rtId edges go through the capture
                // → blueprint apply → restore loop.
                if (IsBlueprintRtId(edge.TargetRtId))
                {
                    continue;
                }

                var role = await tenantRepository.GetRtEntityByRtIdAsync<RtRole>(
                    session, edge.TargetRtId);
                if (role?.Name is { Length: > 0 } name)
                {
                    names.Add(name);
                }
            }

            if (names.Count > 0)
            {
                target[origin.RtId.ToString()] = names;
            }
        }
    }

    /// <summary>
    ///     ExternalTenantUserMapping stores role assignments differently from User: its
    ///     <c>MappedRoleIds</c> attribute holds the list of role rtIds directly (per the
    ///     System.Identity-2.7.0 CK schema), not as outbound AssignedRole edges. Walk every
    ///     mapping, read the OLD role rtIds from that attribute, resolve each to a role name,
    ///     and stash the result in <paramref name="target"/>.
    /// </summary>
    private static async Task CaptureMappedRoleNamesForExternalMappingsAsync(
        ITenantRepository tenantRepository,
        IOctoSession session,
        Dictionary<string, List<string>> target)
    {
        var mappings = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, RtEntityQueryOptions.Create());

        foreach (var mapping in mappings.Items)
        {
            if (mapping.MappedRoleIds is not { Count: > 0 })
            {
                continue;
            }

            var names = new List<string>();
            foreach (var roleIdStr in mapping.MappedRoleIds)
            {
                if (!OctoObjectId.TryParse(roleIdStr, out var roleRtId))
                {
                    continue;
                }

                // Pre-skip stable-rtId entries — those came from a partially-migrated tenant
                // and don't need restoration. We only re-attach the OLD random-ObjectId ones.
                if (IsBlueprintRtId(roleRtId))
                {
                    continue;
                }

                var role = await tenantRepository.GetRtEntityByRtIdAsync<RtRole>(session, roleRtId);
                if (role?.Name is { Length: > 0 } name)
                {
                    names.Add(name);
                }
            }

            if (names.Count > 0)
            {
                target[mapping.RtId.ToString()] = names;
            }
        }
    }
}
