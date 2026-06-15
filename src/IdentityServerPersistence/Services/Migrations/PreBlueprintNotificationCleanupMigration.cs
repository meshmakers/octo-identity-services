using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
///     Migration 19 → 20: deletes pre-blueprint <c>RtMailNotificationConfiguration</c> and
///     <c>RtNotificationTemplate</c> entities so the
///     <c>System.Notification.Bootstrap-1.0.0</c> blueprint's stable-rtId seed
///     (<c>680…01</c> for the config + <c>680…10..12</c> for the three templates) is the
///     single source of truth.
/// </summary>
/// <remarks>
///     <para>
///         Before PR #91 (Phase 3 follow-up #2), the imperative seed in
///         <c>DefaultConfigurationCreatorService.CreateTenantConfiguration</c> created the
///         <see cref="RtMailNotificationConfiguration"/> + 3 <see cref="RtNotificationTemplate"/>
///         entities with random rtIds. Phase 3 follow-up #2 introduced stable rtIds in the
///         <c>680…</c> range for the new blueprint seed.
///     </para>
///     <para>
///         If both seeds ran against the same tenant (a freshly-deployed PR #91 against a tenant
///         that was provisioned by the imperative seed) the result is duplicate entities with the
///         same <c>rtWellKnownName</c> but different rtIds. The notification lookup paths
///         (<c>IdentityConfigurationService.GetMailNotificationConfigurationAsync</c> +
///         <c>NotificationService</c> template resolution) pick the first match arbitrarily, so a
///         configuration flip via the new blueprint can silently land on the orphan copy and have
///         no effect on the running service.
///     </para>
///     <para>
///         This migration runs once per tenant via the standard <see cref="MigrationService"/>
///         framework (tracked under <c>IdentityServiceMigrations</c> in
///         <see cref="IdentityServiceConstants.IdentityMigrationVersionKey"/>) and deletes every
///         <c>RtMailNotificationConfiguration</c> / <c>RtNotificationTemplate</c> whose rtId is
///         <strong>not</strong> in the blueprint's stable range. Anything in
///         <c>680…00..680…FF</c> was authored by the blueprint and survives; anything else is
///         pre-blueprint residue and goes.
///     </para>
///     <para>
///         Ordering inside <c>SetupTenantAsync</c>: this migration runs <em>before</em>
///         <c>ApplyServiceManagedBlueprintsAsync</c>, so the sequence on a pre-blueprint tenant
///         is: clean OLD → blueprint apply → DB has only stable-rtId entities. Mirrors the
///         <c>PreBlueprintCleanupMigration</c> contract used for the Identity entities.
///     </para>
/// </remarks>
[Migration(19, 20, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Phase 3 follow-up #2 cleanup: delete pre-blueprint MailNotificationConfiguration + NotificationTemplate entities")]
// ReSharper disable once UnusedType.Global
internal class PreBlueprintNotificationCleanupMigration(
    ILogger<PreBlueprintNotificationCleanupMigration> logger) : IMigration
{
    /// <summary>
    ///     Inclusive lower bound of the stable rtId range used by
    ///     <c>System.Notification.Bootstrap-1.0.0</c> seed entities. The first byte of every
    ///     blueprint rtId is <c>0x68</c>; everything strictly less than this value is pre-blueprint.
    /// </summary>
    private static readonly OctoObjectId BlueprintRangeStart =
        new("680000000000000000000000");

    /// <summary>
    ///     Exclusive upper bound. ObjectId comparison is byte-by-byte, so anything &gt;= this is
    ///     outside the blueprint range.
    /// </summary>
    private static readonly OctoObjectId BlueprintRangeEndExclusive =
        new("690000000000000000000000");

    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
            using var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var deletedConfigs = await DeletePreBlueprintEntitiesAsync<RtMailNotificationConfiguration>(
                tenantRepository, session, tenantContext.TenantId);

            var deletedTemplates = await DeletePreBlueprintEntitiesAsync<RtNotificationTemplate>(
                tenantRepository, session, tenantContext.TenantId);

            await session.CommitTransactionAsync();

            logger.LogInformation(
                "Tenant '{TenantId}': deleted {Configs} pre-blueprint MailNotificationConfiguration + {Templates} NotificationTemplate row(s); blueprint stable-rtId seed is now single source of truth",
                tenantContext.TenantId, deletedConfigs, deletedTemplates);

            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to clean up pre-blueprint Notification entities for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure(
                $"Failed to clean up pre-blueprint Notification entities: {e.Message}");
        }
    }

    private async Task<int> DeletePreBlueprintEntitiesAsync<TEntity>(
        ITenantRepository tenantRepository,
        IOctoSession session,
        string tenantId)
        where TEntity : RtEntity, new()
    {
        var all = await tenantRepository.GetRtEntitiesByTypeAsync<TEntity>(session,
            RtEntityQueryOptions.Create());

        var deleted = 0;
        foreach (var entity in all.Items)
        {
            if (entity.RtId.CompareTo(BlueprintRangeStart) >= 0
                && entity.RtId.CompareTo(BlueprintRangeEndExclusive) < 0)
            {
                continue;
            }

            await tenantRepository.DeleteOneRtEntityByRtIdAsync<TEntity>(
                session, entity.RtId, DeleteOptions.Erase);
            logger.LogInformation(
                "Tenant '{TenantId}': deleted pre-blueprint {Type} rtId={RtId} name={Name}",
                tenantId, typeof(TEntity).Name, entity.RtId, entity.RtWellKnownName);
            deleted++;
        }

        return deleted;
    }
}
