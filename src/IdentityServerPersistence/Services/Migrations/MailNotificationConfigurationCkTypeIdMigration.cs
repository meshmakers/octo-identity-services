using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
///     Migration 18 → 19: rewrites <c>ckTypeId</c> on existing
///     <c>RtMailNotificationConfiguration</c> documents from
///     <c>System.Identity/MailNotificationConfiguration</c> to
///     <c>System.Notification/MailNotificationConfiguration</c>.
/// </summary>
/// <remarks>
///     <para>
///         Phase 3 follow-up #2 moved the <c>MailNotificationConfiguration</c> CK type from
///         <c>System.Identity-2.7.0</c> to <c>System.Notification-2.1.0</c> so the new
///         <c>System.Notification.Bootstrap-1.0.0</c> blueprint can own its seed. The MongoDB
///         documents live in the shared <c>RtEntity_SystemConfiguration</c> collection
///         (because <c>MailNotificationConfiguration</c> derives from <c>System/Configuration</c>,
///         which is the defining collection root), so no collection rename is needed — only the
///         <c>ckTypeId</c> discriminator field has to flip.
///     </para>
///     <para>
///         The OLD type no longer exists in the CK cache after PR-B drops it from
///         <c>System.Identity-2.8.0</c>, so we use the engine's migration-time APIs:
///         <see cref="IRuntimeRepository.GetRtEntitiesByTypeForMigrationAsync"/> finds existing
///         instances by <c>ckTypeId</c> field value across all <c>RtEntity_*</c> collections
///         without consulting the cache, and
///         <see cref="IRuntimeRepository.UpdateCkTypeIdForMigrationAsync"/> rewrites the field
///         in-place.
///     </para>
///     <para>
///         Operator-set attribute values (<c>EnableEmailNotifications</c>,
///         <c>RedirectAfterEmailInteractionUrl</c>) survive untouched — only the type
///         discriminator changes. After this migration runs, the
///         <c>System.Notification.Bootstrap-1.0.0</c> blueprint re-applies and recognises the
///         existing entity by its stable <c>rtWellKnownName</c>; the blueprint's stable rtId
///         (<c>680…01</c>) is upserted onto whichever rtId the old imperative seed assigned.
///         A fresh tenant (no existing doc) takes the blueprint seed unchanged.
///     </para>
///     <para>
///         Idempotent: on second run the query returns zero rows and the loop is a no-op.
///     </para>
/// </remarks>
[Migration(18, 19, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Phase 3 follow-up #2: rewrite MailNotificationConfiguration ckTypeId from System.Identity to System.Notification")]
// ReSharper disable once UnusedType.Global
internal class MailNotificationConfigurationCkTypeIdMigration(
    ILogger<MailNotificationConfigurationCkTypeIdMigration> logger) : IMigration
{
    private static readonly RtCkId<CkTypeId> OldCkTypeId =
        new("System.Identity/MailNotificationConfiguration");

    private static readonly RtCkId<CkTypeId> NewCkTypeId =
        new("System.Notification/MailNotificationConfiguration");

    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
            using var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var (entities, _) = await tenantRepository
                .GetRtEntitiesByTypeForMigrationAsync(session, OldCkTypeId);

            if (entities.Count == 0)
            {
                logger.LogInformation(
                    "Tenant '{TenantId}': no MailNotificationConfiguration documents with old ckTypeId — nothing to rewrite",
                    tenantContext.TenantId);
                await session.CommitTransactionAsync();
                return MigrationResult.Success();
            }

            foreach (var entity in entities)
            {
                await tenantRepository.UpdateCkTypeIdForMigrationAsync(session, entity.RtId, NewCkTypeId);
            }

            logger.LogInformation(
                "Tenant '{TenantId}': rewrote ckTypeId on {Count} MailNotificationConfiguration document(s) from '{Old}' to '{New}'",
                tenantContext.TenantId, entities.Count,
                OldCkTypeId.SemanticVersionedFullName, NewCkTypeId.SemanticVersionedFullName);

            await session.CommitTransactionAsync();
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to rewrite MailNotificationConfiguration ckTypeId for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure(
                $"Failed to rewrite MailNotificationConfiguration ckTypeId: {e.Message}");
        }
    }
}
