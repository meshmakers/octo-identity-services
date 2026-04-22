using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(13, 14, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Remove duplicate notification templates caused by querying wrong entity type")]
// ReSharper disable once UnusedType.Global
internal class NotificationTemplateDuplicateCleanupMigration(
    ILogger<NotificationTemplateDuplicateCleanupMigration> logger) : IMigration
{
    private static readonly string[] TemplateNames =
    [
        IdentityServiceConstants.WelcomeEmailTemplateName,
        IdentityServiceConstants.WelcomeEmailWithNoPasswordTemplateName,
        IdentityServiceConstants.ResetPasswordEmailTemplateName
    ];

    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
            using var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            foreach (var templateName in TemplateNames)
            {
                var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And)
                    .FieldEquals(nameof(RtNotificationTemplate.RtWellKnownName), templateName);

                await tenantRepository.DeleteManyRtEntitiesAsync<RtNotificationTemplate>(
                    session, fieldFilterCriteria, DeleteOptions.Erase);

                logger.LogInformation(
                    "Deleted notification template(s) '{TemplateName}' for tenant {TenantId}",
                    templateName, tenantContext.TenantId);
            }

            await session.CommitTransactionAsync();

            logger.LogInformation(
                "Notification template cleanup completed for tenant {TenantId}. Templates will be recreated on next startup",
                tenantContext.TenantId);

            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to clean up duplicate notification templates for tenant {TenantId}",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to clean up duplicate notification templates: {e.Message}");
        }
    }
}
