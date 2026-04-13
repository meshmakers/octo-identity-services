using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(12, 13, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Recreate indexes with correctly resolved nested Record attribute paths")]
// ReSharper disable once UnusedType.Global
internal class IndexFieldPathMigration(ILogger<IndexFieldPathMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Recreating indexes for tenant {TenantId} to fix nested Record attribute field paths",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to recreate indexes for tenant {TenantId}", tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to recreate indexes: {e.Message}");
        }
    }
}
