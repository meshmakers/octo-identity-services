using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(7, 8, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Prepend ckTypeId to ascending indexes for improved query selectivity")]
// ReSharper disable once UnusedType.Global
internal class CkTypeIdIndexMigration(ILogger<CkTypeIdIndexMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} to prepend ckTypeId to ascending indexes",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to update indexes for tenant {TenantId}", tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to update indexes: {e.Message}");
        }
    }
}
