using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(0, 7, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Consolidated index setup: RT association indexes, CK type indexes, rtState indexes")]
// ReSharper disable once UnusedType.Global
internal class IndexSetupMigration(ILogger<IndexSetupMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation("Setting up all indexes for tenant {TenantId}", tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to set up indexes for tenant {TenantId}", tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to set up indexes: {e.Message}");
        }
    }
}
