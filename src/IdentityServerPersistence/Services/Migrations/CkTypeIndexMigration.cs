using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(1, 2, IdentityServiceConstants.IdentityMigrationVersionKey)]
// ReSharper disable once UnusedType.Global
internal class CkTypeIndexMigration(ILogger<CkTypeIndexMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to update indexes for tenant {TenantId}", tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to update indexes {e.Message}");
        }
    }
}