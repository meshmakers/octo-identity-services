using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(5, 6, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Add rtState index for RtEntity and RtAssociation collections")]
// ReSharper disable once UnusedType.Global
// ReSharper disable once ClassNeverInstantiated.Global
internal class RtStateIndexMigration(ILogger<RtStateIndexMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation("Updating indexes for tenant {TenantId} to add rtState index",
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
