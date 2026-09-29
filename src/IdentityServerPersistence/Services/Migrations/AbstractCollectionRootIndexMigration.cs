using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(22, 23, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Create the indexes of collections whose collection root is abstract")]
// ReSharper disable once UnusedType.Global
internal class AbstractCollectionRootIndexMigration(ILogger<AbstractCollectionRootIndexMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} to create the indexes of abstract collection roots",
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
