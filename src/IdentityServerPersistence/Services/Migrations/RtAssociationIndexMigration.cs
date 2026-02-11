using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(4, 5, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Add RtAssociation index with targetRtId as leading field for $lookup optimization")]
// ReSharper disable once UnusedType.Global
// ReSharper disable once ClassNeverInstantiated.Global
internal class RtAssociationIndexMigration(ILogger<RtAssociationIndexMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation("Updating RtAssociation indexes for tenant {TenantId} to add targetRtId leading index",
                tenantContext.TenantId);
            await tenantContext.CreateRtAssociationIndexesAsync();
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to update RtAssociation indexes for tenant {TenantId}", tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to update RtAssociation indexes: {e.Message}");
        }
    }
}
