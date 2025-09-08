using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(0, 1, IdentityServiceConstants.IdentityMigrationVersionKey)]
internal class InitialMigration(ILogger<InitialMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            await tenantContext.CreateRtAssociationIndexesAsync();
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to create RT association indexes.");
            return MigrationResult.Failure($"Failed to create RT association indexes: {e.Message}");
        }
    }
}