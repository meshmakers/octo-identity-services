using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 16→17: Adds indexes for the new <c>ServerSideSession</c> and
/// <c>DataProtectionKey</c> CK types (server-side session storage + MongoDB-backed
/// Data Protection key ring). No data migration is required — both types are new.
/// </summary>
[Migration(16, 17, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Add indexes for ServerSideSession and DataProtectionKey collections")]
// ReSharper disable once UnusedType.Global
internal class ServerSideSessionMigration(
    ILogger<ServerSideSessionMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} (ServerSideSession/DataProtectionKey collections)",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to run ServerSideSession index migration for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to run ServerSideSession index migration: {e.Message}");
        }
    }
}
