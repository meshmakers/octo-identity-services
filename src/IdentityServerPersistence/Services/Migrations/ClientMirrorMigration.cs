using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 14→15: Adds indexes for the new <c>ClientMirror</c> CK type that tracks
/// which child tenants a parent-tenant client has been auto-provisioned into.
/// Existing <c>Client</c> documents do not need data migration — the new
/// <c>AutoProvisionInChildTenants</c> attribute defaults to <c>false</c>, which is the
/// desired value for every client that pre-dates this feature.
/// </summary>
[Migration(14, 15, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Add indexes for ClientMirror collection (multi-tenant client credentials)")]
// ReSharper disable once UnusedType.Global
internal class ClientMirrorMigration(
    ILogger<ClientMirrorMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} (ClientMirror collection)",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to run ClientMirror index migration for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to run ClientMirror index migration: {e.Message}");
        }
    }
}
