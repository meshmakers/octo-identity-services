using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 15→16: refreshes indexes for the new <c>ProvisionedByParentTenantId</c>
/// attribute on <c>Client</c>. Existing client documents do not need a data migration —
/// the attribute is optional and unset on every pre-existing client, which is the
/// desired state ("not a mirror").
/// </summary>
[Migration(15, 16, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Refresh indexes for Client.ProvisionedByParentTenantId attribute")]
// ReSharper disable once UnusedType.Global
internal class ClientProvisionedByParentMigration(
    ILogger<ClientProvisionedByParentMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} (Client.ProvisionedByParentTenantId)",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to run ProvisionedByParentTenantId index migration for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to run index migration: {e.Message}");
        }
    }
}
