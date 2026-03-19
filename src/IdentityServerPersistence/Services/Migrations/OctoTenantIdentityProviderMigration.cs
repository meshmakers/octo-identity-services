using Meshmakers.Octo.ConstructionKit.Models.System.Generated.System.v2;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(8, 9, IdentityServiceConstants.IdentityMigrationVersionKey,
    "No-op: OctoTenantIdentityProvider is now created explicitly via admin provisioning only")]
// ReSharper disable once UnusedType.Global
internal class OctoTenantIdentityProviderMigration(
    ILogger<OctoTenantIdentityProviderMigration> logger) : IMigration
{
    public Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        // OctoTenantIdentityProvider is no longer auto-created. Cross-tenant access must be
        // explicitly provisioned via the AdminProvisioningController on the parent tenant.
        logger.LogDebug(
            "Skipping OctoTenantIdentityProvider auto-creation for tenant '{TenantId}' — use admin provisioning instead",
            tenantContext.TenantId);
        return Task.FromResult(MigrationResult.Success());
    }
}
