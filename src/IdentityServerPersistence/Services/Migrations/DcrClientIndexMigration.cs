using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 20→21: refreshes indexes for the new <c>DynamicRegistration</c> /
/// <c>DynamicRegistrationExpiresAt</c> attributes on <c>Client</c> (AB#4338, RFC 7591 Dynamic Client
/// Registration). Existing client documents need no data migration — both attributes are additive;
/// <c>DynamicRegistration</c> defaults to <c>false</c> (correct for every pre-existing client) and
/// <c>DynamicRegistrationExpiresAt</c> is optional/unset.
/// </summary>
[Migration(20, 21, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Refresh indexes for Client.DynamicRegistration / DynamicRegistrationExpiresAt attributes")]
// ReSharper disable once UnusedType.Global
internal class DcrClientIndexMigration(
    ILogger<DcrClientIndexMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} (Client.DynamicRegistration)",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to run DynamicRegistration index migration for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to run index migration: {e.Message}");
        }
    }
}
