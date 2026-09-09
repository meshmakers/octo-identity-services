using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 21→22 (AB#4989/AB#4991): Adds indexes for the new <c>OAuthAuthorization</c> and
/// <c>OAuthToken</c> CK types backing the OpenIddict authorization/token stores. No data
/// migration is required — both types are new; existing <c>PersistedGrant</c> records stay in
/// place (readable for diagnostics) and are deliberately not converted (see
/// docs/CONCEPT-OPENIDDICT-MIGRATION.md §2).
/// </summary>
[Migration(21, 22, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Add indexes for the OpenIddict OAuthAuthorization and OAuthToken collections")]
// ReSharper disable once UnusedType.Global
internal class OAuthTokenStoreMigration(
    ILogger<OAuthTokenStoreMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            logger.LogInformation(
                "Updating indexes for tenant {TenantId} (OAuthAuthorization/OAuthToken collections)",
                tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);
            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to run OAuthToken store index migration for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to run OAuthToken store index migration: {e.Message}");
        }
    }
}
