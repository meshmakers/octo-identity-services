using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 11→12: Sets AllowSelfRegistration=true on all existing identity providers
/// (since the new CK attribute defaults to true, but existing MongoDB documents lack the field)
/// and updates indexes for the new EmailDomainGroupRule type.
/// </summary>
[Migration(10, 12, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Add AllowSelfRegistration default to existing identity providers and update indexes")]
// ReSharper disable once UnusedType.Global
internal class LoginConfigurationMigration(
    ILogger<LoginConfigurationMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            var childRepo = tenantContext.GetTenantRepositoryAsAdmin();

            // Set AllowSelfRegistration=true on all existing identity providers
            await SetDefaultAllowSelfRegistrationAsync(adminSession, childRepo, tenantContext.TenantId);

            // Update indexes (will create the new EmailDomainGroupRule unique index)
            logger.LogInformation("Updating indexes for tenant {TenantId}", tenantContext.TenantId);
            await tenantContext.UpdateIndexesAsync(adminSession);

            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to run login configuration migration for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to run login configuration migration: {e.Message}");
        }
    }

    private async Task SetDefaultAllowSelfRegistrationAsync(
        IOctoAdminSession adminSession, ITenantRepository childRepo, string tenantId)
    {
        var queryOptions = RtEntityQueryOptions.Create();
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtIdentityProvider>(adminSession, queryOptions);

        var updatedCount = 0;
        foreach (var provider in result.Items)
        {
            // Set AllowSelfRegistration to true for existing providers that don't have it set
            // The generated property defaults to false (C# bool default), but we want true for backward compatibility
            if (!provider.AllowSelfRegistration)
            {
                provider.AllowSelfRegistration = true;
                await childRepo.ReplaceOneRtEntityByIdAsync(adminSession, provider.RtId, provider);
                updatedCount++;
            }
        }

        if (updatedCount > 0)
        {
            logger.LogInformation(
                "Set AllowSelfRegistration=true on {Count} existing identity providers in tenant '{TenantId}'",
                updatedCount, tenantId);
        }
    }
}
