using Meshmakers.Octo.ConstructionKit.Models.System.Generated.System.v2;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Migrations;

[Migration(8, 9, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Auto-create OctoTenantIdentityProvider for child tenants with ParentTenantId")]
// ReSharper disable once UnusedType.Global
internal class OctoTenantIdentityProviderMigration(
    ISystemContext systemContext,
    ILogger<OctoTenantIdentityProviderMigration> logger) : IMigration
{
    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            // Query the system tenant for the RtTenant record to find ParentTenantId
            var systemRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
            using var systemSession = await systemContext.GetAdminSessionAsync();
            systemSession.StartTransaction();

            var queryOptions = RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtTenant.TenantId), tenantContext.TenantId);
            var tenantResult = await systemRepo.GetRtEntitiesByTypeAsync<RtTenant>(systemSession, queryOptions);
            await systemSession.CommitTransactionAsync();

            var rtTenant = tenantResult.Items.FirstOrDefault();
            if (rtTenant == null || string.IsNullOrEmpty(rtTenant.ParentTenantId))
            {
                logger.LogDebug(
                    "Tenant '{TenantId}' has no ParentTenantId, skipping OctoTenantIdentityProvider creation",
                    tenantContext.TenantId);
                return MigrationResult.Success();
            }

            // Check if provider already exists in the child tenant
            var childRepo = tenantContext.GetTenantRepositoryAsAdmin();
            var providerResult =
                await childRepo.GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(
                    adminSession, RtEntityQueryOptions.Create());

            if (providerResult.Items.Any(p =>
                    string.Equals(p.ParentTenantId, rtTenant.ParentTenantId, StringComparison.OrdinalIgnoreCase)))
            {
                logger.LogDebug(
                    "OctoTenantIdentityProvider for parent '{ParentTenantId}' already exists in tenant '{TenantId}'",
                    rtTenant.ParentTenantId, tenantContext.TenantId);
                return MigrationResult.Success();
            }

            // Create the provider
            var provider = new RtOctoTenantIdentityProvider
            {
                Name = $"ParentTenant_{rtTenant.ParentTenantId}",
                IsEnabled = true,
                DisplayName = $"Login via {rtTenant.ParentTenantId}",
                ParentTenantId = rtTenant.ParentTenantId
            };

            await childRepo.InsertOneRtEntityAsync(adminSession, provider);

            logger.LogInformation(
                "Migration created OctoTenantIdentityProvider for tenant '{TenantId}' pointing to parent '{ParentTenantId}'",
                tenantContext.TenantId, rtTenant.ParentTenantId);

            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to create OctoTenantIdentityProvider for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to create OctoTenantIdentityProvider: {e.Message}");
        }
    }
}
