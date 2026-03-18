using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Initialization;
using Microsoft.Extensions.Logging;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

// ReSharper disable once ClassNeverInstantiated.Global
internal class DynamicAuthSchemeServiceInitializer(
    ISystemContext systemContext,
    IDynamicAuthSchemeService dynamicAuthSchemeService,
    ILogger<DynamicAuthSchemeServiceInitializer> logger)
    : IAsyncInitializationService
{
    public int Order => 50;

    public async Task InitializeAsync()
    {
        // Register system tenant schemes
        logger.LogInformation("Registering auth schemes for system tenant '{TenantId}'", systemContext.TenantId);
        await dynamicAuthSchemeService.ConfigureAsync(systemContext.TenantId);

        // Register all child tenant schemes
        if (await systemContext.IsSystemTenantExistingAsync())
        {
            List<OctoTenant> tenantList;
            using (var session = await systemContext.GetAdminSessionAsync())
            {
                session.StartTransaction();
                var tenants = await systemContext.GetChildTenantsAsync(session);
                tenantList = tenants.Items.ToList();
                await session.CommitTransactionAsync();
            }

            foreach (var tenant in tenantList)
            {
                logger.LogInformation("Registering auth schemes for tenant '{TenantId}'", tenant.TenantId);
                await dynamicAuthSchemeService.ConfigureAsync(tenant.TenantId);
            }
        }
    }
}
