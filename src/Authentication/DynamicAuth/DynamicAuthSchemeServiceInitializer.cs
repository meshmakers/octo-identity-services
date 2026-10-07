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
                var tenants = await systemContext.GetAllTenantsAsync(session);
                tenantList = tenants.Items.ToList();
                await session.CommitTransactionAsync();
            }

            // One tenant must not take the host down with it (AB#5540). This loop used to be unguarded:
            // on test-2 a single tenant whose System.Identity CK import had failed (a Mongo write
            // conflict on the index update lock; DefaultConfigurationInitializationService logged it and
            // queued the tenant for the background setup retry) threw CkCacheException here and failed
            // the whole host start (HostedServiceStartupFaulted) — for every tenant. A failing tenant is
            // now logged and skipped. Its schemes are registered once its setup completes: the
            // background retry and every later tenant event run SetupAsync with DeferTenantStart=false,
            // which invokes the ITenantSetupCompletedHandler hook (DynamicAuthSchemeTenantSetupHandler).
            // The system tenant above stays unguarded on purpose: without it nothing works at all.
            var failedTenants = new List<string>();
            foreach (var tenant in tenantList)
            {
                logger.LogInformation("Registering auth schemes for tenant '{TenantId}'", tenant.TenantId);
                try
                {
                    await dynamicAuthSchemeService.ConfigureAsync(tenant.TenantId);
                }
                catch (Exception ex)
                {
                    failedTenants.Add(tenant.TenantId);
                    // Type and message are enough to see why (typically a CkCacheException for a tenant
                    // whose CK model import has not completed yet); the setup failure itself was already
                    // logged with its stack trace by DefaultConfigurationInitializationService.
                    logger.LogError(
                        "Registering auth schemes for tenant '{TenantId}' failed with {ExceptionType}: " +
                        "{ExceptionMessage}. Continuing with the remaining tenants; the schemes are " +
                        "registered once the tenant's setup completes",
                        tenant.TenantId, ex.GetType().Name, ex.Message);
                }
            }

            if (failedTenants.Count > 0)
            {
                logger.LogWarning(
                    "Auth scheme registration failed for {Count} of {Total} tenant(s): {Tenants}",
                    failedTenants.Count, tenantList.Count, string.Join(", ", failedTenants));
            }
        }
    }
}
