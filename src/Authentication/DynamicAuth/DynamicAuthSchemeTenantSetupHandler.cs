using IdentityServerPersistence.Services;
using Microsoft.Extensions.Logging;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Registers a tenant's external identity provider auth schemes once its setup completed after
///     cold start (AB#5540). <see cref="DynamicAuthSchemeServiceInitializer" /> skips tenants whose
///     CK model is not usable at startup (their setup failed and was queued for the background
///     retry); this handler catches them up when the retry — or any later tenant event — completes
///     the setup. <see cref="IDynamicAuthSchemeService.ConfigureAsync" /> is idempotent, so running
///     it for tenants that are already registered only refreshes their schemes.
/// </summary>
// ReSharper disable once ClassNeverInstantiated.Global
internal class DynamicAuthSchemeTenantSetupHandler(
    IDynamicAuthSchemeService dynamicAuthSchemeService,
    ILogger<DynamicAuthSchemeTenantSetupHandler> logger)
    : ITenantSetupCompletedHandler
{
    public async Task OnTenantSetupCompletedAsync(string tenantId)
    {
        logger.LogInformation("Registering auth schemes for tenant '{TenantId}' after tenant setup", tenantId);
        await dynamicAuthSchemeService.ConfigureAsync(tenantId);
    }
}
