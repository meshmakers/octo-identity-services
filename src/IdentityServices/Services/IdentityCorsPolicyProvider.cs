using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     CORS policy provider for the Identity Service.
///     Collects allowed origins from clients across all tenants (system + children),
///     deduplicates them, and caches the resulting policy.
/// </summary>
public class IdentityCorsPolicyProvider : ICorsPolicyProvider
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<IdentityCorsPolicyProvider> _logger;
    private volatile HashSet<string>? _cachedOrigins;
    private CorsPolicy? _cachedPolicy;

    public IdentityCorsPolicyProvider(IServiceProvider serviceProvider, ILogger<IdentityCorsPolicyProvider> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
    {
        if (_cachedPolicy != null)
        {
            return _cachedPolicy;
        }

        var origins = await LoadAllOriginsAsync();

        _logger.LogInformation("Creating CORS policy for Identity API from client origins across all tenants: {Origins}",
            string.Join(", ", origins));

        var policyBuilder = new CorsPolicyBuilder();
        if (origins.Count > 0)
        {
            policyBuilder.WithOrigins(origins.ToArray());
        }

        policyBuilder.AllowAnyHeader()
            .AllowAnyMethod();
        _cachedPolicy = policyBuilder.Build();

        return _cachedPolicy;
    }

    /// <summary>
    ///     Checks whether the given origin is allowed across all tenants.
    /// </summary>
    public async Task<bool> IsOriginAllowedAsync(string origin)
    {
        var origins = _cachedOrigins ?? await LoadAllOriginsAsync();
        return origins.Contains(origin);
    }

    /// <summary>
    ///     Invalidates the cached CORS policy so it will be rebuilt on next request.
    /// </summary>
    public void InvalidateCache()
    {
        _logger.LogInformation("Invalidating Identity CORS policy cache");
        _cachedOrigins = null;
        _cachedPolicy = null;
    }

    private async Task<HashSet<string>> LoadAllOriginsAsync()
    {
        using var scope = _serviceProvider.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();

        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!await systemContext.IsSystemTenantExistingAsync())
        {
            _cachedOrigins = origins;
            return origins;
        }

        // Collect from system tenant
        await CollectOriginsFromTenantAsync(systemContext, systemContext.TenantId, origins);

        // Collect from all child tenants (all tenants are direct children of the system tenant)
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();
        var tenants = await systemContext.GetChildTenantsAsync(session);
        await session.CommitTransactionAsync();

        foreach (var tenant in tenants.Items)
        {
            await CollectOriginsFromTenantAsync(systemContext, tenant.TenantId, origins);
        }

        _cachedOrigins = origins;
        return origins;
    }

    private async Task CollectOriginsFromTenantAsync(ISystemContext systemContext, string tenantId, HashSet<string> origins)
    {
        try
        {
            var tenantRepo = await systemContext.TryFindTenantRepositoryAsync(tenantId);
            if (tenantRepo == null)
            {
                return;
            }

            var session = await tenantRepo.GetSessionAsync();
            session.StartTransaction();

            var queryOptions = RtEntityQueryOptions.Create();
            var result = await tenantRepo.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);

            foreach (var client in result.Items)
            {
                foreach (var origin in client.AllowedCorsOrigins)
                {
                    origins.Add(origin);
                }
            }

            await session.CommitTransactionAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to collect CORS origins from tenant '{TenantId}'", tenantId);
        }
    }
}
