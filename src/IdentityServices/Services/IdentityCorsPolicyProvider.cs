using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     CORS policy provider for the Identity Service.
///     Collects allowed origins from clients across all tenants (system + children),
///     deduplicates them, and caches the resulting policy.
/// </summary>
/// <remarks>
///     <para>
///         AB#5487: the cache heals on its own. (1) A policy built from an <b>empty</b> origin list is never cached,
///         so a tenant whose app client is mirrored in after the first request is picked up on the next request
///         instead of staying blind to the SPA until a client is written. (2) A cached policy expires after
///         <see cref="OctoIdentityServicesOptions.CorsPolicyCacheSeconds" /> (default 60 s), which also covers
///         other pods that missed a <c>CorsClientsUpdate</c> event and origins that were removed. The events
///         (<see cref="InvalidateCache" />) stay the fast path.
///     </para>
/// </remarks>
public class IdentityCorsPolicyProvider : ICorsPolicyProvider
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<IdentityCorsPolicyProvider> _logger;
    private readonly TimeSpan? _cacheLifetime;
    private readonly TimeProvider _timeProvider;
    private volatile CacheEntry? _entry;
    private long _generation;

    public IdentityCorsPolicyProvider(
        IServiceProvider serviceProvider,
        ILogger<IdentityCorsPolicyProvider> logger,
        IOptions<OctoIdentityServicesOptions> options,
        TimeProvider? timeProvider = null)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;

        var seconds = options.Value.CorsPolicyCacheSeconds;
        // <= 0 disables the time-based expiry (event-driven invalidation only).
        _cacheLifetime = seconds > 0 ? TimeSpan.FromSeconds(seconds) : null;
    }

    public async Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
    {
        var entry = await GetEntryAsync();
        return entry.Policy;
    }

    /// <summary>
    ///     Checks whether the given origin is allowed across all tenants.
    /// </summary>
    public async Task<bool> IsOriginAllowedAsync(string origin)
    {
        var entry = await GetEntryAsync();
        return entry.Origins.Contains(origin);
    }

    /// <summary>
    ///     Invalidates the cached CORS policy so it will be rebuilt on next request.
    /// </summary>
    public void InvalidateCache()
    {
        _logger.LogInformation("Invalidating Identity CORS policy cache");
        // Bump the generation first: a load that started before this call must not publish its
        // (possibly stale) result into the cache afterwards.
        Interlocked.Increment(ref _generation);
        _entry = null;
    }

    private async Task<CacheEntry> GetEntryAsync()
    {
        var cached = _entry;
        if (cached != null && !cached.IsExpired(_timeProvider.GetUtcNow()))
        {
            return cached;
        }

        var generation = Interlocked.Read(ref _generation);
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

        var entry = new CacheEntry(origins, policyBuilder.Build(),
            _cacheLifetime.HasValue ? _timeProvider.GetUtcNow() + _cacheLifetime.Value : null);

        if (origins.Count == 0)
        {
            // AB#5487: an empty origin list is never a steady state (the system tenant owns clients with
            // origins); caching it would blind a freshly provisioned tenant to every SPA until a client write.
            _logger.LogWarning("Identity CORS policy has no allowed origins; not caching it, the next request rebuilds it");
        }
        else if (Interlocked.Read(ref _generation) == generation)
        {
            _entry = entry;
        }

        return entry;
    }

    private async Task<HashSet<string>> LoadAllOriginsAsync()
    {
        using var scope = _serviceProvider.CreateScope();
        var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();

        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!await systemContext.IsSystemTenantExistingAsync())
        {
            return origins;
        }

        // Collect from system tenant
        await CollectOriginsFromTenantAsync(systemContext, systemContext.TenantId, origins);

        // Collect from every registered tenant (the registry spans all logical parents)
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();
        var tenants = await systemContext.GetAllTenantsAsync(session);
        await session.CommitTransactionAsync();

        foreach (var tenant in tenants.Items)
        {
            await CollectOriginsFromTenantAsync(systemContext, tenant.TenantId, origins);
        }

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
                foreach (var entry in client.AllowedCorsOrigins)
                {
                    origins.Add(entry.Uri);
                }
            }

            await session.CommitTransactionAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to collect CORS origins from tenant '{TenantId}'", tenantId);
        }
    }

    private sealed record CacheEntry(HashSet<string> Origins, CorsPolicy Policy, DateTimeOffset? ExpiresAt)
    {
        public bool IsExpired(DateTimeOffset now) => ExpiresAt.HasValue && now >= ExpiresAt.Value;
    }
}
