using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Caching.Memory;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Cached view of the tenant registry for the identity hot paths (AB#6308, AB#6393). It hands out the
///     registry entries the lightweight repository access needs, so callers that only know a tenant id
///     do not fall back to <see cref="ISystemContext.FindTenantRepositoryAsync" />.
/// </summary>
public interface ITenantRegistry
{
    /// <summary>All registered child tenants (the system tenant is not part of the registry list).</summary>
    Task<IReadOnlyList<OctoTenant>> GetRegisteredTenantsAsync();

    /// <summary>
    ///     Opens the repository of a registered tenant — or of the system tenant itself — without any I/O
    ///     (<see cref="ISystemContext.GetRegisteredTenantRepository" />). Returns <c>null</c> for a tenant id that
    ///     is not in the registry (fail closed). A failing registry read throws; callers treat that as a failed
    ///     lookup too.
    /// </summary>
    Task<ITenantRepository?> TryGetRepositoryAsync(string tenantId);
}

/// <inheritdoc />
/// <remarks>
///     The registry list is shared process-wide through <see cref="IMemoryCache" /> for <see cref="CacheTtl" />.
///     A tenant id that is not in the cached snapshot triggers one re-read, at most once per
///     <see cref="MissRefreshInterval" />: a tenant created a moment ago is found without waiting for the TTL,
///     while a flood of unknown tenant ids cannot turn into a flood of registry reads.
/// </remarks>
public sealed class TenantRegistry(
    ISystemContext systemContext,
    IMemoryCache cache,
    TimeProvider? timeProvider = null) : ITenantRegistry
{
    /// <summary>How long the registry list is reused (AB#6307).</summary>
    public static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(45);

    /// <summary>Minimum age of the cached snapshot before a lookup miss re-reads the registry.</summary>
    public static readonly TimeSpan MissRefreshInterval = TimeSpan.FromSeconds(5);

    private const string CacheKey = "TenantRegistry:snapshot";

    // One gate per cache instance (= process-wide in production): the registry is scoped, so without it
    // concurrent requests that all see an empty or stale snapshot would each read the registry.
    private static readonly ConditionalWeakTable<IMemoryCache, SemaphoreSlim> Gates = new();

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<OctoTenant>> GetRegisteredTenantsAsync()
        => (await GetSnapshotAsync(forceIfOlderThan: null)).Tenants;

    public async Task<ITenantRepository?> TryGetRepositoryAsync(string tenantId)
    {
        if (string.IsNullOrEmpty(tenantId))
        {
            return null;
        }

        var tenant = await FindAsync(tenantId);
        return tenant == null ? null : systemContext.GetRegisteredTenantRepository(tenant);
    }

    private async Task<OctoTenant?> FindAsync(string tenantId)
    {
        // The system tenant is not a registry entry; its database name is known to the system context.
        if (string.Equals(tenantId, systemContext.TenantId, StringComparison.OrdinalIgnoreCase))
        {
            return new OctoTenant(systemContext.TenantId, systemContext.DatabaseName);
        }

        var snapshot = await GetSnapshotAsync(forceIfOlderThan: null);
        if (snapshot.ById.TryGetValue(tenantId, out var tenant))
        {
            return tenant;
        }

        snapshot = await GetSnapshotAsync(forceIfOlderThan: MissRefreshInterval);
        return snapshot.ById.GetValueOrDefault(tenantId);
    }

    private async Task<Snapshot> GetSnapshotAsync(TimeSpan? forceIfOlderThan)
    {
        if (TryGetUsable(forceIfOlderThan) is { } usable)
        {
            return usable;
        }

        // Single flight: the first caller reads the registry, the others wait and then find its snapshot.
        var gate = Gates.GetValue(cache, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync();
        try
        {
            if (TryGetUsable(forceIfOlderThan) is { } refreshed)
            {
                return refreshed;
            }

            using var adminSession = await systemContext.GetAdminSessionAsync();
            var allTenants = await systemContext.GetAllTenantsAsync(adminSession);
            var snapshot = new Snapshot(allTenants.Items.ToList(), _time.GetUtcNow());
            cache.Set(CacheKey, snapshot, CacheTtl);
            return snapshot;
        }
        finally
        {
            gate.Release();
        }
    }

    private Snapshot? TryGetUsable(TimeSpan? forceIfOlderThan)
        => cache.TryGetValue(CacheKey, out Snapshot? cached) && cached != null &&
           (forceIfOlderThan == null || _time.GetUtcNow() - cached.FetchedAt < forceIfOlderThan)
            ? cached
            : null;

    private sealed class Snapshot
    {
        public Snapshot(IReadOnlyList<OctoTenant> tenants, DateTimeOffset fetchedAt)
        {
            Tenants = tenants;
            FetchedAt = fetchedAt;
            ById = new Dictionary<string, OctoTenant>(StringComparer.OrdinalIgnoreCase);
            foreach (var tenant in tenants)
            {
                ById.TryAdd(tenant.TenantId, tenant);
            }
        }

        public IReadOnlyList<OctoTenant> Tenants { get; }
        public DateTimeOffset FetchedAt { get; }
        public Dictionary<string, OctoTenant> ById { get; }
    }
}
