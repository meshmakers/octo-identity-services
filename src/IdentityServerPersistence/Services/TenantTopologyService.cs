using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityServerPersistence.Services;

/// <summary>
///     One tenant of a topology answer (AB#7044): exactly the three facts the contract discloses — no child
///     ids, no parent ids, no tenant data.
/// </summary>
public sealed record TenantTopologyEntry(string TenantId, int Depth, bool HasChildren);

/// <summary>The topology answer for one scope and one caller.</summary>
public sealed record TenantTopologyResult(
    string Scope, bool ScopeHasChildren, IReadOnlyList<TenantTopologyEntry> Tenants);

/// <summary>The tenant hierarchy below a scope could not be read completely (fail closed, no partial list).</summary>
public sealed class TenantHierarchyUnreadableException : Exception
{
    public TenantHierarchyUnreadableException(string message) : base(message)
    {
    }

    public TenantHierarchyUnreadableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
///     Answers which of a caller's allowed tenants lie below a scope tenant (AB#7044).
/// </summary>
public interface ITenantTopologyService
{
    /// <summary>
    ///     (<paramref name="allowedTenants" />) ∩ (strict descendants of <paramref name="scopeTenantId" />), each
    ///     with depth and hasChildren. An unknown scope and a scope without entitled descendants both yield an
    ///     empty list with <c>ScopeHasChildren = false</c> (no existence oracle).
    /// </summary>
    /// <exception cref="TenantHierarchyUnreadableException">Fail closed — the caller answers 503.</exception>
    Task<TenantTopologyResult> GetTopologyAsync(string scopeTenantId, IReadOnlyCollection<string> allowedTenants);
}

/// <inheritdoc />
/// <remarks>
///     <para>
///         The per-scope snapshot (tenantId, depth, hasChildren of the whole subtree) is cached in
///         <see cref="IMemoryCache" /> for <see cref="CacheTtl" /> (= the <see cref="TenantRegistry" /> TTL) with
///         single flight; the per-request cost is the intersection with the claim. Only a <b>registered</b> scope
///         is cached — an unknown scope value never grows memory — and a failed read is never cached.
///     </para>
///     <para>
///         <c>allowed_tenants</c> is a selection hint, not an API authorization. Here it limits which topology
///         facts are revealed: the caller learns a boolean and a depth about tenants they can already log into.
///         <c>ScopeHasChildren</c> is only truthful when the scope is in the claim or the entitled list is
///         non-empty, otherwise <c>false</c> — an unrelated caller learns nothing about a foreign scope.
///     </para>
/// </remarks>
public sealed class TenantTopologyService(
    ISystemContext systemContext,
    IMemoryCache cache,
    IOptions<OctoIdentityServicesOptions> options,
    ILogger<TenantTopologyService> logger) : ITenantTopologyService
{
    /// <summary>How long a scope snapshot is reused — the same TTL as the tenant registry (45 s).</summary>
    public static readonly TimeSpan CacheTtl = TenantRegistry.CacheTtl;

    private const string CacheKeyPrefix = "TenantTopology:";

    // In-flight reads per cache key, one table per cache instance (= process-wide in production, the service is
    // scoped). Entries live only while a read runs, so the table is bounded by concurrent reads — never by the
    // number of distinct (possibly unknown) scope values — and a slow or hung scope blocks only its own key.
    private static readonly ConditionalWeakTable<IMemoryCache, ConcurrentDictionary<string, Lazy<Task<TenantSubtree?>>>>
        InFlight = new();

    public async Task<TenantTopologyResult> GetTopologyAsync(string scopeTenantId,
        IReadOnlyCollection<string> allowedTenants)
    {
        var scope = (scopeTenantId ?? string.Empty).Trim();
        var snapshot = await GetSnapshotAsync(scope);
        if (snapshot == null)
        {
            // Unknown scope: identical to "no entitled descendants".
            return new TenantTopologyResult(scope, false, []);
        }

        var allowed = new HashSet<string>(allowedTenants, StringComparer.OrdinalIgnoreCase);
        var entitled = snapshot.Nodes
            .Where(n => allowed.Contains(n.TenantId))
            .Select(n => new TenantTopologyEntry(n.TenantId, n.Depth, n.HasChildren))
            .ToList();

        var scopeHasChildren = snapshot.ScopeHasChildren && (entitled.Count > 0 || allowed.Contains(scope));
        return new TenantTopologyResult(scope, scopeHasChildren, entitled);
    }

    private async Task<TenantSubtree?> GetSnapshotAsync(string scope)
    {
        if (scope.Length == 0)
        {
            return null;
        }

        var key = CacheKeyPrefix + scope.ToUpperInvariant();
        if (cache.TryGetValue(key, out TenantSubtree? cached) && cached != null)
        {
            return cached;
        }

        // Single flight per key: the first caller starts the read, concurrent callers of the same scope share it.
        // Other scopes (including unknown ones, which are never cached) are not held up by it.
        var inFlight = InFlight.GetValue(cache, _ => new ConcurrentDictionary<string, Lazy<Task<TenantSubtree?>>>());
        var read = inFlight.GetOrAdd(key,
            k => new Lazy<Task<TenantSubtree?>>(() => ReadAsync(k, scope), LazyThreadSafetyMode.ExecutionAndPublication));
        try
        {
            return await read.Value;
        }
        finally
        {
            inFlight.TryRemove(new KeyValuePair<string, Lazy<Task<TenantSubtree?>>>(key, read));
        }
    }

    private async Task<TenantSubtree?> ReadAsync(string key, string scope)
    {
        // A read that finished between the caller's cache miss and this start has already stored its snapshot.
        if (cache.TryGetValue(key, out TenantSubtree? cached) && cached != null)
        {
            return cached;
        }

        var snapshot = await TenantSubtreeWalker.WalkAsync(systemContext, scope, logger,
            Math.Max(1, options.Value.TenantTopology.MaxNodes));
        if (snapshot == null)
        {
            return null;
        }

        cache.Set(key, snapshot, CacheTtl);
        logger.LogDebug("Tenant topology: scope '{Scope}' read, {Count} tenants below it", scope,
            snapshot.Nodes.Count);
        return snapshot;
    }
}
