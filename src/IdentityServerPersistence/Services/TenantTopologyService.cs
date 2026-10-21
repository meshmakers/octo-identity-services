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

    // One gate per cache instance (= process-wide in production): the service is scoped.
    private static readonly ConditionalWeakTable<IMemoryCache, SemaphoreSlim> Gates = new();

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

        // Single flight: the first caller reads the hierarchy, the others wait and then find its snapshot.
        var gate = Gates.GetValue(cache, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync();
        try
        {
            if (cache.TryGetValue(key, out cached) && cached != null)
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
        finally
        {
            gate.Release();
        }
    }
}
