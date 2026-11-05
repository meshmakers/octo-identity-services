using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services;

/// <summary>One tenant below a scope: depth 1 = direct child of the scope; <c>HasChildren</c> = it has at least one child itself.</summary>
public sealed record TenantSubtreeNode(string TenantId, int Depth, bool HasChildren);

/// <summary>The subtree strictly below a registered scope tenant, in breadth-first order.</summary>
public sealed record TenantSubtree(bool ScopeHasChildren, IReadOnlyList<TenantSubtreeNode> Nodes);

/// <summary>
///     Walks the tenant hierarchy below a scope tenant through each tenant's own context. Extracted from
///     <see cref="TenantDiscoveryService.GetScopeDescendantsAsync" /> (AB#7044) so discovery and the
///     tenant-topology endpoint share one walk.
/// </summary>
/// <remarks>
///     <para>
///         The walk goes through <see cref="ITenantContext.GetChildTenantsAsync" /> of every tenant — the
///         parent-local rows of its own database plus the platform-registry rows stamped with it — and
///         deliberately NOT through <see cref="ISystemContext.GetAllTenantsAsync" />, which drops the parent id
///         of every registry row (found on prod-1 with 3.4.126).
///     </para>
///     <para>
///         Only registered children count (AB#6759). A parent-local row is a descendant only when the system
///         registry holds the same tenant id with the same database and names this parent (or no parent, for
///         rows written before the field existed). A stale row left behind by a delete — or one whose name was
///         later reused by a tenant under another parent — is skipped and never walked into, so it can neither
///         widen a scope nor let a scope filter accept a stranger's tenant.
///     </para>
///     <para>
///         A cycle in a hand-edited registry terminates (visited guard). A child without a tenant context
///         (half-created tenant) is a leaf. Anything that makes the walk incomplete — a failing read, or more
///         than <c>maxNodes</c> tenants — throws <see cref="TenantHierarchyUnreadableException" />: callers
///         decide whether that is "unknown" (discovery) or fail closed (topology).
///     </para>
/// </remarks>
public static class TenantSubtreeWalker
{
    /// <returns><c>null</c> when <paramref name="scopeTenantId" /> is not a registered tenant.</returns>
    /// <exception cref="TenantHierarchyUnreadableException">The hierarchy could not be read completely.</exception>
    public static async Task<TenantSubtree?> WalkAsync(ISystemContext systemContext, string scopeTenantId,
        ILogger logger, int maxNodes = int.MaxValue)
    {
        if (string.IsNullOrWhiteSpace(scopeTenantId))
        {
            return null;
        }

        try
        {
            var scopeContext = await systemContext.TryFindTenantContextAsync(scopeTenantId);
            if (scopeContext == null)
            {
                return null;
            }

            var registry = await LoadRegistryAsync(systemContext);

            var nodes = new List<TenantSubtreeNode>();
            var indexById = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { scopeTenantId };
            var queue = new Queue<(string TenantId, int Depth, ITenantContext Context)>();
            queue.Enqueue((scopeTenantId, 0, scopeContext));
            var scopeHasChildren = false;

            while (queue.Count > 0)
            {
                var (tenantId, depth, context) = queue.Dequeue();
                using var adminSession = await context.GetAdminSessionAsync();
                var children = await context.GetChildTenantsAsync(adminSession);

                var registeredChildren = new List<OctoTenant>();
                foreach (var child in children.Items)
                {
                    if (IsRegisteredChildOf(registry, child, tenantId))
                    {
                        registeredChildren.Add(child);
                    }
                    else
                    {
                        logger.LogDebug(
                            "Tenant hierarchy: '{ChildTenantId}' listed by '{TenantId}' (database '{DatabaseName}') is not " +
                            "registered as its child — stale entry skipped (AB#6759)",
                            child.TenantId, tenantId, child.DatabaseName);
                    }
                }

                var hasChildren = registeredChildren.Count > 0;
                if (depth == 0)
                {
                    scopeHasChildren = hasChildren;
                }
                else
                {
                    var index = indexById[tenantId];
                    nodes[index] = nodes[index] with { HasChildren = hasChildren };
                }

                foreach (var child in registeredChildren)
                {
                    // A cycle in a hand-edited registry must not loop forever.
                    if (!visited.Add(child.TenantId))
                    {
                        continue;
                    }

                    if (nodes.Count >= maxNodes)
                    {
                        throw new TenantHierarchyUnreadableException(
                            $"The tenant hierarchy below '{scopeTenantId}' exceeds the limit of {maxNodes} tenants.");
                    }

                    indexById[child.TenantId] = nodes.Count;
                    nodes.Add(new TenantSubtreeNode(child.TenantId, depth + 1, false));

                    var childContext = await systemContext.TryFindTenantContextAsync(child.TenantId);
                    if (childContext != null)
                    {
                        queue.Enqueue((child.TenantId, depth + 1, childContext));
                    }
                    else
                    {
                        logger.LogDebug(
                            "Tenant hierarchy: child '{ChildTenantId}' of '{TenantId}' has no tenant context — treated as a leaf",
                            child.TenantId, tenantId);
                    }
                }
            }

            return new TenantSubtree(scopeHasChildren, nodes);
        }
        catch (TenantHierarchyUnreadableException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new TenantHierarchyUnreadableException(
                $"The tenant hierarchy below '{scopeTenantId}' could not be read.", ex);
        }
    }

    /// <summary>The system registry by tenant id; it is the single source of which tenants exist.</summary>
    private static async Task<IReadOnlyDictionary<string, OctoTenant>> LoadRegistryAsync(ISystemContext systemContext)
    {
        using var adminSession = await systemContext.GetAdminSessionAsync();
        var all = await systemContext.GetAllTenantsAsync(adminSession);
        var registry = new Dictionary<string, OctoTenant>(StringComparer.OrdinalIgnoreCase);
        foreach (var tenant in all.Items)
        {
            registry.TryAdd(tenant.TenantId, tenant);
        }

        return registry;
    }

    /// <summary>
    ///     A row listed by <paramref name="parentTenantId" /> is its child only when the registry holds the same
    ///     tenant with the same database, stamped with that parent (or unstamped, legacy).
    /// </summary>
    private static bool IsRegisteredChildOf(IReadOnlyDictionary<string, OctoTenant> registry, OctoTenant child,
        string parentTenantId)
    {
        if (!registry.TryGetValue(child.TenantId, out var registered))
        {
            return false;
        }

        if (!string.Equals(registered.DatabaseName, child.DatabaseName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return registered.ParentTenantId == null ||
               string.Equals(registered.ParentTenantId, parentTenantId, StringComparison.OrdinalIgnoreCase);
    }
}
