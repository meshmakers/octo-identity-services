using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Discovers which tenants a user belongs to by searching across all tenant databases.
///     Used by the tenant picker flow when no <c>acr_values</c> is present on the authorize request.
/// </summary>
public interface ITenantDiscoveryService
{
    /// <summary>
    ///     Finds all tenants a user can access, searching by email or username.
    ///     First locates the user's home tenant(s), then resolves all allowed tenants
    ///     via cross-tenant mappings using <see cref="IAllowedTenantsResolver" />.
    /// </summary>
    /// <param name="emailOrUsername">The email address or username to search for</param>
    /// <param name="scopeTenantId">
    ///     Optional discovery scope (AB#5311): when set, only tenants strictly below this tenant in
    ///     the registry hierarchy — direct and indirect descendants, never the scope itself — are
    ///     returned. The scope only narrows the result; it never adds a tenant the user is not in.
    ///     An unknown scope yields an empty result rather than the unscoped list.
    /// </param>
    /// <returns>List of tenant IDs the user can access</returns>
    Task<IReadOnlyList<string>> FindTenantsForUserAsync(string emailOrUsername, string? scopeTenantId = null);

    /// <summary>
    ///     Resolves the tenants strictly below <paramref name="scopeTenantId" /> in the registry
    ///     hierarchy (direct and indirect descendants). <c>null</c> when the scope is not a
    ///     registered tenant, so a caller can tell "unknown scope" from "scope without children".
    /// </summary>
    Task<IReadOnlySet<string>?> GetScopeDescendantsAsync(string scopeTenantId);
}

/// <summary>
///     Default implementation that first finds the user's home tenant(s) by searching all
///     tenant databases, then uses <see cref="IAllowedTenantsResolver" /> to resolve the
///     complete list of accessible tenants (including cross-tenant mappings).
/// </summary>
public class TenantDiscoveryService(
    ISystemContext systemContext,
    IAllowedTenantsResolver allowedTenantsResolver,
    ILogger<TenantDiscoveryService> logger) : ITenantDiscoveryService
{
    public async Task<IReadOnlyList<string>> FindTenantsForUserAsync(string emailOrUsername,
        string? scopeTenantId = null)
    {
        if (string.IsNullOrWhiteSpace(emailOrUsername))
        {
            return [];
        }

        // Resolve the scope first: an unknown scope is an empty answer, no matter who asks. The
        // user search below is deliberately NOT restricted to the subtree — the user's home may
        // lie outside it (an administrator whose home is the system tenant reaches the subtree
        // through cross-tenant mappings), so the filter applies to the resolved result.
        IReadOnlySet<string>? scope = null;
        if (!string.IsNullOrWhiteSpace(scopeTenantId))
        {
            scope = await GetScopeDescendantsAsync(scopeTenantId.Trim());
            if (scope == null)
            {
                logger.LogWarning(
                    "Tenant discovery: scope '{ScopeTenantId}' is not a registered tenant — returning no tenants",
                    scopeTenantId);
                return [];
            }
        }

        var normalizedInput = emailOrUsername.Trim().ToUpperInvariant();

        // Collect all tenant IDs: system tenant + all child tenants
        var tenantIds = await GetAllTenantIdsAsync();

        // Search all tenants in parallel for the "real" user (not xt_ shadow users)
        var tasks = tenantIds.Select(tenantId => FindUserInTenantAsync(tenantId, normalizedInput));
        var results = await Task.WhenAll(tasks);

        var homeResults = results
            .Where(r => r.HasValue)
            .Select(r => r!.Value)
            .ToList();

        if (homeResults.Count == 0)
        {
            return [];
        }

        // For each home tenant where the user was found, resolve all allowed tenants
        // via cross-tenant mappings (AllowedTenantsResolver handles hierarchy traversal)
        var allAllowedTenants = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (tenantId, user) in homeResults)
        {
            try
            {
                var allowed = await allowedTenantsResolver.ResolveAsync(tenantId, user);
                foreach (var t in allowed)
                {
                    allAllowedTenants.Add(t);
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "Failed to resolve allowed tenants for user '{UserName}' in tenant '{TenantId}'",
                    user.UserName, tenantId);
                // Still include the home tenant even if resolver fails
                allAllowedTenants.Add(tenantId);
            }
        }

        if (scope != null)
        {
            allAllowedTenants.IntersectWith(scope);
        }

        return allAllowedTenants.ToList();
    }

    public async Task<IReadOnlySet<string>?> GetScopeDescendantsAsync(string scopeTenantId)
    {
        if (string.IsNullOrWhiteSpace(scopeTenantId))
        {
            return null;
        }

        try
        {
            var adminSession = await systemContext.GetAdminSessionAsync();
            var registry = await systemContext.GetAllTenantsAsync(adminSession);
            return CollectDescendants(registry.Items, systemContext.TenantId, scopeTenantId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to resolve the discovery scope '{ScopeTenantId}'", scopeTenantId);
            return null;
        }
    }

    /// <summary>
    ///     Walks the registry hierarchy below <paramref name="scopeTenantId" />. A registry record
    ///     without a parent id is a direct child of the registry owner, i.e. the system tenant
    ///     (see <see cref="OctoTenant.ParentTenantId" />). Ids compare case-insensitively; the
    ///     returned ids carry the registry's spelling. <c>null</c> when the scope is neither the
    ///     system tenant nor a registered tenant.
    /// </summary>
    internal static IReadOnlySet<string>? CollectDescendants(IEnumerable<OctoTenant> registry,
        string systemTenantId, string scopeTenantId)
    {
        var childrenByParent = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { systemTenantId };

        foreach (var tenant in registry)
        {
            known.Add(tenant.TenantId);
            var parent = string.IsNullOrEmpty(tenant.ParentTenantId) ? systemTenantId : tenant.ParentTenantId;
            if (!childrenByParent.TryGetValue(parent, out var children))
            {
                children = [];
                childrenByParent[parent] = children;
            }

            children.Add(tenant.TenantId);
        }

        if (!known.Contains(scopeTenantId))
        {
            return null;
        }

        var descendants = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<string>();
        queue.Enqueue(scopeTenantId);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!childrenByParent.TryGetValue(current, out var children))
            {
                continue;
            }

            foreach (var child in children)
            {
                // A cycle in a hand-edited registry must not loop forever.
                if (descendants.Add(child) && !string.Equals(child, scopeTenantId, StringComparison.OrdinalIgnoreCase))
                {
                    queue.Enqueue(child);
                }
            }
        }

        descendants.Remove(scopeTenantId);
        return descendants;
    }

    private async Task<IReadOnlyList<string>> GetAllTenantIdsAsync()
    {
        var tenantIds = new List<string>();

        try
        {
            // The system context itself is the system tenant
            tenantIds.Add(systemContext.TenantId);

            // Get every registered tenant from the system registry (regardless of logical parent)
            var adminSession = await systemContext.GetAdminSessionAsync();
            var childTenants = await systemContext.GetAllTenantsAsync(adminSession);

            foreach (var child in childTenants.Items)
            {
                tenantIds.Add(child.TenantId);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to enumerate tenants for tenant discovery");
        }

        return tenantIds;
    }

    /// <summary>
    ///     Searches for a user in a specific tenant by normalized username or email.
    ///     Returns the tenant ID and user if found, null otherwise.
    ///     Cross-tenant shadow users (xt_ prefix) are excluded.
    /// </summary>
    private async Task<(string TenantId, RtUser User)?> FindUserInTenantAsync(
        string tenantId, string normalizedInput)
    {
        try
        {
            var tenantRepository = await systemContext.FindTenantRepositoryAsync(tenantId);
            var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            // Search by normalized username
            var byNameOptions = RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtUser.NormalizedUserName), normalizedInput);
            var byNameResult = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, byNameOptions);

            var user = byNameResult.Items.FirstOrDefault();

            // If not found by username, search by normalized email
            if (user == null)
            {
                var byEmailOptions = RtEntityQueryOptions.Create()
                    .FieldEquals(nameof(RtUser.NormalizedEmail), normalizedInput);
                var byEmailResult = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, byEmailOptions);
                user = byEmailResult.Items.FirstOrDefault();
            }

            await session.CommitTransactionAsync();

            if (user == null)
            {
                return null;
            }

            // Exclude cross-tenant shadow users (xt_ prefix)
            if (user.UserName != null && user.UserName.StartsWith("xt_", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return (tenantId, user);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to search for user in tenant '{TenantId}' during tenant discovery",
                tenantId);
            return null;
        }
    }
}
