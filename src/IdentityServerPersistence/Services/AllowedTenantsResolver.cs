using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Resolves the list of tenants a user is allowed to access.
///     This runs at token issuance time, not per-request.
/// </summary>
public interface IAllowedTenantsResolver
{
    Task<IReadOnlyList<string>> ResolveAsync(string loginTenantId, RtUser user);
}

/// <summary>
///     Default implementation that resolves allowed tenants by walking up the ancestor chain,
///     then doing a BFS down through descendant tenants checking cross-tenant user mappings.
///     The BFS tracks the user's username at each tier to follow the xt_ naming chain.
/// </summary>
public class AllowedTenantsResolver(
    ISystemContext systemContext,
    ILogger<AllowedTenantsResolver> logger) : IAllowedTenantsResolver
{
    private const int MaxHierarchyDepth = 10;

    public async Task<IReadOnlyList<string>> ResolveAsync(string loginTenantId, RtUser user)
    {
        var allowedTenants = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { loginTenantId };

        // Determine the source identity for cross-tenant lookups
        string sourceTenantId;
        string sourceUserName;

        if (user.UserName != null && user.UserName.StartsWith("xt_"))
        {
            // Cross-tenant user: extract home tenant from xt_{homeTenant}_{username}
            var parts = user.UserName.Split('_', 3);
            if (parts.Length >= 3)
            {
                var homeTenantId = parts[1];
                allowedTenants.Add(homeTenantId);
                sourceTenantId = homeTenantId;
                sourceUserName = parts[2]; // original username in home tenant
            }
            else
            {
                sourceTenantId = loginTenantId;
                sourceUserName = user.UserName;
            }
        }
        else
        {
            sourceTenantId = loginTenantId;
            sourceUserName = user.UserName ?? string.Empty;
        }

        // Walk up the ancestor chain from the login tenant via OctoTenantIdentityProvider.ParentTenantId
        await ResolveAncestorTenantsAsync(loginTenantId, allowedTenants);

        // Build BFS seeds by unwinding the xt_ username chain through all tiers.
        // e.g. (subtenant1, "xt_meshtest_xt_octosystem_admin") → (meshtest, "xt_octosystem_admin") → (octosystem, "admin")
        var bfsSeeds = BuildUserNameChain(loginTenantId, user.UserName ?? string.Empty);

        await ResolveDescendantTenantsAsync(bfsSeeds, allowedTenants);

        logger.LogDebug(
            "Resolved {Count} allowed tenants for user '{UserName}' (source: {SourceTenantId}): {Tenants}",
            allowedTenants.Count, user.UserName, sourceTenantId,
            string.Join(", ", allowedTenants));

        return allowedTenants.ToList();
    }

    /// <summary>
    ///     Builds the full (tenantId, username) chain by unwinding xt_ prefixes.
    ///     e.g. (subtenant1, "xt_meshtest_xt_octosystem_admin")
    ///        → (meshtest, "xt_octosystem_admin")
    ///        → (octosystem, "admin")
    /// </summary>
    private static List<(string TenantId, string UserName)> BuildUserNameChain(
        string loginTenantId, string userName)
    {
        var chain = new List<(string TenantId, string UserName)>();
        var currentTenantId = loginTenantId;
        var currentUserName = userName;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (!string.IsNullOrEmpty(currentUserName) && visited.Add(currentTenantId))
        {
            chain.Add((currentTenantId, currentUserName));

            if (!currentUserName.StartsWith("xt_"))
            {
                break;
            }

            var parts = currentUserName.Split('_', 3);
            if (parts.Length < 3)
            {
                break;
            }

            currentTenantId = parts[1]; // home tenant
            currentUserName = parts[2]; // username in home tenant
        }

        return chain;
    }

    /// <summary>
    ///     BFS through descendant tenants. For each seed (tenantId, username), get child tenants
    ///     and check for ExternalTenantUserMapping matching sourceUserName. When a match is found,
    ///     enqueue the child with the cross-tenant username pattern: xt_{parentTenantId}_{parentUsername}.
    /// </summary>
    private async Task ResolveDescendantTenantsAsync(
        List<(string TenantId, string UserName)> seeds, HashSet<string> allowedTenants)
    {
        var queue = new Queue<(string TenantId, string UserName)>(seeds);
        // Track which parents we've already processed to avoid infinite loops
        var processedParents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (queue.Count > 0)
        {
            var (currentTenantId, currentUserName) = queue.Dequeue();

            // Skip if we've already processed this tenant as a parent
            if (!processedParents.Add(currentTenantId))
            {
                continue;
            }

            if (string.IsNullOrEmpty(currentUserName))
            {
                continue;
            }

            try
            {
                var tenantContext = await systemContext.FindTenantContextAsync(currentTenantId);
                var adminSession = await tenantContext.GetAdminSessionAsync();
                var childTenants = await tenantContext.GetChildTenantsAsync(adminSession);

                foreach (var childTenant in childTenants.Items)
                {
                    // Skip children already in allowed tenants
                    if (allowedTenants.Contains(childTenant.TenantId))
                    {
                        continue;
                    }

                    try
                    {
                        var hasMapping = await HasExternalTenantUserMappingByNameAsync(
                            childTenant.TenantId, currentTenantId, currentUserName);
                        if (hasMapping)
                        {
                            allowedTenants.Add(childTenant.TenantId);

                            // The user in the child tenant will be: xt_{parentTenantId}_{parentUsername}
                            var childUserName = $"xt_{currentTenantId}_{currentUserName}";
                            queue.Enqueue((childTenant.TenantId, childUserName));
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex,
                            "Failed to check external tenant user mapping in tenant '{ChildTenantId}' for user '{UserName}' from tenant '{SourceTenantId}'",
                            childTenant.TenantId, currentUserName, currentTenantId);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "Failed to resolve child tenants for tenant '{TenantId}'",
                    currentTenantId);
            }
        }
    }

    private async Task ResolveAncestorTenantsAsync(string startTenantId, HashSet<string> allowedTenants)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { startTenantId };
        var currentTenantId = startTenantId;

        for (var depth = 0; depth < MaxHierarchyDepth; depth++)
        {
            try
            {
                var providers = await GetOctoTenantProvidersInTenantAsync(currentTenantId);
                var parentFound = false;

                foreach (var provider in providers)
                {
                    if (string.IsNullOrEmpty(provider.ParentTenantId))
                    {
                        continue;
                    }

                    if (!visited.Add(provider.ParentTenantId))
                    {
                        // Circular reference — stop
                        logger.LogWarning(
                            "Circular reference detected in tenant hierarchy at '{TenantId}'",
                            provider.ParentTenantId);
                        return;
                    }

                    allowedTenants.Add(provider.ParentTenantId);
                    currentTenantId = provider.ParentTenantId;
                    parentFound = true;
                    break; // Follow the first enabled provider's parent
                }

                if (!parentFound)
                {
                    break; // No parent — reached the root
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "Failed to resolve ancestor tenants from tenant '{TenantId}'",
                    currentTenantId);
                break;
            }
        }
    }

    private async Task<IEnumerable<RtOctoTenantIdentityProvider>> GetOctoTenantProvidersInTenantAsync(
        string tenantId)
    {
        try
        {
            var tenantRepository = await systemContext.FindTenantRepositoryAsync(tenantId);
            var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var queryOptions = RtEntityQueryOptions.Create();
            var result = await tenantRepository
                .GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(session, queryOptions);
            await session.CommitTransactionAsync();

            return result.Items.Where(p => p.IsEnabled);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to query OctoTenantIdentityProviders in tenant '{TenantId}'",
                tenantId);
            return [];
        }
    }

    private async Task<bool> HasExternalTenantUserMappingByNameAsync(
        string childTenantId, string sourceTenantId, string sourceUserName)
    {
        var tenantRepository = await systemContext.FindTenantRepositoryAsync(childTenantId);
        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId)
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserName), sourceUserName);

        var result = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items.Any();
    }
}
