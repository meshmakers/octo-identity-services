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
///     Default implementation: the login tenant, the home tenants a cross-tenant shadow user's name
///     unwinds to, and every descendant tenant reachable through cross-tenant user mappings — a BFS
///     that follows the xt_ naming chain tier by tier.
/// </summary>
/// <remarks>
///     Ancestors are deliberately NOT added by walking the identity-provider graph (AB#5170). An
///     <c>OctoTenantIdentityProvider</c> says where a tenant delegates authentication to, not that
///     every user of that tenant exists up there: a user created locally in an operating tenant has
///     no account in the parent, and the switch gate
///     (<c>CrossTenantAuthenticationService.ValidateCrossTenantAccessAsync</c>) refuses them anyway.
///     Offering those tenants regardless — in <c>allowed_tenants</c>, the Studio switcher and the
///     email-first tenant discovery — sent such users to a login they could never pass. The tenants
///     a user really holds above the login tenant are exactly the home tenants of the
///     <c>xt_{home}_{name}</c> chain, which <see cref="BuildUserNameChain" /> yields.
/// </remarks>
public class AllowedTenantsResolver(
    ISystemContext systemContext,
    ILogger<AllowedTenantsResolver> logger) : IAllowedTenantsResolver
{
    public async Task<IReadOnlyList<string>> ResolveAsync(string loginTenantId, RtUser user)
    {
        var allowedTenants = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { loginTenantId };

        // Every tier of the xt_ chain is a tenant the user exists in: the login tenant itself, then
        // the home tenant of each shadow user upwards. A local user's chain is the login tenant alone.
        // e.g. (subtenant1, "xt_meshtest_xt_octosystem_admin") → (meshtest, "xt_octosystem_admin") → (octosystem, "admin")
        var chain = BuildUserNameChain(loginTenantId, user.UserName ?? string.Empty);
        foreach (var (tenantId, _) in chain)
        {
            allowedTenants.Add(tenantId);
        }

        // Every tier is also a seed for the mapping walk downwards.
        await ResolveDescendantTenantsAsync(chain, allowedTenants);

        logger.LogDebug(
            "Resolved {Count} allowed tenants for user '{UserName}' (home: {HomeTenantId}): {Tenants}",
            allowedTenants.Count, user.UserName, chain.Count > 0 ? chain[^1].TenantId : loginTenantId,
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
    ///     BFS through descendant tenants. For each seed (tenantId, username), check every candidate
    ///     tenant for an ExternalTenantUserMapping matching sourceUserName. When a match is found,
    ///     enqueue the child with the cross-tenant username pattern: xt_{parentTenantId}_{parentUsername}.
    /// </summary>
    /// <remarks>
    ///     Candidates are the full tenant registry, not per-parent child lists: the mapping check
    ///     itself carries the source tenant, so it is the actual relation. Since
    ///     GetChildTenantsAsync filters by ParentTenantId (AB#5025), a per-parent walk would drop
    ///     mappings that predate the hierarchy — e.g. an xt_octosystem_* user in a tenant that was
    ///     later re-parented under another tenant would lose that tenant from allowed_tenants.
    /// </remarks>
    private async Task ResolveDescendantTenantsAsync(
        List<(string TenantId, string UserName)> seeds, HashSet<string> allowedTenants)
    {
        IReadOnlyList<string> candidateTenantIds;
        try
        {
            using var adminSession = await systemContext.GetAdminSessionAsync();
            var allTenants = await systemContext.GetAllTenantsAsync(adminSession);
            candidateTenantIds = allTenants.Items.Select(t => t.TenantId).ToList();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to enumerate tenants for allowed-tenant resolution");
            return;
        }

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

            foreach (var childTenantId in candidateTenantIds)
            {
                // Skip children already in allowed tenants
                if (allowedTenants.Contains(childTenantId))
                {
                    continue;
                }

                try
                {
                    var hasMapping = await HasExternalTenantUserMappingByNameAsync(
                        childTenantId, currentTenantId, currentUserName);
                    if (hasMapping)
                    {
                        allowedTenants.Add(childTenantId);

                        // The user in the child tenant will be: xt_{parentTenantId}_{parentUsername}
                        var childUserName = $"xt_{currentTenantId}_{currentUserName}";
                        queue.Enqueue((childTenantId, childUserName));
                    }
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex,
                        "Failed to check external tenant user mapping in tenant '{ChildTenantId}' for user '{UserName}' from tenant '{SourceTenantId}'",
                        childTenantId, currentUserName, currentTenantId);
                }
            }
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
