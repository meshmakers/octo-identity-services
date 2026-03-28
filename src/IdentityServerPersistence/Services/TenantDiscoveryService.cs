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
    /// <returns>List of tenant IDs the user can access</returns>
    Task<IReadOnlyList<string>> FindTenantsForUserAsync(string emailOrUsername);
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
    public async Task<IReadOnlyList<string>> FindTenantsForUserAsync(string emailOrUsername)
    {
        if (string.IsNullOrWhiteSpace(emailOrUsername))
        {
            return [];
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

        return allAllowedTenants.ToList();
    }

    private async Task<IReadOnlyList<string>> GetAllTenantIdsAsync()
    {
        var tenantIds = new List<string>();

        try
        {
            // The system context itself is the system tenant
            tenantIds.Add(systemContext.TenantId);

            // Get all child tenants from the system tenant
            var adminSession = await systemContext.GetAdminSessionAsync();
            var childTenants = await systemContext.GetChildTenantsAsync(adminSession);

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
