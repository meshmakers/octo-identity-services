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
///     Default implementation that resolves allowed tenants by checking cross-tenant user mappings
///     across child tenants.
/// </summary>
public class AllowedTenantsResolver(
    ISystemContext systemContext,
    ILogger<AllowedTenantsResolver> logger) : IAllowedTenantsResolver
{
    public async Task<IReadOnlyList<string>> ResolveAsync(string loginTenantId, RtUser user)
    {
        var allowedTenants = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { loginTenantId };

        // Determine the source identity for cross-tenant lookups
        string sourceTenantId;
        string sourceUserId;

        if (user.UserName != null && user.UserName.StartsWith("xt_"))
        {
            // Cross-tenant user: extract home tenant from xt_{homeTenant}_{username}
            var parts = user.UserName.Split('_', 3);
            if (parts.Length >= 3)
            {
                var homeTenantId = parts[1];
                allowedTenants.Add(homeTenantId);
                sourceTenantId = homeTenantId;

                // For cross-tenant users, resolve the source user in the home tenant
                var sourceUser = await FindSourceUserAsync(homeTenantId, user);
                sourceUserId = sourceUser?.RtId.ToString() ?? user.RtId.ToString();
            }
            else
            {
                sourceTenantId = loginTenantId;
                sourceUserId = user.RtId.ToString();
            }
        }
        else
        {
            sourceTenantId = loginTenantId;
            sourceUserId = user.RtId.ToString();
        }

        // Get all child tenants and check for mappings
        try
        {
            var tenantContext = await systemContext.FindTenantContextAsync(sourceTenantId);
            var adminSession = await tenantContext.GetAdminSessionAsync();
            var childTenants = await tenantContext.GetChildTenantsAsync(adminSession);

            foreach (var childTenant in childTenants.Items)
            {
                if (allowedTenants.Contains(childTenant.TenantId))
                {
                    continue;
                }

                try
                {
                    var hasMapping = await HasExternalTenantUserMappingAsync(
                        childTenant.TenantId, sourceTenantId, sourceUserId);
                    if (hasMapping)
                    {
                        allowedTenants.Add(childTenant.TenantId);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex,
                        "Failed to check external tenant user mapping in tenant '{ChildTenantId}' for user '{UserId}' from tenant '{SourceTenantId}'",
                        childTenant.TenantId, sourceUserId, sourceTenantId);
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to resolve child tenants for source tenant '{SourceTenantId}'",
                sourceTenantId);
        }

        logger.LogDebug(
            "Resolved {Count} allowed tenants for user '{UserName}' (source: {SourceTenantId}/{SourceUserId}): {Tenants}",
            allowedTenants.Count, user.UserName, sourceTenantId, sourceUserId,
            string.Join(", ", allowedTenants));

        return allowedTenants.ToList();
    }

    private async Task<RtUser?> FindSourceUserAsync(string homeTenantId, RtUser crossTenantUser)
    {
        try
        {
            // The cross-tenant user in the child tenant has the original username embedded:
            // xt_{homeTenant}_{originalUsername}
            var parts = crossTenantUser.UserName!.Split('_', 3);
            if (parts.Length < 3)
            {
                return null;
            }

            var originalUserName = parts[2];
            var tenantRepository = await systemContext.FindTenantRepositoryAsync(homeTenantId);
            var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var queryOptions = RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtUser.NormalizedUserName), originalUserName.ToUpperInvariant());

            var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, queryOptions);
            await session.CommitTransactionAsync();

            return result.Items.SingleOrDefault();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to find source user for cross-tenant user '{UserName}' in tenant '{TenantId}'",
                crossTenantUser.UserName, homeTenantId);
            return null;
        }
    }

    private async Task<bool> HasExternalTenantUserMappingAsync(
        string childTenantId, string sourceTenantId, string sourceUserId)
    {
        var tenantRepository = await systemContext.FindTenantRepositoryAsync(childTenantId);
        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId)
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), sourceUserId);

        var result = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items.Any();
    }
}
