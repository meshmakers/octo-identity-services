using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

public class CrossTenantAuthenticationService(
    ISystemContext systemContext,
    IOctoIdentityProviderStore identityProviderStore,
    IPasswordHasher<RtUser> passwordHasher,
    ILogger<CrossTenantAuthenticationService> logger) : ICrossTenantAuthenticationService
{
    private const int MaxHierarchyDepth = 10;

    public async Task<CrossTenantAuthResult?> AuthenticateAsync(
        string childTenantId, string username, string password)
    {
        // Get configured OctoTenantIdentityProviders for the child tenant
        var providers = await GetOctoTenantProvidersAsync();
        if (!providers.Any())
        {
            logger.LogDebug(
                "No OctoTenantIdentityProvider configured for tenant '{TenantId}'",
                childTenantId);
            return null;
        }

        // Walk up the tenant hierarchy
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { childTenantId };

        foreach (var provider in providers)
        {
            if (!provider.IsEnabled)
            {
                logger.LogDebug(
                    "Skipping disabled OctoTenantIdentityProvider '{ProviderName}' in tenant '{TenantId}'",
                    provider.Name, childTenantId);
                continue;
            }

            var parentTenantId = provider.ParentTenantId;
            if (string.IsNullOrEmpty(parentTenantId))
            {
                continue;
            }

            var result = await TryAuthenticateInHierarchyAsync(
                parentTenantId, username, password, visited, 0);
            if (result != null)
            {
                return result;
            }
        }

        return null;
    }

    public async Task<CrossTenantAuthResult?> ValidateCrossTenantAccessAsync(
        string targetTenantId, string sourceTenantId, string sourceUserId)
    {
        // Verify the source tenant is an ancestor of the target tenant
        // by walking up from the target tenant
        var isAncestor = await IsAncestorTenantAsync(targetTenantId, sourceTenantId);
        if (!isAncestor)
        {
            logger.LogWarning(
                "Tenant switch denied: '{SourceTenantId}' is not an ancestor of '{TargetTenantId}'",
                sourceTenantId, targetTenantId);
            return null;
        }

        // Find the user in the source tenant
        var user = await FindUserByIdInTenantAsync(sourceTenantId, sourceUserId);
        if (user == null)
        {
            logger.LogWarning(
                "Tenant switch denied: user '{UserId}' not found in tenant '{TenantId}'",
                sourceUserId, sourceTenantId);
            return null;
        }

        return new CrossTenantAuthResult
        {
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = user.UserName ?? string.Empty,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email
        };
    }

    private async Task<CrossTenantAuthResult?> TryAuthenticateInHierarchyAsync(
        string tenantId, string username, string password,
        HashSet<string> visited, int depth)
    {
        if (depth >= MaxHierarchyDepth)
        {
            logger.LogWarning(
                "Max hierarchy depth ({MaxDepth}) reached while traversing tenant hierarchy from '{TenantId}'",
                MaxHierarchyDepth, tenantId);
            return null;
        }

        if (!visited.Add(tenantId))
        {
            logger.LogWarning(
                "Circular reference detected in tenant hierarchy at '{TenantId}'",
                tenantId);
            return null;
        }

        // Try to find and validate the user in this tenant
        var user = await FindUserByNameInTenantAsync(tenantId, username);
        if (user != null)
        {
            // Validate password
            var verifyResult = passwordHasher.VerifyHashedPassword(
                user, user.PasswordHash ?? string.Empty, password);

            if (verifyResult != PasswordVerificationResult.Failed)
            {
                // Check if the user is locked out
                if (user.LockoutEnabled && user.LockoutEnd.HasValue &&
                    user.LockoutEnd.Value > DateTimeOffset.UtcNow)
                {
                    logger.LogInformation(
                        "Cross-tenant auth: user '{UserName}' in tenant '{TenantId}' is locked out",
                        username, tenantId);
                    return null;
                }

                logger.LogInformation(
                    "Cross-tenant auth succeeded: user '{UserName}' found in tenant '{TenantId}'",
                    username, tenantId);

                return new CrossTenantAuthResult
                {
                    SourceTenantId = tenantId,
                    SourceUserId = user.RtId.ToString(),
                    SourceUserName = user.UserName ?? username,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email
                };
            }
        }

        // User not found or password invalid in this tenant — try its parent
        var parentProviders = await GetOctoTenantProvidersInTenantAsync(tenantId);
        foreach (var provider in parentProviders)
        {
            if (!provider.IsEnabled || string.IsNullOrEmpty(provider.ParentTenantId))
            {
                continue;
            }

            var result = await TryAuthenticateInHierarchyAsync(
                provider.ParentTenantId, username, password, visited, depth + 1);
            if (result != null)
            {
                return result;
            }
        }

        return null;
    }

    private async Task<bool> IsAncestorTenantAsync(string childTenantId, string ancestorTenantId)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { childTenantId };
        var currentTenantId = childTenantId;

        for (var depth = 0; depth < MaxHierarchyDepth; depth++)
        {
            var providers = await GetOctoTenantProvidersInTenantAsync(currentTenantId);
            var parentFound = false;

            foreach (var provider in providers)
            {
                if (!provider.IsEnabled || string.IsNullOrEmpty(provider.ParentTenantId))
                {
                    continue;
                }

                if (string.Equals(provider.ParentTenantId, ancestorTenantId,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (visited.Add(provider.ParentTenantId))
                {
                    currentTenantId = provider.ParentTenantId;
                    parentFound = true;
                    break;
                }
            }

            if (!parentFound)
            {
                break;
            }
        }

        return false;
    }

    /// <inheritdoc />
    public async Task<string?> FindUserIdByNameInTenantAsync(string tenantId, string userName)
    {
        var user = await FindUserByNameInTenantAsync(tenantId, userName);
        return user?.RtId.ToString();
    }

    private async Task<RtUser?> FindUserByNameInTenantAsync(string tenantId, string username)
    {
        try
        {
            var tenantRepository = await systemContext.FindTenantRepositoryAsync(tenantId);
            var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var normalizedUserName = username.ToUpperInvariant();
            var queryOptions = RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtUser.NormalizedUserName), normalizedUserName);

            var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, queryOptions);
            await session.CommitTransactionAsync();

            return result.Items.SingleOrDefault();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to query user '{UserName}' in tenant '{TenantId}'",
                username, tenantId);
            return null;
        }
    }

    private async Task<RtUser?> FindUserByIdInTenantAsync(string tenantId, string userId)
    {
        try
        {
            var tenantRepository = await systemContext.FindTenantRepositoryAsync(tenantId);
            var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var rtId = new Meshmakers.Octo.ConstructionKit.Contracts.OctoObjectId(userId);
            var result = await tenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
            await session.CommitTransactionAsync();

            return result;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to query user '{UserId}' in tenant '{TenantId}'",
                userId, tenantId);
            return null;
        }
    }

    private async Task<IEnumerable<RtOctoTenantIdentityProvider>> GetOctoTenantProvidersAsync()
    {
        var allProviders = await identityProviderStore.GetAllAsync();
        return allProviders.OfType<RtOctoTenantIdentityProvider>();
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
}
