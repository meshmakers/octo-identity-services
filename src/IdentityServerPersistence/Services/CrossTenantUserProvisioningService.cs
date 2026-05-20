using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <inheritdoc />
public class CrossTenantUserProvisioningService(
    UserManager<RtUser> userManager,
    IExternalTenantUserMappingStore externalTenantUserMappingStore,
    IMultiTenancyResolverService multiTenancyResolverService,
    ILogger<CrossTenantUserProvisioningService> logger)
    : ICrossTenantUserProvisioningService
{
    /// <inheritdoc />
    public async Task<RtUser?> FindOrCreateCrossTenantUserAsync(
        CrossTenantAuthResult crossTenantResult, string childTenantId)
    {
        // Check if a mapping already exists
        var mapping = await externalTenantUserMappingStore.FindBySourceUserAsync(
            crossTenantResult.SourceTenantId, crossTenantResult.SourceUserId);

        // Generate a unique username for the cross-tenant user
        var crossTenantUserName = $"xt_{crossTenantResult.SourceTenantId}_{crossTenantResult.SourceUserName}";

        var existingUser = await userManager.FindByNameAsync(crossTenantUserName);
        if (existingUser != null)
        {
            // Sync profile fields from the source tenant on each login
            var needsUpdate = false;

            if (!string.Equals(existingUser.FirstName, crossTenantResult.FirstName ?? string.Empty,
                    StringComparison.Ordinal))
            {
                existingUser.FirstName = crossTenantResult.FirstName ?? string.Empty;
                needsUpdate = true;
            }

            if (!string.Equals(existingUser.LastName, crossTenantResult.LastName ?? string.Empty,
                    StringComparison.Ordinal))
            {
                existingUser.LastName = crossTenantResult.LastName ?? string.Empty;
                needsUpdate = true;
            }

            if (!string.Equals(existingUser.Email, crossTenantResult.Email, StringComparison.OrdinalIgnoreCase))
            {
                existingUser.Email = crossTenantResult.Email;
                existingUser.NormalizedEmail = crossTenantResult.Email?.ToUpperInvariant();
                needsUpdate = true;
            }

            if (needsUpdate)
            {
                var updateResult = await userManager.UpdateAsync(existingUser);
                if (!updateResult.Succeeded)
                {
                    logger.LogWarning(
                        "Failed to update cross-tenant user profile for '{UserName}': {Errors}",
                        crossTenantUserName,
                        string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                }
            }

            // Sync roles from the mapping on each login
            if (mapping != null)
            {
                await SyncMappedRolesAsync(existingUser, mapping);
            }

            return existingUser;
        }

        // Create a local user for this cross-tenant login
        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = crossTenantUserName,
            NormalizedUserName = crossTenantUserName.ToUpperInvariant(),
            Email = crossTenantResult.Email,
            NormalizedEmail = crossTenantResult.Email?.ToUpperInvariant(),
            EmailConfirmed = true,
            FirstName = crossTenantResult.FirstName ?? string.Empty,
            LastName = crossTenantResult.LastName ?? string.Empty,
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var createResult = await userManager.CreateAsync(user);
        if (!createResult.Succeeded)
        {
            logger.LogError(
                "Failed to create cross-tenant user '{UserName}': {Errors}",
                crossTenantUserName,
                string.Join(", ", createResult.Errors.Select(e => e.Description)));
            return null;
        }

        // Create the mapping if it doesn't exist
        if (mapping == null)
        {
            mapping = new RtExternalTenantUserMapping
            {
                RtId = OctoObjectId.GenerateNewId(),
                SourceTenantId = crossTenantResult.SourceTenantId,
                SourceUserId = crossTenantResult.SourceUserId,
                SourceUserName = crossTenantResult.SourceUserName
            };
            await externalTenantUserMappingStore.StoreAsync(mapping);
        }

        // Assign mapped roles to the user
        await SyncMappedRolesAsync(user, mapping);

        logger.LogInformation(
            "Created cross-tenant user '{UserName}' in tenant '{TenantId}' for source user '{SourceUser}' from tenant '{SourceTenant}'",
            crossTenantUserName, childTenantId, crossTenantResult.SourceUserName,
            crossTenantResult.SourceTenantId);

        return user;
    }

    /// <summary>
    /// Syncs roles from an ExternalTenantUserMapping to the local cross-tenant user.
    /// Queries roles directly from the tenant repository to avoid RoleManager tenant scoping issues,
    /// then uses AddToRoleAsync with the resolved role names.
    /// </summary>
    private async Task SyncMappedRolesAsync(RtUser user, RtExternalTenantUserMapping mapping)
    {
        if (mapping.MappedRoleIds == null || mapping.MappedRoleIds.Count == 0)
        {
            return;
        }

        // Query all roles from the tenant repository directly to build an ID → name lookup.
        // This avoids RoleManager/OctoRoleStore tenant resolution issues during cross-tenant login.
        var tenantRepository = multiTenancyResolverService.GetTenantRepository();
        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var allRolesResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();

        var roleNameById = allRolesResult.Items
            .ToDictionary(r => r.RtId.ToString(), r => r.Name);

        var currentRoles = await userManager.GetRolesAsync(user);

        foreach (var roleId in mapping.MappedRoleIds)
        {
            if (!roleNameById.TryGetValue(roleId, out var roleName) || string.IsNullOrEmpty(roleName))
            {
                logger.LogWarning("Mapped role ID '{RoleId}' not found in tenant, skipping", roleId);
                continue;
            }

            if (!currentRoles.Contains(roleName, StringComparer.OrdinalIgnoreCase))
            {
                var result = await userManager.AddToRoleAsync(user, roleName);
                if (!result.Succeeded)
                {
                    logger.LogWarning(
                        "Failed to assign role '{RoleName}' to user '{UserName}': {Errors}",
                        roleName, user.UserName,
                        string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }
    }
}
