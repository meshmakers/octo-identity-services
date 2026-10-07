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
    ICrossTenantShadowUserChainResolver shadowUserChainResolver,
    ILogger<CrossTenantUserProvisioningService> logger)
    : ICrossTenantUserProvisioningService
{
    /// <inheritdoc />
    public async Task<RtUser?> FindCrossTenantUserAsync(CrossTenantAuthResult crossTenantResult)
    {
        var crossTenantUserName = CrossTenantShadowUserName.Build(
            crossTenantResult.SourceTenantId, crossTenantResult.SourceUserName);

        // The exact name wins, so every shadow user that exists today keeps being used by the login
        // path that created it — including both halves of a legacy duplicate.
        var exactUser = await userManager.FindByNameAsync(crossTenantUserName);
        if (exactUser != null)
        {
            return exactUser;
        }

        // AB#5708: the same person reaches this tenant under different source identities depending on
        // the login path (password login unwinds to the home tenant, a tenant switch or auto-login
        // starts at the parent's shadow user). Reuse the shadow user any of those paths created
        // instead of minting a second, role-less one.
        var rootIdentity = await shadowUserChainResolver.GetRootIdentityAsync(
            crossTenantResult.SourceTenantId, crossTenantResult.SourceUserName);
        var rootShadowUserName = CrossTenantShadowUserName.Build(rootIdentity.TenantId, rootIdentity.UserName);

        var tenantRepository = multiTenancyResolverService.GetTenantRepository();
        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        // Every shadow user of this person ends with the root shadow name (xt_{root}_{name}); the suffix
        // match is only a pre-filter, the unwound root identity decides.
        var candidateQuery = RtEntityQueryOptions.Create();
        candidateQuery.FieldEndsWith(nameof(RtUser.NormalizedUserName), rootShadowUserName.ToUpperInvariant());
        var candidatesResult = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, candidateQuery);
        await session.CommitTransactionAsync();

        // A shadow user never has a password; one that does is a local account wearing the name.
        var candidates = new List<(RtUser User, int ChainLength)>();
        foreach (var candidate in candidatesResult.Items.Where(u => string.IsNullOrEmpty(u.PasswordHash)))
        {
            var chain = await shadowUserChainResolver.GetSourceChainAsync(candidate.UserName);
            if (chain.Count > 0 && CrossTenantShadowUserName.IsSameIdentity(chain[^1], rootIdentity))
            {
                candidates.Add((candidate, chain.Count));
            }
        }

        var equivalentUser = candidates
            // Deterministic pick among legacy duplicates: the shortest chain (closest to the home
            // identity), then the name.
            .OrderBy(c => c.ChainLength)
            .ThenBy(c => c.User.UserName, StringComparer.OrdinalIgnoreCase)
            .Select(c => c.User)
            .FirstOrDefault();

        if (equivalentUser != null)
        {
            logger.LogInformation(
                "Cross-tenant login as '{RequestedUserName}' reuses existing shadow user '{UserName}' of the same identity '{RootTenant}/{RootUser}'",
                crossTenantUserName, equivalentUser.UserName, rootIdentity.TenantId, rootIdentity.UserName);
        }

        return equivalentUser;
    }

    /// <inheritdoc />
    public async Task<bool> IsExplicitlyProvisionedAsync(CrossTenantAuthResult crossTenantResult)
    {
        if (await externalTenantUserMappingStore.FindBySourceUserAsync(
                crossTenantResult.SourceTenantId, crossTenantResult.SourceUserId) != null)
        {
            return true;
        }

        // A mapping created for any identity of the source's chain (e.g. the home user, while the
        // login arrives through the parent's shadow user) is the same explicit grant.
        var identities = new List<(string SourceTenantId, string SourceUserName)>
        {
            (crossTenantResult.SourceTenantId, crossTenantResult.SourceUserName)
        };
        identities.AddRange(await shadowUserChainResolver.GetSourceChainAsync(crossTenantResult.SourceUserName));

        var mappings = await externalTenantUserMappingStore.FindBySourceUserNamesAsync(identities);
        return mappings.Count > 0;
    }

    /// <inheritdoc />
    public async Task<RtUser?> FindOrCreateCrossTenantUserAsync(
        CrossTenantAuthResult crossTenantResult, string childTenantId)
    {
        // Check if a mapping already exists
        var mapping = await externalTenantUserMappingStore.FindBySourceUserAsync(
            crossTenantResult.SourceTenantId, crossTenantResult.SourceUserId);

        // Generate a unique username for the cross-tenant user
        var crossTenantUserName = CrossTenantShadowUserName.Build(
            crossTenantResult.SourceTenantId, crossTenantResult.SourceUserName);

        var existingUser = await FindCrossTenantUserAsync(crossTenantResult);
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
                        existingUser.UserName,
                        string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                }
            }

            // Roles are NOT synced onto the user: mapping and group roles are resolved at token time
            // (IGroupRoleResolver.ResolveEffectiveUserRoleIdsAsync, AB#5708).
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
            await externalTenantUserMappingStore.StoreAsync(new RtExternalTenantUserMapping
            {
                RtId = OctoObjectId.GenerateNewId(),
                SourceTenantId = crossTenantResult.SourceTenantId,
                SourceUserId = crossTenantResult.SourceUserId,
                SourceUserName = crossTenantResult.SourceUserName
            });
        }

        logger.LogInformation(
            "Created cross-tenant user '{UserName}' in tenant '{TenantId}' for source user '{SourceUser}' from tenant '{SourceTenant}'",
            crossTenantUserName, childTenantId, crossTenantResult.SourceUserName,
            crossTenantResult.SourceTenantId);

        return user;
    }
}
