using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services;

public class CrossTenantAuthenticationService(
    ITenantRegistry tenantRegistry,
    IOctoIdentityProviderStore identityProviderStore,
    IPasswordHasher<RtUser> passwordHasher,
    ICrossTenantShadowUserChainResolver shadowUserChainResolver,
    ICrossTenantAncestryGuard ancestryGuard,
    ISourceTenantGrantPolicy grantPolicy,
    IOptions<IdentityOptions> identityOptions,
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

        // Walk up the tenant hierarchy. AB#8339: every tenant the walk reaches must be a registry ancestor of the
        // child; the providers are only the child's opt-in, they do not decide who its ancestors are.
        var registryAncestors = await ancestryGuard.GetRegistryAncestorsAsync(childTenantId);
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
                childTenantId, registryAncestors, parentTenantId, username, password, visited, 0);
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
        // Verify the source tenant is an ancestor of the target tenant by walking up from the target tenant — or, for a
        // source that is no registry ancestor, that T holds a grant for this user and S permits T right now (AB#8343).
        var isAncestor = await IsAncestorTenantAsync(targetTenantId, sourceTenantId);
        if (!isAncestor &&
            await EvaluateSiblingGrantAsync(targetTenantId, sourceTenantId, sourceUserId) != SiblingGrant.Admitted)
        {
            logger.LogWarning(
                "Tenant switch denied: '{SourceTenantId}' is not an ancestor of '{TargetTenantId}' and holds no permitted grant there",
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

        // AB#7855: a locked-out or not-allowed ("disabled") identity crosses no tenant boundary, whatever session or
        // token it still holds — checked on every crossing, for the source user and each tier of its xt_ chain.
        if (await FindSignInBlockAsync(user) is { } block)
        {
            logger.LogWarning(
                "Tenant switch denied: user '{UserId}' of tenant '{TenantId}' may not sign in ({Reason})",
                sourceUserId, sourceTenantId, block);
            return null;
        }

        return new CrossTenantAuthResult
        {
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = user.UserName ?? string.Empty,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            SourceUserRequiresSecondFactor = await RequiresSecondFactorAsync(user)
        };
    }

    /// <summary>
    ///     AB#7855: why <paramref name="user" /> may not cross a tenant boundary, or <c>null</c> when it may. Blocked are a
    ///     locked-out identity and one the sign-in rules refuse (<see cref="IdentityOptions.SignIn" />: confirmed e-mail /
    ///     phone / account — the same rules <c>SignInManager.CanSignInAsync</c> applies on the token endpoint; RtUser has
    ///     no separate "disabled" flag). A shadow user (<c>xt_…</c>) is judged with every tier of its name chain: locking
    ///     the home user stops its shadows too. A tier the resolver does not unwind, whose user no longer exists or whose
    ///     tenant cannot be read adds nothing (an unreadable tier already requires the second factor).
    /// </summary>
    private async Task<string?> FindSignInBlockAsync(RtUser user)
    {
        if (GetSignInBlock(user) is { } own)
        {
            return own;
        }

        foreach (var (tenantId, userName) in await shadowUserChainResolver.GetSourceChainAsync(user.UserName))
        {
            // A tier that cannot be read blocks nothing here: the second-factor rule already fails closed for it
            // (RequiresSecondFactorAsync), and refusing every crossing on a transient read error would lock out users
            // that are not locked.
            var (tierUser, _) = await LookupUserByNameInTenantAsync(tenantId, userName);
            if (tierUser != null && GetSignInBlock(tierUser) is { } tier)
            {
                return $"chain tier '{userName}' in tenant '{tenantId}': {tier}";
            }
        }

        return null;
    }

    private string? GetSignInBlock(RtUser user)
        => SourceUserSignInBlock.Get(user, identityOptions.Value.SignIn, DateTimeOffset.UtcNow);

    private async Task<CrossTenantAuthResult?> TryAuthenticateInHierarchyAsync(
        string childTenantId, IReadOnlyList<string> registryAncestors, string tenantId, string username,
        string password, HashSet<string> visited, int depth)
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

        // AB#8339: a tenant that is no registry ancestor of the child is neither asked for the password (no guessing and
        // no lockout counting of a stranger's users) nor walked beyond under Enforce.
        if (!ancestryGuard.IsTrustedAncestor(childTenantId, registryAncestors, tenantId, "cross-tenant login"))
        {
            return null;
        }

        // Try to find and validate the user in this tenant
        var user = await FindUserByNameInTenantAsync(tenantId, username);
        if (user != null)
        {
            if (IsLockedOut(user))
            {
                // AB#7854: a locked-out identity is not even verified — no guessing while locked, also not through
                // a child tenant. The walk goes on to the parents, as for a wrong password.
                logger.LogInformation(
                    "Cross-tenant auth: user '{UserName}' in tenant '{TenantId}' is locked out",
                    username, tenantId);
            }
            else if (passwordHasher.VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, password)
                     != PasswordVerificationResult.Failed)
            {
                logger.LogInformation(
                    "Cross-tenant auth succeeded: user '{UserName}' found in tenant '{TenantId}'",
                    username, tenantId);

                var requiresSecondFactor = await RequiresSecondFactorAsync(user);
                if (!user.TwoFactorEnabled)
                {
                    // Same rule as SignInManager: a correct password resets the counter only when no second factor
                    // follows; otherwise the verified second factor resets it.
                    await ResetAccessFailuresAsync(tenantId, user);
                }

                return new CrossTenantAuthResult
                {
                    SourceTenantId = tenantId,
                    SourceUserId = user.RtId.ToString(),
                    SourceUserName = user.UserName ?? username,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email,
                    SourceUserRequiresSecondFactor = requiresSecondFactor
                };
            }
            else
            {
                // AB#7854: a wrong password counts against the identity it was tried on — the parent-tenant user —
                // exactly like a wrong password on that tenant's own login.
                await RecordAccessFailureAsync(tenantId, user);
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
                childTenantId, registryAncestors, provider.ParentTenantId, username, password, visited, depth + 1);
            if (result != null)
            {
                return result;
            }
        }

        return null;
    }

    private static bool IsLockedOut(RtUser user)
        => SourceUserSignInBlock.IsLockedOut(user, DateTimeOffset.UtcNow);

    private async Task RecordAccessFailureAsync(string tenantId, RtUser user)
    {
        try
        {
            var repository = await tenantRegistry.TryGetRepositoryAsync(tenantId);
            if (repository == null)
            {
                return;
            }

            var lockout = identityOptions.Value.Lockout;
            var (_, lockedOut) = await OctoUserStore.RecordAccessFailureAsync(repository, user.RtId,
                lockout.MaxFailedAccessAttempts, lockout.DefaultLockoutTimeSpan);
            if (lockedOut)
            {
                logger.LogWarning(
                    "Cross-tenant auth: user '{UserName}' in tenant '{TenantId}' is locked out after failed attempts",
                    user.UserName, tenantId);
            }
        }
        catch (Exception ex)
        {
            // The attempt is refused either way; a counting failure is logged, never turned into a success.
            logger.LogWarning(ex,
                "Cross-tenant auth: failed attempt of user '{UserName}' in tenant '{TenantId}' could not be counted",
                user.UserName, tenantId);
        }
    }

    private async Task ResetAccessFailuresAsync(string tenantId, RtUser user)
    {
        if (user.AccessFailedCount == 0)
        {
            return;
        }

        try
        {
            var repository = await tenantRegistry.TryGetRepositoryAsync(tenantId);
            if (repository != null)
            {
                await OctoUserStore.ResetAccessFailedCountAsync(repository, user.RtId);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Cross-tenant auth: failure count of user '{UserName}' in tenant '{TenantId}' could not be reset",
                user.UserName, tenantId);
        }
    }

    /// <summary>
    ///     AB#7804: the source user needs a second factor when it has 2FA enabled itself, or — for a shadow user
    ///     (<c>xt_…</c>) — when any identity of its name chain has. A shadow user never has 2FA of its own (it signs in
    ///     through its home tenant), so judging only the immediate user would let every hop beyond the first skip the
    ///     home user's second factor.
    /// </summary>
    /// <remarks>
    ///     AB#7861 (review finding 6): every gap in the chain fails closed — the second factor is then required. A gap is
    ///     a tier whose tenant cannot be read, a tier whose user no longer exists (root user renamed or deleted), and a
    ///     chain the resolver cannot unwind to a local user (deleted tenant, ambiguous tenant prefix): the identity whose
    ///     second factor would decide is unknown, so the safe answer is "required". Before, such tiers added nothing.
    /// </remarks>
    private async Task<bool> RequiresSecondFactorAsync(RtUser user)
    {
        if (user.TwoFactorEnabled)
        {
            return true;
        }

        if (!CrossTenantShadowUserName.IsShadowUserName(user.UserName))
        {
            return false;
        }

        var chain = await shadowUserChainResolver.GetSourceChainAsync(user.UserName);
        if (chain.Count == 0 || CrossTenantShadowUserName.IsShadowUserName(chain[^1].UserName))
        {
            logger.LogWarning(
                "Second-factor requirement of '{UserName}' assumed: its shadow-user chain cannot be unwound to a home user",
                user.UserName);
            return true;
        }

        foreach (var (tenantId, userName) in chain)
        {
            var (tierUser, failed) = await LookupUserByNameInTenantAsync(tenantId, userName);
            if (failed || tierUser == null)
            {
                logger.LogWarning(
                    "Second-factor requirement of '{UserName}' assumed: chain tier '{TierUserName}' in tenant '{TenantId}' {Reason}",
                    user.UserName, userName, tenantId, failed ? "could not be read" : "does not exist");
                return true;
            }

            if (tierUser.TwoFactorEnabled)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    ///     Whether <paramref name="ancestorTenantId" /> may act as an ancestor of <paramref name="childTenantId" /> for a
    ///     tenant switch (token exchange, AB#4338). Two conditions: the child opted in — its enabled
    ///     <c>OctoTenantIdentityProvider</c>s reach the ancestor (<see cref="IsReachableThroughProvidersAsync" />) — and the
    ///     tenant registry confirms the ancestry (AB#8339, <see cref="ICrossTenantAncestryGuard" />). Before AB#8339 the
    ///     providers alone decided, and they are written by the child's own administrator: a provider pointing at any
    ///     tenant made that tenant an "ancestor". Under <see cref="CrossTenantAncestryMode.Warn" /> a provider-only
    ///     ancestor still passes and is logged.
    /// </summary>
    private async Task<bool> IsAncestorTenantAsync(string childTenantId, string ancestorTenantId)
    {
        if (!await IsReachableThroughProvidersAsync(childTenantId, ancestorTenantId))
        {
            return false;
        }

        return await ancestryGuard.IsTrustedAncestorAsync(childTenantId, ancestorTenantId, "tenant switch");
    }

    /// <inheritdoc />
    public async Task<SiblingGrantRefusal> GetSiblingGrantRefusalAsync(string targetTenantId, string sourceTenantId,
        string sourceUserId)
        => await EvaluateSiblingGrantAsync(targetTenantId, sourceTenantId, sourceUserId, classifyRefusal: true) switch
        {
            SiblingGrant.NotPermitted => SiblingGrantRefusal.NotPermitted,
            SiblingGrant.NoEffectiveRole => SiblingGrantRefusal.NoEffectiveRole,
            SiblingGrant.Removed => SiblingGrantRefusal.Removed,
            _ => SiblingGrantRefusal.None
        };

    /// <summary>State of a grant for a source tenant that is no registry ancestor of the target (AB#8343, AB#8344).</summary>
    private enum SiblingGrant
    {
        /// <summary>No grant applies: S is a registry ancestor, T holds no mapping, or the state cannot be read.</summary>
        None,

        /// <summary>T holds a mapping for the user, but S does not permit T.</summary>
        NotPermitted,

        /// <summary>T holds a mapping for the user and S permits T, but the mapping grants no role that exists in T.</summary>
        NoEffectiveRole,

        /// <summary>T holds no mapping for the user, but the user's <c>xt_</c> shadow user exists in T.</summary>
        Removed,

        /// <summary>T holds a mapping with at least one effective role for the user and S permits T.</summary>
        Admitted
    }

    /// <summary>
    ///     AB#8343: a source tenant S that is no registry ancestor of T reaches T only through an explicit grant — a mapping
    ///     for (S, user) stored in <b>T</b> — and only while S permits T (<see cref="ISourceTenantGrantPolicy" />, asked at
    ///     every exchange, so withdrawing T from S's allow-list stops the next exchange). AB#8344: and only while that
    ///     mapping itself grants a role — its direct <c>MappedRoleIds</c> or the roles of the groups it is a member of. Roles
    ///     or groups attached directly to the <c>xt_</c> shadow user do not keep a sibling user in T once the mapping grants
    ///     nothing: the mapping is the grant. A registry ancestor never takes this path: its rules (provider opt-in,
    ///     AB#8339) stay as they are. Fails closed: an unreadable registry, T or policy admits nothing.
    /// </summary>
    /// <param name="classifyRefusal">
    ///     Also tell a removed grant (no mapping, but the user's <c>xt_</c> shadow user exists in T) from a user T never
    ///     granted. Only the refusal answer needs it; the gate itself refuses both alike.
    /// </param>
    private async Task<SiblingGrant> EvaluateSiblingGrantAsync(string targetTenantId, string sourceTenantId,
        string sourceUserId, bool classifyRefusal = false)
    {
        try
        {
            var registryAncestors = await ancestryGuard.GetRegistryAncestorsAsync(targetTenantId);
            if (registryAncestors.Contains(sourceTenantId, StringComparer.OrdinalIgnoreCase))
            {
                return SiblingGrant.None;
            }

            var targetRepository = await tenantRegistry.TryGetRepositoryAsync(targetTenantId);
            if (targetRepository == null)
            {
                LogUnregisteredTenant(targetTenantId);
                return SiblingGrant.None;
            }

            var mapping = await ExternalTenantUserMappingLookup.FindOldestAsync(targetRepository, sourceTenantId,
                sourceUserId, logger);
            if (mapping == null)
            {
                return classifyRefusal &&
                       await HasShadowUserInTargetAsync(targetRepository, sourceTenantId, sourceUserId)
                    ? SiblingGrant.Removed
                    : SiblingGrant.None;
            }

            if (!await grantPolicy.IsPermittedAsync(sourceTenantId, targetTenantId))
            {
                logger.LogWarning(
                    "Tenant switch denied: '{SourceTenantId}' does not permit '{TargetTenantId}'; grant {MappingId} is not honoured (AB#8343)",
                    sourceTenantId, targetTenantId, mapping.RtId);
                return SiblingGrant.NotPermitted;
            }

            if (!await GrantsAnyRoleAsync(targetRepository, mapping))
            {
                logger.LogWarning(
                    "Tenant switch denied: grant {MappingId} of '{SourceTenantId}' in '{TargetTenantId}' has no effective role left (AB#8344)",
                    mapping.RtId, sourceTenantId, targetTenantId);
                return SiblingGrant.NoEffectiveRole;
            }

            return SiblingGrant.Admitted;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Tenant switch denied: the grant of '{SourceTenantId}' in '{TargetTenantId}' could not be checked (AB#8343)",
                sourceTenantId, targetTenantId);
            return SiblingGrant.None;
        }
    }

    /// <summary>
    ///     AB#8344: whether <paramref name="mapping" /> grants at least one role that exists in T — a direct
    ///     <c>MappedRoleIds</c> entry or a role of a group the mapping is a member of (nested groups included, the same
    ///     traversal as token issuance, <see cref="GroupRoleResolver" />). A role id of a deleted role grants nothing, as in
    ///     <c>OctoUserStore.GetRolesAsync</c>.
    /// </summary>
    private async Task<bool> GrantsAnyRoleAsync(ITenantRepository targetRepository, RtExternalTenantUserMapping mapping)
    {
        var resolver = new FixedTenantRepositoryResolver(targetRepository);
        var groupRoleResolver = new GroupRoleResolver(new GroupStore(resolver),
            new ExternalTenantUserMappingStore(resolver), shadowUserChainResolver);

        var roleIds = new HashSet<string>(await groupRoleResolver.ResolveEffectiveRoleIdsAsync(mapping.RtId.ToString()));
        if (mapping.MappedRoleIds != null)
        {
            roleIds.UnionWith(mapping.MappedRoleIds);
        }

        using var session = await targetRepository.GetSessionAsync();
        session.StartTransaction();
        var found = false;
        foreach (var roleId in roleIds)
        {
            if (OctoObjectId.TryParse(roleId, out var roleRtId) &&
                await targetRepository.GetRtEntityByRtIdAsync<RtRole>(session, roleRtId) != null)
            {
                found = true;
                break;
            }
        }

        await session.CommitTransactionAsync();
        return found;
    }

    /// <summary>
    ///     AB#8344: whether T holds the <c>xt_{S}_{user}</c> shadow user of the source user — the trace of an earlier
    ///     admitted exchange. Only used to word the refusal; never admits anything.
    /// </summary>
    private async Task<bool> HasShadowUserInTargetAsync(ITenantRepository targetRepository, string sourceTenantId,
        string sourceUserId)
    {
        var sourceUser = await FindUserByIdInTenantAsync(sourceTenantId, sourceUserId);
        if (string.IsNullOrEmpty(sourceUser?.UserName))
        {
            return false;
        }

        var shadowUserName = CrossTenantShadowUserName.Build(sourceTenantId, sourceUser.UserName);
        using var session = await targetRepository.GetSessionAsync();
        session.StartTransaction();
        var result = await targetRepository.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtUser.NormalizedUserName), shadowUserName.ToUpperInvariant()));
        await session.CommitTransactionAsync();
        return result.Items.Any();
    }

    /// <summary>
    ///     Breadth-first search over the identity-provider graph for <paramref name="ancestorTenantId" />.
    /// </summary>
    /// <remarks>
    ///     A tenant may have SEVERAL enabled <c>OctoTenantIdentityProvider</c>s, so ancestry is a graph,
    ///     not a chain. Descending into the first provider that yields an unvisited parent — and thereby
    ///     abandoning its siblings on the same level — made the answer depend on store enumeration order
    ///     and denied legitimate access (AB#4960): a tenant whose stale provider happened to be returned
    ///     first hid its real parent, so every gate built on this check failed closed.
    ///     <see cref="MaxHierarchyDepth" /> bounds the number of LEVELS walked, and <c>visited</c> keeps a
    ///     cycle from looping.
    /// </remarks>
    private async Task<bool> IsReachableThroughProvidersAsync(string childTenantId, string ancestorTenantId)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { childTenantId };
        var currentLevel = new List<string> { childTenantId };

        for (var depth = 0; depth < MaxHierarchyDepth && currentLevel.Count > 0; depth++)
        {
            var nextLevel = new List<string>();

            foreach (var tenantId in currentLevel)
            {
                var providers = await GetOctoTenantProvidersInTenantAsync(tenantId);

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
                        nextLevel.Add(provider.ParentTenantId);
                    }
                }
            }

            currentLevel = nextLevel;
        }

        return false;
    }

    /// <inheritdoc />
    public async Task<string?> FindUserIdByNameInTenantAsync(string tenantId, string userName)
    {
        var user = await FindUserByNameInTenantAsync(tenantId, userName);
        return user?.RtId.ToString();
    }

    /// <inheritdoc />
    public async Task<string?> FindUserNameByIdInTenantAsync(string tenantId, string userId)
    {
        var user = await FindUserByIdInTenantAsync(tenantId, userId);
        return user?.UserName;
    }

    private async Task<RtUser?> FindUserByNameInTenantAsync(string tenantId, string username)
        => (await LookupUserByNameInTenantAsync(tenantId, username)).User;

    /// <summary>
    ///     User lookup that tells "not found" (<c>Failed=false, User=null</c>) apart from "could not be read"
    ///     (<c>Failed=true</c>: tenant missing from the registry, query error). Callers that must fail closed on an
    ///     unreadable tenant (the second-factor requirement, AB#7804) need the difference.
    /// </summary>
    private async Task<(RtUser? User, bool Failed)> LookupUserByNameInTenantAsync(string tenantId, string username)
    {
        try
        {
            var tenantRepository = await tenantRegistry.TryGetRepositoryAsync(tenantId);
            if (tenantRepository == null)
            {
                LogUnregisteredTenant(tenantId);
                return (null, true);
            }

            using var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var normalizedUserName = username.ToUpperInvariant();
            var queryOptions = RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtUser.NormalizedUserName), normalizedUserName);

            var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, queryOptions);
            await session.CommitTransactionAsync();

            return (result.Items.SingleOrDefault(), false);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to query user '{UserName}' in tenant '{TenantId}'",
                username, tenantId);
            return (null, true);
        }
    }

    private async Task<RtUser?> FindUserByIdInTenantAsync(string tenantId, string userId)
    {
        try
        {
            var tenantRepository = await tenantRegistry.TryGetRepositoryAsync(tenantId);
            if (tenantRepository == null)
            {
                LogUnregisteredTenant(tenantId);
                return null;
            }

            using var session = await tenantRepository.GetSessionAsync();
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
            var tenantRepository = await tenantRegistry.TryGetRepositoryAsync(tenantId);
            if (tenantRepository == null)
            {
                LogUnregisteredTenant(tenantId);
                return [];
            }

            using var session = await tenantRepository.GetSessionAsync();
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

    /// <summary>
    ///     Fail closed: a tenant that is not in the registry has no users and no identity providers, so it
    ///     can neither authenticate anybody nor serve as an ancestor for a tenant switch.
    /// </summary>
    private void LogUnregisteredTenant(string tenantId)
        => logger.LogWarning("Cross-tenant lookup refused: tenant '{TenantId}' is not registered", tenantId);
}
