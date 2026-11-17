using System.Security.Claims;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.AdminProvisioning;

/// <summary>What an admin provisioning operation did, or why it did nothing.</summary>
internal enum AdminProvisioningStatus
{
    /// <summary>A mapping was created.</summary>
    Created,

    /// <summary><c>ProvisionCurrentUser</c>: an existing mapping was repaired.</summary>
    Repaired,

    /// <summary><c>ProvisionCurrentUser</c>: an existing mapping already granted access; nothing changed.</summary>
    AlreadyProvisioned,

    /// <summary>The mapping was deleted.</summary>
    Removed,

    /// <summary>The target tenant does not exist.</summary>
    TenantNotFound,

    /// <summary>The source tenant is not a registry ancestor of the target.</summary>
    SourceTenantNotAncestor,

    /// <summary>A mapping for the source user exists in the target tenant.</summary>
    AlreadyExists,

    /// <summary>The caller is a cross-tenant shadow user whose home identity could not be resolved.</summary>
    HomeIdentityUnresolved,

    /// <summary>The target tenant is still initializing.</summary>
    TenantInitializing,

    /// <summary>The target tenant has no mapping with the id.</summary>
    MappingNotFound
}

/// <summary>Result of an admin provisioning operation.</summary>
/// <param name="Status">What happened.</param>
/// <param name="Mapping">The mapping as stored (created, repaired, confirmed or removed), or the existing one for <see cref="AdminProvisioningStatus.AlreadyExists" />.</param>
/// <param name="GroupNames">Target-tenant groups the mapping is a member of.</param>
internal sealed record AdminProvisioningOutcome(
    AdminProvisioningStatus Status,
    RtExternalTenantUserMapping? Mapping = null,
    IReadOnlyList<string>? GroupNames = null)
{
    /// <summary>The value of <c>X-Provisioning-Outcome</c> / the method result outcome for <c>ProvisionCurrentUser</c>.</summary>
    public string? ProvisioningOutcome => Status switch
    {
        AdminProvisioningStatus.Created => AdminProvisioningService.OutcomeCreated,
        AdminProvisioningStatus.Repaired => AdminProvisioningService.OutcomeRepaired,
        AdminProvisioningStatus.AlreadyProvisioned => AdminProvisioningService.OutcomeAlreadyProvisioned,
        _ => null
    };

    public static AdminProvisioningOutcome Of(AdminProvisioningStatus status) => new(status);
}

/// <summary>
///     Cross-tenant admin provisioning: writes mappings of source-tenant users into a target tenant through the system
///     context. The <c>ExternalTenantUserMapping.ProvisionAdmin*</c>, <c>ProvisionCurrentUser</c> and
///     <c>RemoveAdminProvisioning</c> method handlers call it; <c>AdminProvisioningController</c> is their REST facade. The
///     callers check the caller's role and the target-tenant scope (<c>AdminProvisioningTargetScope</c>) before.
/// </summary>
internal sealed class AdminProvisioningService(
    ISystemContext systemContext,
    IDynamicAuthSchemeService dynamicAuthSchemeService,
    ICrossTenantShadowUserChainResolver shadowUserChainResolver,
    ICrossTenantAncestryGuard ancestryGuard,
    ICrossTenantGrantAuditRecorder grantAudit,
    ILogger<AdminProvisioningService> logger)
{
    /// <summary>No mapping existed; one with all target roles and TenantOwners membership was created.</summary>
    public const string OutcomeCreated = "created";

    /// <summary>A mapping existed but granted no effective role (or carried a wrong user name); it was fixed.</summary>
    public const string OutcomeRepaired = "repaired";

    /// <summary>A mapping with an effective role and the right user name existed; nothing was changed.</summary>
    public const string OutcomeAlreadyProvisioned = "already-provisioned";

    /// <summary>Attempts and back-off of <see cref="ProvisionCurrentUserAsync" /> while the target tenant initializes.</summary>
    internal static int MaxRetries { get; set; } = 10;

    internal static int RetryDelayMs { get; set; } = 1000;

    /// <summary>
    /// Records a grant event in the target tenant T and the source tenant S. Called after the commit; never fails the
    /// operation.
    /// </summary>
    private async Task AuditGrantAsync(string eventName, string targetTenantId, string callerName,
        RtExternalTenantUserMapping mapping, IReadOnlyList<string> groupNames)
    {
        try
        {
            await grantAudit.RecordGrantAsync(eventName, targetTenantId, callerName, mapping, groupNames.ToList());
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Audit event {EventName} of mapping {MappingId} could not be recorded",
                eventName, mapping.RtId);
        }
    }

    /// <summary>
    /// Creates a mapping in the target tenant with the given roles; a mapping that carries TenantManagement also joins
    /// TenantOwners. Only a registry ancestor of the target is a source; the source becomes the target's login parent.
    /// </summary>
    public async Task<AdminProvisioningOutcome> CreateAsync(string targetTenantId, string sourceTenantId,
        string sourceUserId, string sourceUserName, IReadOnlyList<string>? roleIds, string callerName)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return AdminProvisioningOutcome.Of(AdminProvisioningStatus.TenantNotFound);
        }

        if (!await ancestryGuard.IsTrustedAncestorAsync(targetTenantId, sourceTenantId, "admin provisioning mapping"))
        {
            return AdminProvisioningOutcome.Of(AdminProvisioningStatus.SourceTenantNotAncestor);
        }

        // A mapping is unique per (source tenant, source user): a second one would lock the user out.
        var duplicate = await ExternalTenantUserMappingLookup.FindOldestAsync(
            tenantRepository, sourceTenantId, sourceUserId, logger);
        if (duplicate != null)
        {
            return new AdminProvisioningOutcome(AdminProvisioningStatus.AlreadyExists, duplicate);
        }

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = sourceUserName,
            MappedRoleIds = roleIds != null ? new AttributeStringValueList(roleIds.ToList()) : null
        };

        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();
        await tenantRepository.InsertOneRtEntityAsync(session, mapping);

        // A mapping that carries TenantManagement is an administrator mapping: it joins TenantOwners (which holds every
        // role including SecretManagement) in addition to the roles it was created with.
        var groupNames = new List<string>();
        if (roleIds != null && await ContainsTenantManagementRoleAsync(tenantRepository, session, roleIds))
        {
            var tenantOwnersGroup = await FindTenantOwnersGroupAsync(tenantRepository, session);
            if (tenantOwnersGroup != null)
            {
                await AddToTenantOwnersGroupAsync(tenantRepository, session, tenantOwnersGroup, mapping);
                groupNames.Add(tenantOwnersGroup.GroupName);
            }
        }

        await session.CommitTransactionAsync();

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, targetTenantId, sourceTenantId);

        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantCreated, targetTenantId, callerName, mapping, groupNames);
        return new AdminProvisioningOutcome(AdminProvisioningStatus.Created, mapping, groupNames);
    }

    /// <summary>
    /// Creates a mapping in the target tenant as a member of the given target-tenant groups (ids that are no group of the
    /// target are skipped). Same source rule as <see cref="CreateAsync" />.
    /// </summary>
    public async Task<AdminProvisioningOutcome> CreateWithGroupsAsync(string targetTenantId, string sourceTenantId,
        string sourceUserId, string sourceUserName, IReadOnlyList<string>? groupIds, string callerName)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return AdminProvisioningOutcome.Of(AdminProvisioningStatus.TenantNotFound);
        }

        if (!await ancestryGuard.IsTrustedAncestorAsync(targetTenantId, sourceTenantId, "admin provisioning mapping"))
        {
            return AdminProvisioningOutcome.Of(AdminProvisioningStatus.SourceTenantNotAncestor);
        }

        var duplicate = await ExternalTenantUserMappingLookup.FindOldestAsync(
            tenantRepository, sourceTenantId, sourceUserId, logger);
        if (duplicate != null)
        {
            return new AdminProvisioningOutcome(AdminProvisioningStatus.AlreadyExists, duplicate);
        }

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = sourceUserName,
            MappedRoleIds = null
        };

        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();
        await tenantRepository.InsertOneRtEntityAsync(session, mapping);

        var groupNames = new List<string>();
        if (groupIds is { Count: > 0 })
        {
            var updates = new List<AssociationUpdateInfo>();
            foreach (var groupId in groupIds)
            {
                // An id that is no object id cannot name a group; it is skipped like an unknown group.
                if (!OctoObjectId.TryParse(groupId, out var groupRtId))
                {
                    continue;
                }

                var group = await tenantRepository.GetRtEntityByRtIdAsync<RtGroup>(session, groupRtId);
                if (group == null)
                {
                    continue;
                }

                updates.Add(AssociationUpdateInfo.CreateInsert(
                    group.ToRtEntityId(),
                    mapping.ToRtEntityId(),
                    IdentityAssociationConstants.GroupMemberId));
                groupNames.Add(group.GroupName);
            }

            if (updates.Count > 0)
            {
                await tenantRepository.ApplyChangesAsync(session, updates, new OperationResult());
            }
        }

        await session.CommitTransactionAsync();

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, targetTenantId, sourceTenantId);

        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantCreated, targetTenantId, callerName, mapping, groupNames);
        return new AdminProvisioningOutcome(AdminProvisioningStatus.Created, mapping, groupNames);
    }

    /// <summary>
    /// Provisions the caller (<paramref name="userId" /> of <paramref name="callerTenantId" />) in the target tenant with all
    /// roles. Idempotent and self-healing: <see cref="AdminProvisioningStatus.Created" /> for a new mapping,
    /// <see cref="AdminProvisioningStatus.Repaired" /> when a mapping existed but granted no effective role or carried a
    /// wrong user name, <see cref="AdminProvisioningStatus.AlreadyProvisioned" /> when nothing needed to change.
    /// <para>
    /// When the caller is a cross-tenant shadow user (<c>xt_…</c>), the mapping is written for its <b>home identity</b> -
    /// the root of its <c>xt_</c> chain - because the token exchange accepts a home mapping for every path of the same
    /// person. A shadow user whose home identity cannot be resolved is refused
    /// (<see cref="AdminProvisioningStatus.HomeIdentityUnresolved" />) and nothing is written (fail closed).
    /// </para>
    /// </summary>
    /// <param name="claimUserName">The user name the caller's token carries, if any; the stored name wins.</param>
    public async Task<(AdminProvisioningOutcome Outcome, string? CallerUserName)> ProvisionCurrentUserAsync(
        string targetTenantId, string userId, string callerTenantId, string? claimUserName, string callerName,
        CancellationToken cancellationToken = default)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return (AdminProvisioningOutcome.Of(AdminProvisioningStatus.TenantNotFound), null);
        }

        // Access tokens typically don't include profile claims (name, preferred_username); the user stored in the
        // source tenant is the fallback.
        var storedUserName = await FindUserNameByIdAsync(callerTenantId, userId);
        var userName = !string.IsNullOrEmpty(claimUserName) ? claimUserName : storedUserName ?? userId;
        var tenantId = callerTenantId;

        // A shadow user (session scoped to an intermediate tenant) is provisioned as its home identity. The stored name is
        // authoritative; the claim only counts when the user cannot be read.
        var callerUserName = storedUserName ?? claimUserName;
        if (CrossTenantShadowUserName.IsShadowUserName(callerUserName))
        {
            var home = await ResolveHomeIdentityAsync(callerUserName!);
            if (home == null || string.Equals(home.Value.TenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning(
                    "ProvisionCurrentUser refused: caller '{CallerUserName}' of tenant '{CallerTenantId}' is a cross-tenant shadow user whose home identity could not be resolved (target tenant '{TargetTenantId}')",
                    callerUserName, tenantId, targetTenantId);
                return (AdminProvisioningOutcome.Of(AdminProvisioningStatus.HomeIdentityUnresolved), callerUserName);
            }

            logger.LogInformation(
                "ProvisionCurrentUser: caller '{CallerUserName}' of tenant '{CallerTenantId}' is a cross-tenant shadow user; provisioning its home identity '{HomeUserName}' ({HomeUserId}) of tenant '{HomeTenantId}' into tenant '{TargetTenantId}'",
                callerUserName, tenantId, home.Value.UserName, home.Value.UserId, home.Value.TenantId, targetTenantId);

            tenantId = home.Value.TenantId;
            userId = home.Value.UserId;
            userName = home.Value.UserName;
        }

        // The target tenant may still be initializing (CK model import + default-configuration seeding run
        // asynchronously after tenant creation). Retry with backoff while the tenant is not ready, and once the budget is
        // exhausted answer TenantInitializing - not a generic failure.
        for (var attempt = 1; attempt <= MaxRetries; attempt++)
        {
            try
            {
                return (await ProvisionCurrentUserInternal(tenantRepository, userId, userName, tenantId, callerName),
                    callerUserName);
            }
            catch (Exception ex) when (IsTenantInitializing(ex))
            {
                logger.LogInformation(ex,
                    "Target tenant '{TargetTenantId}' is not ready yet (attempt {Attempt}/{MaxRetries}).",
                    targetTenantId, attempt, MaxRetries);
                if (attempt >= MaxRetries)
                {
                    break;
                }

                await Task.Delay(RetryDelayMs * attempt, cancellationToken);
            }
        }

        return (AdminProvisioningOutcome.Of(AdminProvisioningStatus.TenantInitializing), callerUserName);
    }

    /// <summary>Deletes a mapping in the target tenant.</summary>
    public async Task<AdminProvisioningOutcome> DeleteAsync(string targetTenantId, OctoObjectId mappingRtId,
        string callerName)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return AdminProvisioningOutcome.Of(AdminProvisioningStatus.TenantNotFound);
        }

        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existing = await tenantRepository
            .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mappingRtId);
        if (existing == null)
        {
            await session.CommitTransactionAsync();
            return AdminProvisioningOutcome.Of(AdminProvisioningStatus.MappingNotFound);
        }

        // Group names before the removal: the mapping's GroupMember edges go with it. Read in a session of their own and
        // guarded: a failing read never breaks or aborts the deletion.
        var groupNames = await GroupNamesForAuditAsync(tenantRepository, existing);
        await tenantRepository
            .DeleteOneRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mappingRtId, DeleteOptions.Erase);
        await session.CommitTransactionAsync();

        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantRemoved, targetTenantId, callerName, existing, groupNames);
        return new AdminProvisioningOutcome(AdminProvisioningStatus.Removed, existing, groupNames);
    }

    /// <summary>The user name stored for <paramref name="userId" /> in <paramref name="tenantId" />, or <c>null</c>.</summary>
    private async Task<string?> FindUserNameByIdAsync(string tenantId, string userId)
    {
        if (!OctoObjectId.TryParse(userId, out var userRtId))
        {
            return null;
        }

        var repository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        if (repository == null)
        {
            return null;
        }

        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var user = await repository.GetRtEntityByRtIdAsync<RtUser>(session, userRtId);
        await session.CommitTransactionAsync();
        return user?.UserName;
    }

    /// <summary>
    /// Unwinds a shadow user name (<c>xt_{tenant}_{user}</c>, possibly nested) against the tenant
    /// registry to the root identity and looks that user up in its tenant. Returns <c>null</c> — fail closed —
    /// when the chain is ambiguous or broken (the last tier is still a shadow name), the home tenant is not
    /// registered or the home user does not exist.
    /// </summary>
    private async Task<(string TenantId, string UserId, string UserName)?> ResolveHomeIdentityAsync(
        string shadowUserName)
    {
        var chain = await shadowUserChainResolver.GetSourceChainAsync(shadowUserName);
        if (chain.Count == 0)
        {
            return null;
        }

        var (homeTenantId, homeUserName) = chain[^1];
        if (CrossTenantShadowUserName.IsShadowUserName(homeUserName))
        {
            return null;
        }

        var repository = await systemContext.TryFindTenantRepositoryAsync(homeTenantId);
        if (repository == null)
        {
            return null;
        }

        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtUser>(session,
            RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtUser.NormalizedUserName), homeUserName.ToUpperInvariant()));
        await session.CommitTransactionAsync();

        var homeUser = result.Items.FirstOrDefault();
        return homeUser == null
            ? null
            : (homeTenantId, homeUser.RtId.ToString(), homeUser.UserName ?? homeUserName);
    }

    /// <summary>
    /// Returns true when an exception indicates the target tenant is still being provisioned and the
    /// provisioning should be retried: an unpopulated CK cache (<see cref="CkCacheException"/>), missing
    /// default configuration / roles (<see cref="TenantNotReadyException"/>), or a freshly-provisioned
    /// identity database whose first read fails with MongoDB errorCode 13 ("requires authentication")
    /// because the tenant database user is not yet in place. Walks the inner-exception chain so
    /// wrapped failures are matched too.
    /// </summary>
    private static bool IsTenantInitializing(Exception exception)
    {
        for (Exception? ex = exception; ex is not null; ex = ex.InnerException)
        {
            if (ex is CkCacheException or TenantNotReadyException)
            {
                return true;
            }

            if (ex is MongoDB.Driver.MongoCommandException { Code: 13 })
            {
                return true;
            }
        }

        return false;
    }

    private async Task<AdminProvisioningOutcome> ProvisionCurrentUserInternal(
        ITenantRepository tenantRepository, string userId, string userName, string tenantId, string callerName)
    {
        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        // Check if mapping already exists
        var existingQuery = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), tenantId)
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), userId);
        var existingResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, existingQuery);

        var existingMapping = ExternalTenantUserMappingLookup.PickOldest(
            existingResult.Items.ToList(), tenantId, userId, logger);

        // Get all roles from target tenant. Needed to fill a new mapping and to judge whether an existing
        // one grants anything. If no roles exist yet, the default configuration has not been initialized —
        // throw to trigger a retry in the caller.
        var roleResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        if (!roleResult.Items.Any())
        {
            await session.CommitTransactionAsync();
            throw new TenantNotReadyException("No roles found in target tenant — default configuration not yet initialized.");
        }

        var roleIds = roleResult.Items.Select(r => r.RtId.ToString()).ToList();

        if (existingMapping != null)
        {
            return await RepairOrConfirmExistingMappingAsync(
                tenantRepository, session, existingMapping, roleIds, userId, userName, tenantId, callerName);
        }

        // An administrator is a TenantOwners member, not the holder of direct roles; the group carries
        // every role. A tenant without the group, or with a group that carries no role, keeps the role list.
        var tenantOwnersGroup = await FindTenantOwnersGroupAsync(tenantRepository, session);
        var groupCarriesRoles = tenantOwnersGroup != null
                                && await GroupHasAllRolesAsync(tenantRepository, session, tenantOwnersGroup, roleIds);
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = tenantId,
            SourceUserId = userId,
            SourceUserName = userName,
            MappedRoleIds = groupCarriesRoles ? null : new AttributeStringValueList(roleIds)
        };

        await tenantRepository.InsertOneRtEntityAsync(session, mapping);

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, tenantRepository.TenantId, tenantId);

        // Add mapping as member of TenantOwners group
        var groupNames = new List<string>();
        if (tenantOwnersGroup != null)
        {
            await AddToTenantOwnersGroupAsync(tenantRepository, session, tenantOwnersGroup, mapping);
            groupNames.Add(tenantOwnersGroup.GroupName);
        }

        await session.CommitTransactionAsync();

        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantCreated, tenantRepository.TenantId, callerName, mapping,
            groupNames);
        return new AdminProvisioningOutcome(AdminProvisioningStatus.Created, mapping, groupNames);
    }

    /// <summary>
    /// A mapping for (source tenant, source user) already exists. It only counts as provisioned when
    /// it grants an effective role and carries the user name the role lookup keys on: the token exchange
    /// resolves roles by source tenant + source user NAME, this lookup finds the mapping by user ID. A bare
    /// mapping (stored by the cross-tenant login before anybody provisioned the user), one that lists no
    /// existing role and is in no group with roles, or one with a wrong name leaves the user denied — it is
    /// repaired here instead of being reported as provisioned. A mapping that already grants a role is never
    /// widened: only a wrong name is corrected.
    /// </summary>
    private async Task<AdminProvisioningOutcome> RepairOrConfirmExistingMappingAsync(
        ITenantRepository tenantRepository, IOctoSession session, RtExternalTenantUserMapping mapping,
        IReadOnlyList<string> targetRoleIds, string userId, string userName, string tenantId, string callerName)
    {
        var targetRoleIdSet = targetRoleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Groups the mapping is a member of (names for the response, roles to judge the grant).
        var associations = await tenantRepository.GetRtAssociationsAsync(
            session,
            mapping.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Inbound,
                roleId: IdentityAssociationConstants.GroupMemberId));

        var groupNames = new List<string>();
        var groupRoleIds = new List<string>();
        var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
        foreach (var assoc in associations.Items.Where(a => a.OriginCkTypeId == groupCkTypeId))
        {
            var group = await tenantRepository.GetRtEntityByRtIdAsync<RtGroup>(session, assoc.OriginRtId);
            if (group == null)
            {
                continue;
            }

            groupNames.Add(group.GroupName);

            var groupRoleAssociations = await tenantRepository.GetRtAssociationsAsync(
                session,
                group.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(
                    GraphDirections.Outbound,
                    roleId: IdentityAssociationConstants.AssignedRoleId));
            groupRoleIds.AddRange(groupRoleAssociations.Items.Select(a => a.TargetRtId.ToString()));
        }

        var grantsRole = (mapping.MappedRoleIds?.Any(targetRoleIdSet.Contains) ?? false)
                         || groupRoleIds.Any(targetRoleIdSet.Contains);

        // The user name only replaces a stored one when it is a real name; the user id is the fallback
        // used when the name could not be determined and must not overwrite a good name.
        var nameNeedsCorrection = !string.IsNullOrEmpty(userName)
                                  && !string.Equals(userName, userId, StringComparison.Ordinal)
                                  && !string.Equals(mapping.SourceUserName, userName, StringComparison.OrdinalIgnoreCase);

        if (grantsRole && !nameNeedsCorrection)
        {
            await session.CommitTransactionAsync();
            return new AdminProvisioningOutcome(AdminProvisioningStatus.AlreadyProvisioned, mapping, groupNames);
        }

        // Repair through the TenantOwners group when it carries roles; the role list is the
        // fallback for a tenant without a usable group.
        var repairGroup = !grantsRole ? await FindTenantOwnersGroupAsync(tenantRepository, session) : null;
        var repairViaGroup = repairGroup != null && await GroupHasAllRolesAsync(tenantRepository, session, repairGroup, targetRoleIds);
        if (!grantsRole && !repairViaGroup)
        {
            mapping.MappedRoleIds = new AttributeStringValueList(targetRoleIds.ToList());
        }

        if (nameNeedsCorrection)
        {
            mapping.SourceUserName = userName;
        }

        await tenantRepository.ReplaceOneRtEntityByIdAsync(session, mapping.RtId, mapping);

        if (repairGroup != null && !grantsRole
            && !groupNames.Contains(CommonConstants.TenantOwnersGroup, StringComparer.OrdinalIgnoreCase))
        {
            await AddToTenantOwnersGroupAsync(tenantRepository, session, repairGroup, mapping);
            groupNames.Add(repairGroup.GroupName);
        }

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, tenantRepository.TenantId, tenantId);

        await session.CommitTransactionAsync();

        logger.LogInformation(
            "Repaired external tenant user mapping '{MappingRtId}' of user '{SourceUserId}' from tenant '{SourceTenantId}' in tenant '{TargetTenantId}' (rolesFilled={RolesFilled}, nameCorrected={NameCorrected})",
            mapping.RtId, userId, tenantId, tenantRepository.TenantId, !grantsRole, nameNeedsCorrection);

        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantChanged, tenantRepository.TenantId, callerName, mapping,
            groupNames);
        return new AdminProvisioningOutcome(AdminProvisioningStatus.Repaired, mapping, groupNames);
    }

    /// <summary>True when one of <paramref name="roleIds"/> is the TenantManagement role of the target tenant.</summary>
    private static async Task<bool> ContainsTenantManagementRoleAsync(
        ITenantRepository tenantRepository, IOctoSession session, IEnumerable<string> roleIds)
    {
        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(
            session,
            RtEntityQueryOptions.Create().FieldEquals(
                nameof(RtRole.NormalizedName), CommonConstants.TenantManagementRole.ToUpperInvariant()));
        var tenantManagement = roles.Items.FirstOrDefault();
        return tenantManagement != null
               && roleIds.Contains(tenantManagement.RtId.ToString(), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True when the group has an <c>AssignedRole</c> edge to every one of <paramref name="roleIds"/>: only then the
    /// group alone replaces the direct role list of a mapping.
    /// </summary>
    private static async Task<bool> GroupHasAllRolesAsync(
        ITenantRepository tenantRepository, IOctoSession session, RtGroup group, IEnumerable<string> roleIds)
    {
        var edges = await tenantRepository.GetRtAssociationsAsync(
            session,
            group.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        var held = edges.Items.Select(e => e.TargetRtId.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return roleIds.All(held.Contains);
    }

    /// <summary>
    /// The mapping's target-tenant group names for an audit event, read in a session of their own (outside the caller's
    /// transaction). A read error yields none and never fails the request (like
    /// <c>ExternalTenantUserMappingsController.GroupNamesForAuditAsync</c>).
    /// </summary>
    private async Task<IReadOnlyList<string>> GroupNamesForAuditAsync(ITenantRepository tenantRepository,
        RtExternalTenantUserMapping mapping)
    {
        try
        {
            using var auditSession = await tenantRepository.GetSessionAsync();
            return await GroupNamesOfMappingAsync(tenantRepository, auditSession, mapping);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Group names of mapping {MappingId} could not be read for the audit event",
                mapping.RtId);
            return [];
        }
    }

    /// <summary>Names of the target-tenant groups the mapping is a member of (for audit events).</summary>
    private static async Task<IReadOnlyList<string>> GroupNamesOfMappingAsync(
        ITenantRepository tenantRepository, IOctoSession session, RtExternalTenantUserMapping mapping)
    {
        var associations = await tenantRepository.GetRtAssociationsAsync(
            session,
            mapping.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Inbound,
                roleId: IdentityAssociationConstants.GroupMemberId));
        var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
        var names = new List<string>();
        foreach (var assoc in associations.Items.Where(a => a.OriginCkTypeId == groupCkTypeId))
        {
            var group = await tenantRepository.GetRtEntityByRtIdAsync<RtGroup>(session, assoc.OriginRtId);
            if (group != null)
            {
                names.Add(group.GroupName);
            }
        }

        return names;
    }

    /// <summary>The TenantOwners group of the target tenant, or <c>null</c> when the tenant has none.</summary>
    private static async Task<RtGroup?> FindTenantOwnersGroupAsync(
        ITenantRepository tenantRepository, IOctoSession session)
    {
        var groupQuery = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName),
                CommonConstants.TenantOwnersGroup.ToUpperInvariant());
        var groupResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtGroup>(session, groupQuery);
        return groupResult.Items.FirstOrDefault();
    }

    /// <summary>Adds the mapping to the given TenantOwners group as a member.</summary>
    private static async Task AddToTenantOwnersGroupAsync(
        ITenantRepository tenantRepository, IOctoSession session, RtGroup tenantOwnersGroup,
        RtExternalTenantUserMapping mapping)
    {
        var updates = new List<AssociationUpdateInfo>
        {
            AssociationUpdateInfo.CreateInsert(
                tenantOwnersGroup.ToRtEntityId(),
                mapping.ToRtEntityId(),
                IdentityAssociationConstants.GroupMemberId)
        };
        var opResult = new OperationResult();
        await tenantRepository.ApplyChangesAsync(session, updates, opResult);
    }

    /// <summary>
    /// Ensures the OctoTenantIdentityProvider exists in the target tenant, pointing to the source tenant.
    /// This enables "LOGIN VIA {sourceTenant}" on the target tenant's login page.
    /// </summary>
    private async Task EnsureOctoTenantIdentityProviderAsync(
        ITenantRepository tenantRepository, string targetTenantId, string sourceTenantId)
    {
        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existingResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(session, RtEntityQueryOptions.Create());

        if (existingResult.Items.Any(p =>
                string.Equals(p.ParentTenantId, sourceTenantId, StringComparison.OrdinalIgnoreCase)))
        {
            await session.CommitTransactionAsync();
            return;
        }

        var provider = new RtOctoTenantIdentityProvider
        {
            Name = $"ParentTenant_{sourceTenantId}",
            IsEnabled = true,
            DisplayName = $"Login via {sourceTenantId}",
            ParentTenantId = sourceTenantId
        };

        await tenantRepository.InsertOneRtEntityAsync(session, provider);
        await session.CommitTransactionAsync();

        // Refresh auth schemes so the new provider is immediately available
        await dynamicAuthSchemeService.ConfigureAsync(targetTenantId);

        logger.LogInformation(
            "Created OctoTenantIdentityProvider in tenant '{TargetTenantId}' pointing to '{SourceTenantId}'",
            targetTenantId, sourceTenantId);
    }
}

/// <summary>
/// Thrown when the target tenant's default configuration (roles, groups) is not yet initialized.
/// </summary>
internal class TenantNotReadyException(string message) : Exception(message);
