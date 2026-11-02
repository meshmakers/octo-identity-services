using System.Collections.Concurrent;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SecretManagement;

/// <summary>
///     Marker persisted in the tenant configuration once <see cref="SecretManagementAdminGrant"/> has run for a
///     tenant. Its presence is the run-once gate: an operator who later removes the role from an administrator
///     must not see it come back on the next restart.
/// </summary>
public sealed class SecretManagementAdminGrantMarker
{
    public DateTime CompletedAtUtc { get; set; }

    public List<string> GrantedUserIds { get; set; } = [];
}

/// <summary>Outcome of one <see cref="SecretManagementAdminGrant.EnsureAsync"/> call.</summary>
internal enum SecretManagementAdminGrantStatus
{
    /// <summary>The grants were written (possibly none) and the marker recorded.</summary>
    Completed,

    /// <summary>The marker already existed; nothing was read or written.</summary>
    AlreadyDone,

    /// <summary>The SecretManagement role does not exist (yet); nothing written, no marker — retried next setup.</summary>
    RoleMissing
}

internal sealed record SecretManagementAdminGrantResult(
    SecretManagementAdminGrantStatus Status,
    IReadOnlyList<string> GrantedUserIds);

/// <summary>
///     AB#5544: one-time, additive grant of the <c>SecretManagement</c> role to the existing HUMAN administrators
///     of a tenant — every local user that holds both <c>AdminPanelManagement</c> and <c>TenantManagement</c>.
///     No group, client or cross-tenant shadow user receives it. See <see cref="SecretManagementGrantPlanner"/>.
/// </summary>
/// <remarks>
///     <para>
///         Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> right AFTER the
///         <c>System.Identity.Bootstrap</c> blueprint apply, because the role (660…60, blueprint 1.7.0) has to
///         exist first. That is why this is not an <c>IMigration</c>: the infrastructure migrations run before
///         the blueprint apply.
///     </para>
///     <para>
///         Never removes anything. Only <c>AssignedRole</c> insert edges are written, and only for subjects
///         that do not hold the role yet. The marker
///         (<see cref="IdentityServiceConstants.SecretManagementAdminGrantKey"/>) is written after the edges
///         are committed; a crash in between re-runs the step, which then finds the edges and writes nothing
///         new.
///     </para>
/// </remarks>
internal static class SecretManagementAdminGrant
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    public static async Task<SecretManagementAdminGrantResult> EnsureAsync(
        ITenantContext tenantContext, ILogger logger)
    {
        // Serialises the runs inside this process (setup, tenant update and retry can reach the same tenant at
        // the same moment). Several identity replicas starting at once can still race: the engine does not
        // reject a second identical AssignedRole edge, so each write re-reads the user's edges first, and a
        // duplicate that slips through is harmless (role reads treat the edges as a set).
        var gate = Locks.GetOrAdd(tenantContext.TenantId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await EnsureCoreAsync(tenantContext, logger).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<SecretManagementAdminGrantResult> EnsureCoreAsync(
        ITenantContext tenantContext, ILogger logger)
    {
        using (var readSession = await tenantContext.GetAdminSessionAsync())
        {
            var marker = await tenantContext.GetConfigurationAsync<SecretManagementAdminGrantMarker>(
                readSession, IdentityServiceConstants.SecretManagementAdminGrantKey, defaultValue: null);
            if (marker != null)
            {
                return new SecretManagementAdminGrantResult(SecretManagementAdminGrantStatus.AlreadyDone, []);
            }
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        SecretManagementGrantPlan plan;
        using (var session = await tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
            var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(
                roles.Items, tenantContext.TenantId, logger);

            if (!roleIndex.TryGetValue(CommonConstants.SecretManagementRole, out var secretManagementRoleId))
            {
                await session.CommitTransactionAsync();
                logger.LogWarning(
                    "SecretManagement role not found in tenant '{TenantId}'; the one-time administrator grant " +
                    "is retried on the next tenant setup",
                    tenantContext.TenantId);
                return new SecretManagementAdminGrantResult(SecretManagementAdminGrantStatus.RoleMissing, []);
            }

            // A tenant without one of the admin roles can still have TenantOwners; an unknown role id simply
            // never matches.
            var adminPanelRoleId = roleIndex.TryGetValue(CommonConstants.AdminPanelManagementRole, out var apm)
                ? apm.ToString()
                : "-";
            var tenantManagementRoleId = roleIndex.TryGetValue(CommonConstants.TenantManagementRole, out var tm)
                ? tm.ToString()
                : "-";

            var input = await ReadRoleGraphAsync(tenantRepository, session);
            await session.CommitTransactionAsync();

            plan = SecretManagementGrantPlanner.Plan(
                input, adminPanelRoleId, tenantManagementRoleId, secretManagementRoleId.ToString());

            using var writeSession = await tenantRepository.GetSessionAsync();
            writeSession.StartTransaction();
            var roleEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), secretManagementRoleId);
            var updates = new List<AssociationUpdateInfo>();
            foreach (var userId in plan.UserIds)
            {
                var userEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtUser>(), new OctoObjectId(userId));
                // Re-read right before the insert: another replica may have written the edge since the plan.
                var existing = await tenantRepository.GetRtAssociationsAsync(writeSession, userEntityId,
                    RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                        roleId: IdentityAssociationConstants.AssignedRoleId));
                if (existing.Items.Any(e => e.TargetRtId == secretManagementRoleId))
                {
                    continue;
                }

                updates.Add(AssociationUpdateInfo.CreateInsert(
                    userEntityId, roleEntityId, IdentityAssociationConstants.AssignedRoleId));
            }

            if (updates.Count > 0)
            {
                var opResult = new OperationResult();
                await tenantRepository.ApplyChangesAsync(writeSession, updates, opResult);
                if (opResult.HasErrors || opResult.HasFatalErrors)
                {
                    // Throw before the commit and before the run-once marker: the caller logs it and the
                    // next tenant setup retries (the marker would otherwise claim a grant that failed).
                    throw new InvalidOperationException(
                        $"Failed to grant {CommonConstants.SecretManagementRole} to the existing administrators of " +
                        $"tenant '{tenantContext.TenantId}': {string.Join("; ", opResult.GetMessages())}");
                }
            }

            await writeSession.CommitTransactionAsync();
        }

        using (var markerSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                markerSession,
                IdentityServiceConstants.SecretManagementAdminGrantKey,
                new SecretManagementAdminGrantMarker
                {
                    CompletedAtUtc = DateTime.UtcNow,
                    GrantedUserIds = plan.UserIds.ToList()
                });
        }

        logger.LogInformation(
            "SecretManagement granted to existing human administrators of tenant '{TenantId}': {UserCount} users " +
            "({UserIds}); recorded as done",
            tenantContext.TenantId, plan.UserIds.Count, string.Join(", ", plan.UserIds));

        return new SecretManagementAdminGrantResult(
            SecretManagementAdminGrantStatus.Completed, plan.UserIds);
    }

    private static async Task<SecretManagementGrantInput> ReadRoleGraphAsync(
        ITenantRepository tenantRepository, IOctoSession session)
    {
        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        var userRoles = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        var excludedUsers = new HashSet<string>(StringComparer.Ordinal);
        var users = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create());
        foreach (var user in users.Items)
        {
            if (CrossTenantShadowUserName.IsShadowUserName(user.UserName))
            {
                // Provisioned parent-tenant administrator (AB#5708): not a local human administrator.
                excludedUsers.Add(user.RtId.ToString());
            }

            userRoles[user.RtId.ToString()] =
                await ReadTargetsAsync(user.ToRtEntityId(), IdentityAssociationConstants.AssignedRoleId, roleCkTypeId);
        }

        var groupRoles = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        var groupChildren = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        var groupMembers = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        var groups = await tenantRepository.GetRtEntitiesByTypeAsync<RtGroup>(session, RtEntityQueryOptions.Create());
        foreach (var group in groups.Items)
        {
            var id = group.RtId.ToString();
            var entityId = group.ToRtEntityId();
            groupRoles[id] = await ReadTargetsAsync(entityId, IdentityAssociationConstants.AssignedRoleId, roleCkTypeId);
            groupChildren[id] = await ReadTargetsAsync(entityId, IdentityAssociationConstants.ChildGroupId, groupCkTypeId);
            groupMembers[id] = await ReadTargetsAsync(entityId, IdentityAssociationConstants.GroupMemberId, userCkTypeId);
        }

        return new SecretManagementGrantInput(userRoles, groupRoles, groupChildren, groupMembers, excludedUsers);

        async Task<IReadOnlySet<string>> ReadTargetsAsync(
            RtEntityId origin, RtCkId<CkAssociationRoleId> associationRoleId, RtCkId<CkTypeId> targetCkTypeId)
        {
            var edges = await tenantRepository.GetRtAssociationsAsync(
                session, origin,
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound, roleId: associationRoleId));
            return edges.Items
                .Where(e => e.TargetCkTypeId == targetCkTypeId)
                .Select(e => e.TargetRtId.ToString())
                .ToHashSet(StringComparer.Ordinal);
        }
    }
}
