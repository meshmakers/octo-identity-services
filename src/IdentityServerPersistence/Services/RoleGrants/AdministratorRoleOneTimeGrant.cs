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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.RoleGrants;

/// <summary>
///     Marker persisted in the tenant configuration once a one-time administrator role grant
///     (<see cref="AdministratorRoleOneTimeGrant"/>) has run for a tenant. Its presence is the run-once gate: an operator
///     who later removes the role from an administrator must not see it come back on the next restart.
/// </summary>
public class AdministratorRoleGrantMarker
{
    public DateTime CompletedAtUtc { get; set; }

    public List<string> GrantedUserIds { get; set; } = [];
}

/// <summary>Outcome of one <see cref="AdministratorRoleOneTimeGrant.EnsureAsync{TMarker}"/> call.</summary>
internal enum AdministratorRoleGrantStatus
{
    /// <summary>The grants were written (possibly none) and the marker recorded.</summary>
    Completed,

    /// <summary>The marker already existed; nothing was read or written.</summary>
    AlreadyDone,

    /// <summary>The role does not exist (yet); nothing written, no marker — retried next setup.</summary>
    RoleMissing,

    /// <summary>
    ///     No administrator qualified and the caller asked to wait for one: nothing written, no marker — retried next
    ///     setup.
    /// </summary>
    NoAdministratorYet,

    /// <summary>The grant does not apply to this tenant (e.g. AiBudgetAdmin in a child tenant); nothing read or written.</summary>
    NotApplicable
}

internal sealed record AdministratorRoleGrantResult(
    AdministratorRoleGrantStatus Status,
    IReadOnlyList<string> GrantedUserIds);

/// <summary>
///     One-time, additive grant of a built-in role to the existing HUMAN administrators of a tenant — every local user
///     that holds both <c>AdminPanelManagement</c> and <c>TenantManagement</c> (direct, through groups or mixed). No group,
///     client or cross-tenant shadow user receives it; the edges are direct <c>AssignedRole</c> edges of the users. See
///     <see cref="AdministratorRoleGrantPlanner"/>. Used for <c>SecretManagement</c> (AB#5544, every tenant) and
///     <c>AiBudgetAdmin</c> (AB#8690, system tenant only).
/// </summary>
/// <remarks>
///     <para>
///         Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> right AFTER the
///         <c>System.Identity.Bootstrap</c> blueprint apply, because the role has to exist first. That is why this is
///         not an <c>IMigration</c>: the infrastructure migrations run before the blueprint apply.
///     </para>
///     <para>
///         Never removes anything. Only <c>AssignedRole</c> insert edges are written, and only for subjects that do not
///         hold the role yet. The marker is written after the edges are committed; a crash in between re-runs the
///         step, which then finds the edges and writes nothing new. It writes the edges as the service, not through the
///         role-change guard: the guard decides what a caller may grant, this step is the platform's own bootstrap.
///     </para>
/// </remarks>
internal static class AdministratorRoleOneTimeGrant
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    /// <param name="tenantContext">Tenant to grant in.</param>
    /// <param name="roleName">Name of the built-in role to grant.</param>
    /// <param name="markerKey">Tenant configuration key of the run-once marker.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="waitForAdministrator">
    ///     When <c>true</c>, a run that finds no administrator to grant writes no marker, so a later setup (after the
    ///     first administrator exists) grants it. When <c>false</c>, the marker is written even then.
    /// </param>
    public static async Task<AdministratorRoleGrantResult> EnsureAsync<TMarker>(
        ITenantContext tenantContext, string roleName, string markerKey, ILogger logger,
        bool waitForAdministrator = false)
        where TMarker : AdministratorRoleGrantMarker, new()
    {
        // Serialises the runs inside this process (setup, tenant update and retry can reach the same tenant at
        // the same moment). Several identity replicas starting at once can still race: the engine does not
        // reject a second identical AssignedRole edge, so each write re-reads the user's edges first, and a
        // duplicate that slips through is harmless (role reads treat the edges as a set).
        var gate = Locks.GetOrAdd($"{tenantContext.TenantId}|{markerKey}", _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await EnsureCoreAsync<TMarker>(tenantContext, roleName, markerKey, logger, waitForAdministrator)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<AdministratorRoleGrantResult> EnsureCoreAsync<TMarker>(
        ITenantContext tenantContext, string roleName, string markerKey, ILogger logger, bool waitForAdministrator)
        where TMarker : AdministratorRoleGrantMarker, new()
    {
        using (var readSession = await tenantContext.GetAdminSessionAsync())
        {
            var marker = await tenantContext.GetConfigurationAsync<TMarker>(
                readSession, markerKey, defaultValue: null);
            if (marker != null)
            {
                return new AdministratorRoleGrantResult(AdministratorRoleGrantStatus.AlreadyDone, []);
            }
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        IReadOnlyList<string> plannedUserIds;
        using (var session = await tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
            var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(
                roles.Items, tenantContext.TenantId, logger);

            if (!roleIndex.TryGetValue(roleName, out var targetRoleId))
            {
                await session.CommitTransactionAsync();
                logger.LogWarning(
                    "{RoleName} role not found in tenant '{TenantId}'; the one-time administrator grant " +
                    "is retried on the next tenant setup",
                    roleName, tenantContext.TenantId);
                return new AdministratorRoleGrantResult(AdministratorRoleGrantStatus.RoleMissing, []);
            }

            // A tenant without one of the admin roles can still have TenantOwners; an unknown role id simply
            // never matches.
            var adminPanelRoleId = roleIndex.TryGetValue(CommonConstants.AdminPanelManagementRole, out var apm)
                ? apm.ToString()
                : "-";
            var tenantManagementRoleId = roleIndex.TryGetValue(CommonConstants.TenantManagementRole, out var tm)
                ? tm.ToString()
                : "-";

            var graph = await ReadRoleGraphAsync(tenantRepository, session);
            await session.CommitTransactionAsync();

            plannedUserIds = AdministratorRoleGrantPlanner.Plan(
                graph.UserRoleIds, graph.GroupRoleIds, graph.GroupChildGroupIds, graph.GroupMemberUserIds,
                graph.ExcludedUserIds, adminPanelRoleId, tenantManagementRoleId, targetRoleId.ToString());

            if (plannedUserIds.Count == 0 && waitForAdministrator)
            {
                logger.LogInformation(
                    "No human administrator to grant {RoleName} to in tenant '{TenantId}' yet; retried on the next " +
                    "tenant setup", roleName, tenantContext.TenantId);
                return new AdministratorRoleGrantResult(AdministratorRoleGrantStatus.NoAdministratorYet, []);
            }

            using var writeSession = await tenantRepository.GetSessionAsync();
            writeSession.StartTransaction();
            var roleEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), targetRoleId);
            var updates = new List<AssociationUpdateInfo>();
            foreach (var userId in plannedUserIds)
            {
                var userEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtUser>(), new OctoObjectId(userId));
                // Re-read right before the insert: another replica may have written the edge since the plan.
                var existing = await tenantRepository.GetRtAssociationsAsync(writeSession, userEntityId,
                    RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                        roleId: IdentityAssociationConstants.AssignedRoleId));
                if (existing.Items.Any(e => e.TargetRtId == targetRoleId))
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
                        $"Failed to grant {roleName} to the existing administrators of " +
                        $"tenant '{tenantContext.TenantId}': {string.Join("; ", opResult.GetMessages())}");
                }
            }

            await writeSession.CommitTransactionAsync();
        }

        using (var markerSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                markerSession,
                markerKey,
                new TMarker
                {
                    CompletedAtUtc = DateTime.UtcNow,
                    GrantedUserIds = plannedUserIds.ToList()
                });
        }

        logger.LogInformation(
            "{RoleName} granted to existing human administrators of tenant '{TenantId}': {UserCount} users " +
            "({UserIds}); recorded as done",
            roleName, tenantContext.TenantId, plannedUserIds.Count, string.Join(", ", plannedUserIds));

        return new AdministratorRoleGrantResult(AdministratorRoleGrantStatus.Completed, plannedUserIds);
    }

    private sealed record RoleGraph(
        IReadOnlyDictionary<string, IReadOnlySet<string>> UserRoleIds,
        IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoleIds,
        IReadOnlyDictionary<string, IReadOnlySet<string>> GroupChildGroupIds,
        IReadOnlyDictionary<string, IReadOnlySet<string>> GroupMemberUserIds,
        IReadOnlySet<string> ExcludedUserIds);

    private static async Task<RoleGraph> ReadRoleGraphAsync(ITenantRepository tenantRepository, IOctoSession session)
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

        return new RoleGraph(userRoles, groupRoles, groupChildren, groupMembers, excludedUsers);

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
