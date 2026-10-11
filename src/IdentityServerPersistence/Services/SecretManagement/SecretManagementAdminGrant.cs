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

    public List<string> GrantedGroupIds { get; set; } = [];

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
    IReadOnlyList<string> GrantedGroupIds,
    IReadOnlyList<string> GrantedUserIds);

/// <summary>
///     AB#5544: one-time, additive grant of the <c>SecretManagement</c> role to the existing administrators of a
///     tenant — every group and user that holds both <c>AdminPanelManagement</c> and <c>TenantManagement</c>,
///     plus the <c>TenantOwners</c> group. See <see cref="SecretManagementGrantPlanner"/> for the rule.
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
    /// <summary>Stable rtId of the blueprint-seeded TenantOwners group.</summary>
    internal static readonly OctoObjectId TenantOwnersGroupRtId = new("660000000000000000000040");

    public static async Task<SecretManagementAdminGrantResult> EnsureAsync(
        ITenantContext tenantContext, ILogger logger)
    {
        using (var readSession = await tenantContext.GetAdminSessionAsync())
        {
            var marker = await tenantContext.GetConfigurationAsync<SecretManagementAdminGrantMarker>(
                readSession, IdentityServiceConstants.SecretManagementAdminGrantKey, defaultValue: null);
            if (marker != null)
            {
                return new SecretManagementAdminGrantResult(SecretManagementAdminGrantStatus.AlreadyDone, [], []);
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
                return new SecretManagementAdminGrantResult(SecretManagementAdminGrantStatus.RoleMissing, [], []);
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
                input, adminPanelRoleId, tenantManagementRoleId, secretManagementRoleId.ToString(),
                TenantOwnersGroupRtId.ToString());

            using var writeSession = await tenantRepository.GetSessionAsync();
            writeSession.StartTransaction();
            var roleEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), secretManagementRoleId);
            var updates = new List<AssociationUpdateInfo>();
            updates.AddRange(plan.GroupIds.Select(g => AssociationUpdateInfo.CreateInsert(
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), new OctoObjectId(g)),
                roleEntityId, IdentityAssociationConstants.AssignedRoleId)));
            updates.AddRange(plan.UserIds.Select(u => AssociationUpdateInfo.CreateInsert(
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtUser>(), new OctoObjectId(u)),
                roleEntityId, IdentityAssociationConstants.AssignedRoleId)));
            if (updates.Count > 0)
            {
                var opResult = new OperationResult();
                await tenantRepository.ApplyChangesAsync(writeSession, updates, opResult);
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
                    GrantedGroupIds = plan.GroupIds.ToList(),
                    GrantedUserIds = plan.UserIds.ToList()
                });
        }

        logger.LogInformation(
            "SecretManagement granted to existing administrators of tenant '{TenantId}': {GroupCount} groups " +
            "({GroupIds}), {UserCount} users ({UserIds}); recorded as done",
            tenantContext.TenantId, plan.GroupIds.Count, string.Join(", ", plan.GroupIds),
            plan.UserIds.Count, string.Join(", ", plan.UserIds));

        return new SecretManagementAdminGrantResult(
            SecretManagementAdminGrantStatus.Completed, plan.GroupIds, plan.UserIds);
    }

    private static async Task<SecretManagementGrantInput> ReadRoleGraphAsync(
        ITenantRepository tenantRepository, IOctoSession session)
    {
        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        var userRoles = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        var users = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create());
        foreach (var user in users.Items)
        {
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

        return new SecretManagementGrantInput(userRoles, groupRoles, groupChildren, groupMembers);

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
