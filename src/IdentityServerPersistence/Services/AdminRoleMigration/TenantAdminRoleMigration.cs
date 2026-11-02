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

namespace IdentityServerPersistence.Services.AdminRoleMigration;

/// <summary>Outcome of one <see cref="TenantAdminRoleMigration.EnsureAsync"/> call.</summary>
internal enum AdminRoleMigrationStatus
{
    /// <summary>Mode Off: nothing was read.</summary>
    Skipped,

    /// <summary>DryRun: the plan was logged, nothing written.</summary>
    DryRun,

    /// <summary>Apply: the plan was written (possibly empty).</summary>
    Applied,

    /// <summary>
    ///     The tenant has no TenantOwners group, or the group does not carry TenantManagement and UserManagement
    ///     itself, or a role is missing: nothing is migrated, because the move would remove access.
    /// </summary>
    NotApplicable
}

internal sealed record AdminRoleMigrationResult(
    AdminRoleMigrationStatus Status,
    IReadOnlyList<AdminRoleMigrationSubjectPlan> Plan);

/// <summary>
///     AB#8165 (decision Gerald 2026-11-02: "alle admins müssen wir auf tenantowner umstellen"): moves the existing
///     admins of a tenant from directly assigned roles to <c>TenantOwners</c> membership. Switchable per cluster
///     with <c>IdentityApiAuthorization:AdminRoleMigration</c> = Off (default) / DryRun / Apply, because it changes
///     role data. See <see cref="AdminRoleMigrationPlanner"/> for the rule.
/// </summary>
/// <remarks>
///     Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> after the SecretManagement grants (so
///     TenantOwners already carries <c>SecretManagement</c>). It has no run-once marker: Off/DryRun/Apply is the
///     operator's switch, and a run is idempotent — a second Apply plans nothing. Users, cross-tenant shadow users
///     (<c>xt_</c>) and external tenant user mappings are migrated; clients and groups never. Only roles that
///     TenantOwners carries are removed, and only from subjects that are members of the group afterwards, so the
///     effective roles of a migrated subject do not shrink. Logs ids only.
/// </remarks>
internal static class TenantAdminRoleMigration
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    public static async Task<AdminRoleMigrationResult> EnsureAsync(
        ITenantContext tenantContext, AdminRoleMigrationMode mode, ILogger logger)
    {
        if (mode == AdminRoleMigrationMode.Off)
        {
            return new AdminRoleMigrationResult(AdminRoleMigrationStatus.Skipped, []);
        }

        var gate = Locks.GetOrAdd(tenantContext.TenantId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await EnsureCoreAsync(tenantContext, mode, logger).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<AdminRoleMigrationResult> EnsureCoreAsync(
        ITenantContext tenantContext, AdminRoleMigrationMode mode, ILogger logger)
    {
        var tenantId = tenantContext.TenantId;
        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        var mappingCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtExternalTenantUserMapping>();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(roles.Items, tenantId, logger);
        var roleNames = roleIndex.ToDictionary(kv => kv.Value.ToString(), kv => kv.Key, StringComparer.Ordinal);

        var groupQuery = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName), CommonConstants.TenantOwnersGroup.ToUpperInvariant());
        var group = (await tenantRepository.GetRtEntitiesByTypeAsync<RtGroup>(session, groupQuery)).Items.FirstOrDefault();

        if (group == null
            || !roleIndex.TryGetValue(CommonConstants.TenantManagementRole, out var tenantManagementRoleId)
            || !roleIndex.TryGetValue(CommonConstants.UserManagementRole, out var userManagementRoleId))
        {
            await session.CommitTransactionAsync();
            logger.LogWarning(
                "AdminRoleMigration {Mode} skipped in tenant '{TenantId}': no {Group} group or no TenantManagement/" +
                "UserManagement role", mode, tenantId, CommonConstants.TenantOwnersGroup);
            return new AdminRoleMigrationResult(AdminRoleMigrationStatus.NotApplicable, []);
        }

        var ownerRoleIds = await ReadTargetsAsync(group.ToRtEntityId(), IdentityAssociationConstants.AssignedRoleId, roleCkTypeId);
        if (!ownerRoleIds.Contains(tenantManagementRoleId.ToString())
            || !ownerRoleIds.Contains(userManagementRoleId.ToString()))
        {
            await session.CommitTransactionAsync();
            logger.LogWarning(
                "AdminRoleMigration {Mode} skipped in tenant '{TenantId}': {Group} does not carry TenantManagement and " +
                "UserManagement itself, moving admins would remove their access", mode, tenantId,
                CommonConstants.TenantOwnersGroup);
            return new AdminRoleMigrationResult(AdminRoleMigrationStatus.NotApplicable, []);
        }

        var memberIds = new HashSet<string>(StringComparer.Ordinal);
        memberIds.UnionWith(await ReadTargetsAsync(group.ToRtEntityId(), IdentityAssociationConstants.GroupMemberId, userCkTypeId));
        memberIds.UnionWith(await ReadTargetsAsync(group.ToRtEntityId(), IdentityAssociationConstants.GroupMemberId, mappingCkTypeId));

        var subjects = new List<AdminRoleMigrationSubject>();
        var users = await tenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create());
        foreach (var user in users.Items)
        {
            subjects.Add(new AdminRoleMigrationSubject(
                AdminRoleMigrationSubjectKind.User, user.RtId.ToString(),
                await ReadTargetsAsync(user.ToRtEntityId(), IdentityAssociationConstants.AssignedRoleId, roleCkTypeId)));
        }

        var mappings = await tenantRepository.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(
            session, RtEntityQueryOptions.Create());
        foreach (var mapping in mappings.Items)
        {
            subjects.Add(new AdminRoleMigrationSubject(
                AdminRoleMigrationSubjectKind.Mapping, mapping.RtId.ToString(),
                (mapping.MappedRoleIds ?? Enumerable.Empty<string>()).ToHashSet(StringComparer.Ordinal)));
        }

        var plan = AdminRoleMigrationPlanner.Plan(
            subjects, ownerRoleIds, memberIds, tenantManagementRoleId.ToString(), userManagementRoleId.ToString());

        var joinIds = plan.Where(p => p.JoinGroup).Select(p => $"{p.Kind}:{p.RtId}").ToList();
        var removals = plan.SelectMany(p => p.RemoveRoleIds.Select(r =>
            $"{p.Kind}:{p.RtId}:{(roleNames.TryGetValue(r, out var n) ? n : r)}")).ToList();

        if (mode == AdminRoleMigrationMode.DryRun || plan.Count == 0)
        {
            await session.CommitTransactionAsync();
            logger.LogInformation(
                "AdminRoleMigration {Mode} tenant '{TenantId}': {JoinCount} would join {Group} ({JoinIds}); " +
                "{RemoveCount} direct roles would be removed ({Removals})",
                mode, tenantId, joinIds.Count, CommonConstants.TenantOwnersGroup, string.Join(", ", joinIds),
                removals.Count, string.Join(", ", removals));
            return new AdminRoleMigrationResult(
                mode == AdminRoleMigrationMode.DryRun ? AdminRoleMigrationStatus.DryRun : AdminRoleMigrationStatus.Applied,
                plan);
        }

        var updates = new List<AssociationUpdateInfo>();
        var mappingUpdates = new List<(RtExternalTenantUserMapping Mapping, List<string> RoleIds)>();
        foreach (var p in plan)
        {
            var subjectCkTypeId = p.Kind == AdminRoleMigrationSubjectKind.User ? userCkTypeId : mappingCkTypeId;
            var subjectEntityId = new RtEntityId(subjectCkTypeId, new OctoObjectId(p.RtId));
            if (p.JoinGroup)
            {
                updates.Add(AssociationUpdateInfo.CreateInsert(
                    group.ToRtEntityId(), subjectEntityId, IdentityAssociationConstants.GroupMemberId));
            }

            if (p.Kind == AdminRoleMigrationSubjectKind.User)
            {
                foreach (var roleId in p.RemoveRoleIds)
                {
                    updates.Add(AssociationUpdateInfo.CreateDelete(
                        subjectEntityId, new RtEntityId(roleCkTypeId, new OctoObjectId(roleId)),
                        IdentityAssociationConstants.AssignedRoleId));
                }
            }
            else if (p.RemoveRoleIds.Count > 0)
            {
                var mapping = mappings.Items.First(m => m.RtId.ToString() == p.RtId);
                var remaining = (mapping.MappedRoleIds ?? Enumerable.Empty<string>())
                    .Where(r => !p.RemoveRoleIds.Contains(r, StringComparer.Ordinal))
                    .ToList();
                mappingUpdates.Add((mapping, remaining));
            }
        }

        if (updates.Count > 0)
        {
            var opResult = new OperationResult();
            await tenantRepository.ApplyChangesAsync(session, updates, opResult);
            if (opResult.HasErrors || opResult.HasFatalErrors)
            {
                // Not committed: the next setup plans the same moves again.
                throw new InvalidOperationException(
                    $"AdminRoleMigration failed in tenant '{tenantId}': {string.Join("; ", opResult.GetMessages())}");
            }
        }

        foreach (var (mapping, remaining) in mappingUpdates)
        {
            mapping.MappedRoleIds = new AttributeStringValueList(remaining);
            await tenantRepository.ReplaceOneRtEntityByIdAsync(session, mapping.RtId, mapping);
        }

        await session.CommitTransactionAsync();

        logger.LogInformation(
            "AdminRoleMigration Apply tenant '{TenantId}': {JoinCount} joined {Group} ({JoinIds}); " +
            "{RemoveCount} direct roles removed ({Removals})",
            tenantId, joinIds.Count, CommonConstants.TenantOwnersGroup, string.Join(", ", joinIds),
            removals.Count, string.Join(", ", removals));
        return new AdminRoleMigrationResult(AdminRoleMigrationStatus.Applied, plan);

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
