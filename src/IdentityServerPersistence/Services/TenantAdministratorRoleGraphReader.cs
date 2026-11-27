using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Reads the role graph of one tenant (users, groups, their roles, members and child groups) for the
///     <see cref="TenantAdministratorRoleGrantPlanner"/>. Cross-tenant shadow users (<c>xt_</c>) are marked excluded.
/// </summary>
internal static class TenantAdministratorRoleGraphReader
{
    public static async Task<TenantAdministratorRoleGraph> ReadAsync(
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

        return new TenantAdministratorRoleGraph(userRoles, groupRoles, groupChildren, groupMembers, excludedUsers);

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
