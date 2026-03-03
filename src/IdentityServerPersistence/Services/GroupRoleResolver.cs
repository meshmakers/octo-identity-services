using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence.Services;

/// <summary>
/// Resolves the effective role IDs for a user by traversing group memberships
/// via CK associations, including nested groups with circular reference protection.
/// </summary>
public interface IGroupRoleResolver
{
    /// <summary>
    /// Resolves all role IDs inherited from groups for the given user.
    /// </summary>
    Task<IReadOnlySet<string>> ResolveEffectiveRoleIdsAsync(string userRtId);

    /// <summary>
    /// Resolves all role IDs inherited from groups for the given external tenant user mapping.
    /// </summary>
    Task<IReadOnlySet<string>> ResolveEffectiveRoleIdsForExternalUserAsync(string externalUserMappingRtId);
}

internal class GroupRoleResolver(IGroupStore groupStore) : IGroupRoleResolver
{
    private const int MaxDepth = 10;

    public async Task<IReadOnlySet<string>> ResolveEffectiveRoleIdsAsync(string userRtId)
    {
        // Find all groups where this user is a member (via inbound GroupMember associations)
        var allGroups = (await groupStore.GetAllAsync()).ToList();

        var directGroupIds = new List<OctoObjectId>();
        foreach (var group in allGroups)
        {
            var memberUserIds = await groupStore.GetMemberUserIdsAsync(group.RtId);
            if (memberUserIds.Contains(userRtId))
            {
                directGroupIds.Add(group.RtId);
            }
        }

        return await CollectRoleIdsAsync(directGroupIds);
    }

    public async Task<IReadOnlySet<string>> ResolveEffectiveRoleIdsForExternalUserAsync(
        string externalUserMappingRtId)
    {
        var allGroups = (await groupStore.GetAllAsync()).ToList();

        var directGroupIds = new List<OctoObjectId>();
        foreach (var group in allGroups)
        {
            var memberExtUserIds = await groupStore.GetMemberExternalUserIdsAsync(group.RtId);
            if (memberExtUserIds.Contains(externalUserMappingRtId))
            {
                directGroupIds.Add(group.RtId);
            }
        }

        return await CollectRoleIdsAsync(directGroupIds);
    }

    private async Task<IReadOnlySet<string>> CollectRoleIdsAsync(List<OctoObjectId> startGroupIds)
    {
        var roleIds = new HashSet<string>();
        var visited = new HashSet<OctoObjectId>();

        foreach (var groupId in startGroupIds)
        {
            await CollectRoleIdsRecursiveAsync(groupId, roleIds, visited, 0);
        }

        return roleIds;
    }

    private async Task CollectRoleIdsRecursiveAsync(
        OctoObjectId groupId,
        HashSet<string> roleIds,
        HashSet<OctoObjectId> visited,
        int depth)
    {
        if (depth >= MaxDepth || !visited.Add(groupId))
        {
            return;
        }

        // Get roles assigned to this group via AssignedRole associations
        var groupRoleIds = await groupStore.GetRoleIdsAsync(groupId);
        foreach (var roleId in groupRoleIds)
        {
            roleIds.Add(roleId);
        }

        // Get child groups via ChildGroup associations and recurse
        var childGroupIds = await groupStore.GetMemberGroupIdsAsync(groupId);
        foreach (var childGroupId in childGroupIds)
        {
            await CollectRoleIdsRecursiveAsync(
                new OctoObjectId(childGroupId), roleIds, visited, depth + 1);
        }
    }
}
