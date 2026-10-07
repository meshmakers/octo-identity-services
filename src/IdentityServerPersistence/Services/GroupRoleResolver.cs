using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence.Services;

/// <summary>
/// Resolves the effective role IDs for a subject (user or client) by traversing group
/// memberships via CK associations, including nested groups with circular reference protection.
/// </summary>
public interface IGroupRoleResolver
{
    /// <summary>
    /// Resolves all role IDs inherited from groups for the given subject. The subject may be a
    /// user or a client RtId — both are linked to groups via the same GroupMember association.
    /// </summary>
    Task<IReadOnlySet<string>> ResolveEffectiveRoleIdsAsync(string subjectRtId);

    /// <summary>
    /// Resolves all role IDs a user receives through groups and cross-tenant user mappings — every
    /// role except the user's direct <c>AssignedRole</c> edges (AB#5708):
    /// <list type="bullet">
    ///     <item>groups the user is a member of;</item>
    ///     <item>for a cross-tenant shadow user (<c>xt_…</c>): every <c>ExternalTenantUserMapping</c> of
    ///         this tenant whose source identity is a tier of the user's name chain contributes its
    ///         <c>MappedRoleIds</c> and the roles of the groups the mapping is a member of (e.g.
    ///         <c>TenantOwners</c>).</item>
    /// </list>
    /// Evaluated on every call (token issuance, refresh, role checks) — never materialised on the
    /// user — so a role a blueprint adds to a group later is effective on the next token, and a removed
    /// membership or mapping takes its roles away with it.
    /// </summary>
    /// <param name="userRtId">The local user's RtId.</param>
    /// <param name="userName">The local user's name; only shadow user names unwind to mappings.</param>
    Task<IReadOnlySet<string>> ResolveEffectiveUserRoleIdsAsync(string userRtId, string? userName);
}

internal class GroupRoleResolver(
    IGroupStore groupStore,
    IExternalTenantUserMappingStore externalTenantUserMappingStore,
    ICrossTenantShadowUserChainResolver shadowUserChainResolver) : IGroupRoleResolver
{
    private const int MaxDepth = 10;

    public Task<IReadOnlySet<string>> ResolveEffectiveRoleIdsAsync(string subjectRtId)
        => ResolveGroupRoleIdsAsync(new HashSet<string> { subjectRtId });

    public async Task<IReadOnlySet<string>> ResolveEffectiveUserRoleIdsAsync(string userRtId, string? userName)
    {
        var subjectIds = new HashSet<string> { userRtId };
        var mappedRoleIds = new HashSet<string>();

        // Registry-aware unwinding: a tenant id with an underscore must not be misread as a nested chain.
        var sourceChain = await shadowUserChainResolver.GetSourceChainAsync(userName);
        if (sourceChain.Count > 0)
        {
            var mappings = await externalTenantUserMappingStore.FindBySourceUserNamesAsync(sourceChain);
            foreach (var mapping in mappings)
            {
                subjectIds.Add(mapping.RtId.ToString());

                if (mapping.MappedRoleIds == null)
                {
                    continue;
                }

                foreach (var roleId in mapping.MappedRoleIds)
                {
                    // MappedRoleIds is a free string list, not an association: skip anything that
                    // cannot be a role rtId instead of failing token issuance on it.
                    if (OctoObjectId.TryParse(roleId, out _))
                    {
                        mappedRoleIds.Add(roleId);
                    }
                }
            }
        }

        var roleIds = new HashSet<string>(await ResolveGroupRoleIdsAsync(subjectIds));
        roleIds.UnionWith(mappedRoleIds);
        return roleIds;
    }

    private async Task<IReadOnlySet<string>> ResolveGroupRoleIdsAsync(IReadOnlySet<string> subjectRtIds)
    {
        // Find all groups where one of the subjects is a direct member (via GroupMember associations).
        // GetAllMemberSubjectIdsAsync returns members of any CK type (user, client, external
        // mapping), so the same traversal serves user, client and mapping subjects.
        var allGroups = (await groupStore.GetAllAsync()).ToList();

        var directGroupIds = new List<OctoObjectId>();
        foreach (var group in allGroups)
        {
            var memberIds = await groupStore.GetAllMemberSubjectIdsAsync(group.RtId);
            if (memberIds.Any(subjectRtIds.Contains))
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
