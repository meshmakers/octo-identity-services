using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;

/// <summary>
///     An in-memory copy of everything that decides who effectively holds a role (AB#7927): groups with their roles, child
///     groups and members, external tenant user mappings with their roles, the direct holders of the administrator role and
///     the mappings that serve each cross-tenant shadow user. A change is applied to a <see cref="Clone" /> and the holders
///     are compared before and after, so every route to <c>UserManagement</c> (direct, group, nested group, mapping, shadow
///     user) is judged by the same code.
/// </summary>
internal sealed class RoleGraph
{
    private const int MaxGroupDepth = 10;

    /// <summary>Groups by rtId.</summary>
    public Dictionary<string, GroupNode> Groups { get; internal init; } = new(StringComparer.Ordinal);

    /// <summary>External tenant user mappings by rtId.</summary>
    public Dictionary<string, MappingNode> Mappings { get; internal init; } = new(StringComparer.Ordinal);

    /// <summary>Ids of all users.</summary>
    public HashSet<string> UserIds { get; internal init; } = new(StringComparer.Ordinal);

    /// <summary>Cross-tenant shadow user id to the ids of the mappings that serve it.</summary>
    public Dictionary<string, HashSet<string>> ShadowUserMappings { get; internal init; } = new(StringComparer.Ordinal);

    /// <summary>Ids of the users that hold the administrator role directly.</summary>
    public HashSet<string> DirectHolders { get; internal init; } = new(StringComparer.Ordinal);

    /// <summary>The rtId of the administrator role (<c>UserManagement</c>), <c>null</c> when the tenant has none.</summary>
    public string? AdminRoleId { get; internal init; }

    /// <summary>Loads the graph from the stores of the current tenant.</summary>
    public static async Task<RoleGraph> LoadAsync(
        UserManager<RtUser> userManager,
        RoleManager<RtRole> roleManager,
        IUserStore<RtUser> userStore,
        IGroupStore groupStore,
        IExternalTenantUserMappingStore mappingStore,
        ICrossTenantShadowUserChainResolver chainResolver)
    {
        var adminRole = await roleManager.FindByNameAsync(CommonConstants.UserManagementRole).ConfigureAwait(false);
        var graph = new RoleGraph { AdminRoleId = adminRole?.RtId.ToString() };

        foreach (var group in await groupStore.GetAllAsync().ConfigureAwait(false))
        {
            var node = new GroupNode
            {
                Roles = [.. await groupStore.GetRoleIdsAsync(group.RtId).ConfigureAwait(false)],
                Children = [.. await groupStore.GetMemberGroupIdsAsync(group.RtId).ConfigureAwait(false)],
                Users = [.. await groupStore.GetMemberUserIdsAsync(group.RtId).ConfigureAwait(false)],
                Clients = [.. await groupStore.GetMemberClientIdsAsync(group.RtId).ConfigureAwait(false)],
                Mappings = [.. await groupStore.GetMemberExternalUserIdsAsync(group.RtId).ConfigureAwait(false)]
            };
            graph.Groups[group.RtId.ToString()] = node;
        }

        foreach (var mapping in await mappingStore.GetAllAsync().ConfigureAwait(false))
        {
            graph.Mappings[mapping.RtId.ToString()] = new MappingNode
            {
                Roles = mapping.MappedRoleIds == null ? [] : [.. mapping.MappedRoleIds]
            };
        }

        foreach (var user in userManager.Users.AsEnumerable().ToList())
        {
            var id = user.RtId.ToString();
            graph.UserIds.Add(id);
            if (!CrossTenantShadowUserName.IsShadowUserName(user.UserName))
            {
                continue;
            }

            var chain = await chainResolver.GetSourceChainAsync(user.UserName).ConfigureAwait(false);
            if (chain.Count == 0)
            {
                continue;
            }

            graph.ShadowUserMappings[id] =
            [
                .. (await mappingStore.FindBySourceUserNamesAsync(chain).ConfigureAwait(false))
                .Select(m => m.RtId.ToString())
            ];
        }

        if (adminRole != null)
        {
            var normalized = adminRole.NormalizedName ?? adminRole.Name?.ToUpperInvariant() ?? string.Empty;
            foreach (var holder in await ((IUserRoleStore<RtUser>)userStore)
                         .GetUsersInRoleAsync(normalized, CancellationToken.None).ConfigureAwait(false))
            {
                graph.DirectHolders.Add(holder.RtId.ToString());
            }
        }

        return graph;
    }

    /// <summary>A deep copy to apply a change to.</summary>
    public RoleGraph Clone() => new()
    {
        AdminRoleId = AdminRoleId,
        Groups = Groups.ToDictionary(g => g.Key, g => g.Value.Clone(), StringComparer.Ordinal),
        Mappings = Mappings.ToDictionary(m => m.Key, m => new MappingNode { Roles = [.. m.Value.Roles] },
            StringComparer.Ordinal),
        UserIds = [.. UserIds],
        ShadowUserMappings = ShadowUserMappings.ToDictionary(s => s.Key, s => new HashSet<string>(s.Value),
            StringComparer.Ordinal),
        DirectHolders = [.. DirectHolders]
    };

    /// <summary>
    ///     The role ids a member of the group receives: the roles of the group and of every nested group (depth 10,
    ///     cycle-safe, like <c>GroupRoleResolver</c>).
    /// </summary>
    public HashSet<string> EffectiveRoles(string groupId)
    {
        var roles = new HashSet<string>(StringComparer.Ordinal);
        Collect(groupId, roles, [], 0);
        return roles;
    }

    /// <summary>The groups that give their roles to the subject: those it is a direct member of and their nested groups.</summary>
    public HashSet<string> GroupsReachingSubject(string? userId, IEnumerable<string> mappingIds)
    {
        var mappings = mappingIds.ToHashSet(StringComparer.Ordinal);
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, group) in Groups)
        {
            if ((userId != null && group.Users.Contains(userId)) || group.Mappings.Overlaps(mappings))
            {
                CollectGroups(id, result, 0);
            }
        }

        return result;
    }

    /// <summary>The mappings that serve the user (empty for a local user).</summary>
    public IReadOnlyCollection<string> MappingsServing(string? userId) =>
        userId != null && ShadowUserMappings.TryGetValue(userId, out var mappings) ? mappings : [];

    /// <summary>The ids of the users that effectively hold the administrator role (direct, groups, mappings, shadow users).</summary>
    public HashSet<string> Holders()
    {
        var holders = new HashSet<string>(StringComparer.Ordinal);
        if (AdminRoleId == null)
        {
            return holders;
        }

        holders.UnionWith(DirectHolders.Where(UserIds.Contains));

        var granting = Groups.Keys.Where(g => EffectiveRoles(g).Contains(AdminRoleId)).ToHashSet(StringComparer.Ordinal);
        foreach (var id in granting)
        {
            holders.UnionWith(Groups[id].Users.Where(UserIds.Contains));
        }

        foreach (var (shadowId, mappingIds) in ShadowUserMappings)
        {
            if (!UserIds.Contains(shadowId))
            {
                continue;
            }

            var viaMapping = mappingIds.Any(m =>
                Mappings.TryGetValue(m, out var node) && node.Roles.Contains(AdminRoleId));
            var viaGroup = granting.Any(g => Groups[g].Mappings.Overlaps(mappingIds));
            if (viaMapping || viaGroup)
            {
                holders.Add(shadowId);
            }
        }

        return holders;
    }

    /// <summary>Removes a group and every reference to it.</summary>
    public void RemoveGroup(string groupId)
    {
        Groups.Remove(groupId);
        foreach (var group in Groups.Values)
        {
            group.Children.Remove(groupId);
        }
    }

    /// <summary>Removes a mapping and every reference to it.</summary>
    public void RemoveMapping(string mappingId)
    {
        Mappings.Remove(mappingId);
        foreach (var group in Groups.Values)
        {
            group.Mappings.Remove(mappingId);
        }

        foreach (var served in ShadowUserMappings.Values)
        {
            served.Remove(mappingId);
        }
    }

    private void Collect(string groupId, HashSet<string> roles, HashSet<string> visited, int depth)
    {
        if (depth >= MaxGroupDepth || !visited.Add(groupId) || !Groups.TryGetValue(groupId, out var group))
        {
            return;
        }

        roles.UnionWith(group.Roles);
        foreach (var child in group.Children)
        {
            Collect(child, roles, visited, depth + 1);
        }
    }

    private void CollectGroups(string groupId, HashSet<string> groups, int depth)
    {
        if (depth >= MaxGroupDepth || !groups.Add(groupId) || !Groups.TryGetValue(groupId, out var group))
        {
            return;
        }

        foreach (var child in group.Children)
        {
            CollectGroups(child, groups, depth + 1);
        }
    }
}

/// <summary>A group of the <see cref="RoleGraph" />.</summary>
internal sealed class GroupNode
{
    /// <summary>Role ids assigned to the group.</summary>
    public HashSet<string> Roles { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Nested (child) group ids.</summary>
    public HashSet<string> Children { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Member user ids.</summary>
    public HashSet<string> Users { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Member client ids.</summary>
    public HashSet<string> Clients { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Member external tenant user mapping ids.</summary>
    public HashSet<string> Mappings { get; init; } = new(StringComparer.Ordinal);

    public GroupNode Clone() => new()
    {
        Roles = [.. Roles], Children = [.. Children], Users = [.. Users], Clients = [.. Clients], Mappings = [.. Mappings]
    };
}

/// <summary>An external tenant user mapping of the <see cref="RoleGraph" />.</summary>
internal sealed class MappingNode
{
    /// <summary>The mapped role ids.</summary>
    public HashSet<string> Roles { get; init; } = new(StringComparer.Ordinal);
}
