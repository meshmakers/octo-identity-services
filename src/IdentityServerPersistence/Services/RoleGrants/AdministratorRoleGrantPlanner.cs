namespace IdentityServerPersistence.Services.RoleGrants;

/// <summary>
///     Shared rule of the one-time "grant role X to the human tenant administrators" steps
///     (<c>SecretManagementAdminGrant</c>, AB#5544, and <c>TenantAdministratorFileRoleGrant</c>, AB#6578). Pure
///     function — no I/O. The callers keep their own typed input/plan records and delegate here.
/// </summary>
/// <remarks>
///     A local user that holds BOTH <c>AdminPanelManagement</c> and <c>TenantManagement</c> — direct, via groups
///     (including <c>TenantOwners</c>) or mixed — and does not yet hold the target role is a subject of the plan.
///     Excluded users (cross-tenant shadow users) are skipped. Group semantics mirror <c>GroupRoleResolver</c>:
///     the effective roles of a group are its own roles plus those of its child groups (depth-limited,
///     cycle-safe); a user's effective roles are the direct roles plus the effective roles of every group the
///     user is a direct member of.
/// </remarks>
internal static class AdministratorRoleGrantPlanner
{
    private const int MaxDepth = 10;

    /// <returns>The user rtIds to grant, ordered ordinally.</returns>
    public static IReadOnlyList<string> Plan(
        IReadOnlyDictionary<string, IReadOnlySet<string>> userRoleIds,
        IReadOnlyDictionary<string, IReadOnlySet<string>> groupRoleIds,
        IReadOnlyDictionary<string, IReadOnlySet<string>> groupChildGroupIds,
        IReadOnlyDictionary<string, IReadOnlySet<string>> groupMemberUserIds,
        IReadOnlySet<string>? excludedUserIds,
        string adminPanelManagementRoleId,
        string tenantManagementRoleId,
        string targetRoleId)
    {
        var groupIds = groupRoleIds.Keys
            .Concat(groupChildGroupIds.Keys)
            .Concat(groupMemberUserIds.Keys)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var effectiveGroupRoles = groupIds.ToDictionary(
            g => g,
            g =>
            {
                var roles = new HashSet<string>(StringComparer.Ordinal);
                Walk(groupRoleIds, groupChildGroupIds, g, new HashSet<string>(StringComparer.Ordinal), 0, roles);
                return roles;
            },
            StringComparer.Ordinal);

        var granted = new List<string>();
        foreach (var (userId, directRoles) in userRoleIds.OrderBy(u => u.Key, StringComparer.Ordinal))
        {
            if (excludedUserIds?.Contains(userId) == true)
            {
                continue;
            }

            var roles = new HashSet<string>(directRoles, StringComparer.Ordinal);
            foreach (var (groupId, members) in groupMemberUserIds)
            {
                if (members.Contains(userId))
                {
                    roles.UnionWith(effectiveGroupRoles[groupId]);
                }
            }

            if (roles.Contains(adminPanelManagementRoleId) && roles.Contains(tenantManagementRoleId)
                && !roles.Contains(targetRoleId))
            {
                granted.Add(userId);
            }
        }

        return granted;
    }

    private static void Walk(
        IReadOnlyDictionary<string, IReadOnlySet<string>> groupRoleIds,
        IReadOnlyDictionary<string, IReadOnlySet<string>> groupChildGroupIds,
        string groupId, HashSet<string> visited, int depth, HashSet<string> roles)
    {
        if (depth >= MaxDepth || !visited.Add(groupId))
        {
            return;
        }

        if (groupRoleIds.TryGetValue(groupId, out var own))
        {
            roles.UnionWith(own);
        }

        if (!groupChildGroupIds.TryGetValue(groupId, out var children))
        {
            return;
        }

        foreach (var child in children)
        {
            Walk(groupRoleIds, groupChildGroupIds, child, visited, depth + 1, roles);
        }
    }
}
