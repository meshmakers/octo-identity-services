namespace IdentityServerPersistence.Services.SecretManagement;

/// <summary>
///     Role graph of one tenant as the <see cref="SecretManagementGrantPlanner"/> sees it. All ids are
///     rtId hex strings; role ids are the rtIds of <c>RtRole</c> entities.
/// </summary>
/// <param name="UserRoleIds">User rtId → role rtIds assigned directly (outbound <c>AssignedRole</c>).</param>
/// <param name="GroupRoleIds">Group rtId → role rtIds assigned directly to the group.</param>
/// <param name="GroupChildGroupIds">Group rtId → child group rtIds (outbound <c>ChildGroup</c>).</param>
/// <param name="GroupMemberUserIds">Group rtId → user rtIds that are direct members (outbound <c>GroupMember</c> to a user).</param>
internal sealed record SecretManagementGrantInput(
    IReadOnlyDictionary<string, IReadOnlySet<string>> UserRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupChildGroupIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupMemberUserIds);

/// <summary>Grants the planner decided on. Never contains a subject that already holds the role.</summary>
internal sealed record SecretManagementGrantPlan(
    IReadOnlyList<string> GroupIds,
    IReadOnlyList<string> UserIds);

/// <summary>
///     AB#5544: decides which existing groups and users receive the <c>SecretManagement</c> role. Pure
///     function — no I/O — so the rule is unit-testable without a database.
/// </summary>
/// <remarks>
///     <para>
///         Rule (PO decision): a subject that holds BOTH <c>AdminPanelManagement</c> and
///         <c>TenantManagement</c> gets <c>SecretManagement</c>, and so does the <c>TenantOwners</c>
///         group. Holding only <c>AdminPanelManagement</c> is not enough — secret sweeps stay a separate
///         privilege. Nothing is ever removed.
///     </para>
///     <para>
///         Where the grant lands: a group whose effective roles contain both roles gets the role itself, so
///         its members receive it through the same group the admin roles come from. A user who holds both
///         roles but does not end up with <c>SecretManagement</c> through such a group (both roles direct,
///         or one direct and one from a group, or from two different groups) gets it directly.
///     </para>
///     <para>
///         Group semantics mirror <c>GroupRoleResolver</c>: the effective roles of a group are its own
///         roles plus the effective roles of its child groups (<c>ChildGroup</c> edges, depth-limited and
///         cycle-safe); a user's effective roles are the direct roles plus the effective roles of every
///         group the user is a direct member of.
///     </para>
/// </remarks>
internal static class SecretManagementGrantPlanner
{
    private const int MaxDepth = 10;

    public static SecretManagementGrantPlan Plan(
        SecretManagementGrantInput input,
        string adminPanelManagementRoleId,
        string tenantManagementRoleId,
        string secretManagementRoleId,
        string? tenantOwnersGroupId)
    {
        var groupIds = input.GroupRoleIds.Keys
            .Concat(input.GroupChildGroupIds.Keys)
            .Concat(input.GroupMemberUserIds.Keys)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var effectiveGroupRoles = groupIds.ToDictionary(
            g => g,
            g => EffectiveGroupRoles(input, g),
            StringComparer.Ordinal);

        bool QualifiesForGrant(IReadOnlySet<string> roles) =>
            roles.Contains(adminPanelManagementRoleId) && roles.Contains(tenantManagementRoleId);

        // 1. Groups. TenantOwners always gets a direct edge (it mirrors the blueprint seed), unless it holds
        //    the role directly already. Any other group qualifies when its effective roles hold both admin
        //    roles; candidates are processed leaves first and a group is skipped when a descendant already
        //    received the grant — the admin roles come from that descendant, so the grant belongs there.
        var grantedGroups = new HashSet<string>(StringComparer.Ordinal);
        if (tenantOwnersGroupId != null
            && groupIds.Contains(tenantOwnersGroupId, StringComparer.Ordinal)
            && !(input.GroupRoleIds.TryGetValue(tenantOwnersGroupId, out var ownersRoles)
                 && ownersRoles.Contains(secretManagementRoleId)))
        {
            grantedGroups.Add(tenantOwnersGroupId);
        }

        var candidates = groupIds
            .Where(g => !string.Equals(g, tenantOwnersGroupId, StringComparison.Ordinal))
            .Where(g => QualifiesForGrant(effectiveGroupRoles[g]))
            .Where(g => !effectiveGroupRoles[g].Contains(secretManagementRoleId))
            .OrderBy(g => Height(input, g, new HashSet<string>(StringComparer.Ordinal), 0))
            .ThenBy(g => g, StringComparer.Ordinal);
        foreach (var groupId in candidates)
        {
            if (DescendantGranted(input, groupId, grantedGroups))
            {
                continue;
            }

            grantedGroups.Add(groupId);
        }

        // 2. Users: effective roles AFTER the group grants above; grant directly only where still missing.
        var grantedUsers = new List<string>();
        foreach (var (userId, directRoles) in input.UserRoleIds.OrderBy(u => u.Key, StringComparer.Ordinal))
        {
            var roles = new HashSet<string>(directRoles, StringComparer.Ordinal);
            foreach (var (groupId, members) in input.GroupMemberUserIds)
            {
                if (!members.Contains(userId))
                {
                    continue;
                }

                roles.UnionWith(effectiveGroupRoles[groupId]);
                if (GrantReaches(input, groupId, grantedGroups))
                {
                    roles.Add(secretManagementRoleId);
                }
            }

            if (QualifiesForGrant(roles) && !roles.Contains(secretManagementRoleId))
            {
                grantedUsers.Add(userId);
            }
        }

        return new SecretManagementGrantPlan(
            grantedGroups.OrderBy(g => g, StringComparer.Ordinal).ToList(),
            grantedUsers);
    }

    private static int Height(SecretManagementGrantInput input, string groupId, HashSet<string> visited, int depth)
    {
        if (depth >= MaxDepth || !visited.Add(groupId)
            || !input.GroupChildGroupIds.TryGetValue(groupId, out var children) || children.Count == 0)
        {
            return 0;
        }

        return 1 + children.Max(c => Height(input, c, new HashSet<string>(visited, StringComparer.Ordinal), depth + 1));
    }

    /// <summary>True when a (transitive) child group of <paramref name="groupId"/>, not the group itself, is granted.</summary>
    private static bool DescendantGranted(SecretManagementGrantInput input, string groupId, HashSet<string> grantedGroups)
    {
        if (!input.GroupChildGroupIds.TryGetValue(groupId, out var children))
        {
            return false;
        }

        var visited = new HashSet<string>(StringComparer.Ordinal) { groupId };
        return children.Any(c => Walk(input, c, visited, 1, grantedGroups.Contains));
    }

    private static HashSet<string> EffectiveGroupRoles(SecretManagementGrantInput input, string groupId)
    {
        var roles = new HashSet<string>(StringComparer.Ordinal);
        Walk(input, groupId, new HashSet<string>(StringComparer.Ordinal), 0,
            g =>
            {
                if (input.GroupRoleIds.TryGetValue(g, out var own))
                {
                    roles.UnionWith(own);
                }

                return false;
            });
        return roles;
    }

    /// <summary>True when <paramref name="groupId"/> or one of its (transitive) child groups is granted.</summary>
    private static bool GrantReaches(SecretManagementGrantInput input, string groupId, HashSet<string> grantedGroups)
    {
        return Walk(input, groupId, new HashSet<string>(StringComparer.Ordinal), 0, grantedGroups.Contains);
    }

    /// <summary>Depth-first over ChildGroup edges; stops early when <paramref name="visit"/> returns true.</summary>
    private static bool Walk(
        SecretManagementGrantInput input, string groupId, HashSet<string> visited, int depth, Func<string, bool> visit)
    {
        if (depth >= MaxDepth || !visited.Add(groupId))
        {
            return false;
        }

        if (visit(groupId))
        {
            return true;
        }

        if (!input.GroupChildGroupIds.TryGetValue(groupId, out var children))
        {
            return false;
        }

        foreach (var child in children)
        {
            if (Walk(input, child, visited, depth + 1, visit))
            {
                return true;
            }
        }

        return false;
    }
}
