namespace IdentityServerPersistence.Services.SecretManagement;

/// <summary>
///     Role graph of one tenant as the <see cref="SecretManagementGrantPlanner"/> sees it. All ids are
///     rtId hex strings; role ids are the rtIds of <c>RtRole</c> entities.
/// </summary>
/// <param name="UserRoleIds">User rtId → role rtIds assigned directly (outbound <c>AssignedRole</c>).</param>
/// <param name="GroupRoleIds">Group rtId → role rtIds assigned directly to the group.</param>
/// <param name="GroupChildGroupIds">Group rtId → child group rtIds (outbound <c>ChildGroup</c>).</param>
/// <param name="GroupMemberUserIds">Group rtId → user rtIds that are direct members (outbound <c>GroupMember</c> to a user).</param>
/// <param name="ExcludedUserIds">
///     User rtIds that are never granted: cross-tenant shadow users (<c>xt_…</c>, provisioned parent-tenant
///     administrators, AB#5708). Optional; empty when omitted.
/// </param>
internal sealed record SecretManagementGrantInput(
    IReadOnlyDictionary<string, IReadOnlySet<string>> UserRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupChildGroupIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupMemberUserIds,
    IReadOnlySet<string>? ExcludedUserIds = null);

/// <summary>Users the planner decided on. Never contains a user that already holds the role.</summary>
internal sealed record SecretManagementGrantPlan(IReadOnlyList<string> UserIds);

/// <summary>
///     AB#5544: decides which existing users receive the <c>SecretManagement</c> role. Pure function — no
///     I/O — so the rule is unit-testable without a database.
/// </summary>
/// <remarks>
///     <para>
///         Rule (decision Gerald 2026-10-11): SecretManagement goes to <b>human administrators only</b>. A
///         local user that holds BOTH <c>AdminPanelManagement</c> and <c>TenantManagement</c> — direct, via
///         groups (including <c>TenantOwners</c>) or mixed — gets a <b>direct</b> edge. Holding only
///         <c>AdminPanelManagement</c> is not enough — secret sweeps stay a separate privilege. Nothing is
///         ever removed.
///     </para>
///     <para>
///         Why no group grant: a role on a group is inherited by every member of it, and group members are
///         not only users — clients (service accounts, e.g. <c>octo-pipeline-sa-*</c>) and external tenant
///         user mappings (provisioned parent-tenant administrators, AB#5708, who sit in <c>TenantOwners</c>)
///         inherit the same way (<c>GroupRoleResolver</c>). Subjects of the plan are therefore only
///         <c>RtUser</c> entities, and cross-tenant shadow users (<c>xt_</c> prefix, reserved) are
///         excluded. Clients and mappings are never users, so they are never subjects.
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
        string secretManagementRoleId)
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

        var grantedUsers = new List<string>();
        foreach (var (userId, directRoles) in input.UserRoleIds.OrderBy(u => u.Key, StringComparer.Ordinal))
        {
            if (input.ExcludedUserIds?.Contains(userId) == true)
            {
                continue;
            }

            var roles = new HashSet<string>(directRoles, StringComparer.Ordinal);
            foreach (var (groupId, members) in input.GroupMemberUserIds)
            {
                if (members.Contains(userId))
                {
                    roles.UnionWith(effectiveGroupRoles[groupId]);
                }
            }

            if (roles.Contains(adminPanelManagementRoleId) && roles.Contains(tenantManagementRoleId)
                && !roles.Contains(secretManagementRoleId))
            {
                grantedUsers.Add(userId);
            }
        }

        return new SecretManagementGrantPlan(grantedUsers);
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
