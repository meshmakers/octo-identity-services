namespace IdentityServerPersistence.Services;

/// <summary>
///     Role graph of one tenant as the <see cref="TenantAdministratorRoleGrantPlanner"/> sees it. All ids are
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
internal sealed record TenantAdministratorRoleGraph(
    IReadOnlyDictionary<string, IReadOnlySet<string>> UserRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupChildGroupIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupMemberUserIds,
    IReadOnlySet<string>? ExcludedUserIds = null);

/// <summary>Users the planner decided on. Never contains a user that already holds the role.</summary>
internal sealed record TenantAdministratorRoleGrantPlan(IReadOnlyList<string> UserIds);

/// <summary>
///     AB#6578 / AB#5544: decides which existing users receive a role (<c>FileManagement</c>,
///     <c>SecretManagement</c>) because they administer the tenant. ONE rule for both one-time grants
///     (<c>TenantAdministratorFileRoleGrant</c>, <c>SecretManagementAdminGrant</c>). Pure function — no I/O — so
///     the rule is unit-testable without a database.
/// </summary>
/// <remarks>
///     <para>
///         Why FileManagement: the one-time Reporting-based grant (<see cref="FileRoles.FileRoleGrantPlanner"/>) only
///         reaches holders of the Reporting roles; a tenant without Reporting has no File-role holder, so its
///         administrators see an empty file system (AB#6578). Why SecretManagement: secret sweeps are a separate
///         privilege for human administrators only (decision Gerald 2026-10-11, AB#5544).
///     </para>
///     <para>
///         Rule: a local
///         <b>human</b> user that holds BOTH <c>AdminPanelManagement</c> and <c>TenantManagement</c> — direct, via
///         groups (including <c>TenantOwners</c>) or mixed — gets a <b>direct</b> <c>AssignedRole</c> edge. Holding
///         only one of the two is not enough. A user that already holds the target role (directly or through a
///         group) is skipped. Nothing is ever removed.
///     </para>
///     <para>
///         Why no group grant: a role on a group is inherited by every member, and members are not only users —
///         clients (service accounts) and external tenant user mappings (provisioned parent-tenant administrators,
///         AB#5708) inherit the same way. Subjects are therefore only <c>RtUser</c> entities, and cross-tenant shadow
///         users (<c>xt_</c> prefix) are excluded via <see cref="TenantAdministratorRoleGraph.ExcludedUserIds"/>.
///     </para>
///     <para>
///         Group semantics mirror <c>GroupRoleResolver</c>: the effective roles of a group are its own roles plus the
///         effective roles of its child groups (depth-limited, cycle-safe); a user's effective roles are the direct
///         roles plus the effective roles of every group the user is a direct member of.
///     </para>
/// </remarks>
internal static class TenantAdministratorRoleGrantPlanner
{
    private const int MaxDepth = 10;

    public static TenantAdministratorRoleGrantPlan Plan(
        TenantAdministratorRoleGraph input,
        string adminPanelManagementRoleId,
        string tenantManagementRoleId,
        string targetRoleId)
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
                && !roles.Contains(targetRoleId))
            {
                grantedUsers.Add(userId);
            }
        }

        return new TenantAdministratorRoleGrantPlan(grantedUsers);
    }

    private static HashSet<string> EffectiveGroupRoles(TenantAdministratorRoleGraph input, string groupId)
    {
        var roles = new HashSet<string>(StringComparer.Ordinal);
        Walk(input, groupId, new HashSet<string>(StringComparer.Ordinal), 0, roles);
        return roles;
    }

    private static void Walk(
        TenantAdministratorRoleGraph input, string groupId, HashSet<string> visited, int depth,
        HashSet<string> roles)
    {
        if (depth >= MaxDepth || !visited.Add(groupId))
        {
            return;
        }

        if (input.GroupRoleIds.TryGetValue(groupId, out var own))
        {
            roles.UnionWith(own);
        }

        if (!input.GroupChildGroupIds.TryGetValue(groupId, out var children))
        {
            return;
        }

        foreach (var child in children)
        {
            Walk(input, child, visited, depth + 1, roles);
        }
    }
}
