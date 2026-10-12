namespace IdentityServerPersistence.Services.FileRoles;

using IdentityServerPersistence.Services.RoleGrants;

/// <summary>
///     Role graph of one tenant as the <see cref="TenantAdministratorFileRoleGrantPlanner"/> sees it. All ids are
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
internal sealed record TenantAdministratorFileRoleGrantInput(
    IReadOnlyDictionary<string, IReadOnlySet<string>> UserRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoleIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupChildGroupIds,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupMemberUserIds,
    IReadOnlySet<string>? ExcludedUserIds = null);

/// <summary>Users the planner decided on. Never contains a user that already holds the role.</summary>
internal sealed record TenantAdministratorFileRoleGrantPlan(IReadOnlyList<string> UserIds);

/// <summary>
///     AB#6578: decides which existing users receive <c>FileManagement</c> because they administer the tenant.
///     Pure function — no I/O — so the rule is unit-testable without a database.
/// </summary>
/// <remarks>
///     <para>
///         Why: the one-time Reporting-based grant (<see cref="FileRoleGrantPlanner"/>) only reaches holders of the
///         Reporting roles. A tenant without Reporting has no File-role holder, so its administrators see an empty
///         file system (data permissions are fail-closed, read needs FileViewer or FileManagement) while the
///         platform-services admin session still sees the default file root.
///     </para>
///     <para>
///         Rule (same discriminator and exclusions as the AB#5544 SecretManagement administrator grant): a local
///         <b>human</b> user that holds BOTH <c>AdminPanelManagement</c> and <c>TenantManagement</c> — direct, via
///         groups (including <c>TenantOwners</c>) or mixed — gets a <b>direct</b> <c>AssignedRole</c> edge. Holding
///         only one of the two is not enough. A user that already holds <c>FileManagement</c> (directly or through a
///         group) is skipped. Nothing is ever removed.
///     </para>
///     <para>
///         Why no group grant: a role on a group is inherited by every member, and members are not only users —
///         clients (service accounts) and external tenant user mappings (provisioned parent-tenant administrators,
///         AB#5708) inherit the same way. Subjects are therefore only <c>RtUser</c> entities, and cross-tenant shadow
///         users (<c>xt_</c> prefix) are excluded via <see cref="TenantAdministratorFileRoleGrantInput.ExcludedUserIds"/>.
///     </para>
///     <para>
///         Group semantics mirror <c>GroupRoleResolver</c>: the effective roles of a group are its own roles plus the
///         effective roles of its child groups (depth-limited, cycle-safe); a user's effective roles are the direct
///         roles plus the effective roles of every group the user is a direct member of.
///     </para>
/// </remarks>
internal static class TenantAdministratorFileRoleGrantPlanner
{
    public static TenantAdministratorFileRoleGrantPlan Plan(
        TenantAdministratorFileRoleGrantInput input,
        string adminPanelManagementRoleId,
        string tenantManagementRoleId,
        string fileManagementRoleId)
        => new(AdministratorRoleGrantPlanner.Plan(
            input.UserRoleIds, input.GroupRoleIds, input.GroupChildGroupIds, input.GroupMemberUserIds,
            input.ExcludedUserIds, adminPanelManagementRoleId, tenantManagementRoleId, fileManagementRoleId));
}
