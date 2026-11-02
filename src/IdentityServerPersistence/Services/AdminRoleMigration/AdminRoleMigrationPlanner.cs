namespace IdentityServerPersistence.Services.AdminRoleMigration;

/// <summary>Kind of a migrated subject. Clients and groups are never migrated.</summary>
internal enum AdminRoleMigrationSubjectKind
{
    /// <summary>A user, including cross-tenant shadow users (<c>xt_</c>).</summary>
    User,

    /// <summary>An external tenant user mapping; its roles are the <c>MappedRoleIds</c> list.</summary>
    Mapping
}

/// <summary>A subject with the role rtIds it holds directly.</summary>
internal sealed record AdminRoleMigrationSubject(
    AdminRoleMigrationSubjectKind Kind,
    string RtId,
    IReadOnlySet<string> DirectRoleIds);

/// <summary>What happens to one subject.</summary>
/// <param name="JoinGroup">True when the subject is not yet a member of TenantOwners.</param>
/// <param name="RemoveRoleIds">Direct roles that TenantOwners carries and that are removed (ordered).</param>
internal sealed record AdminRoleMigrationSubjectPlan(
    AdminRoleMigrationSubjectKind Kind,
    string RtId,
    bool JoinGroup,
    IReadOnlyList<string> RemoveRoleIds);

/// <summary>
///     AB#8165: decides which subjects move from directly assigned admin roles to <c>TenantOwners</c>. Pure
///     function — no I/O.
/// </summary>
/// <remarks>
///     A subject qualifies when it holds <c>TenantManagement</c> AND <c>UserManagement</c> directly. It joins the
///     group (if it is no member yet) and loses exactly those direct roles that the group carries; every other
///     role stays. A subject that does not qualify, or that is already a member without a covered direct role, is
///     not part of the plan — so a second run plans nothing.
/// </remarks>
internal static class AdminRoleMigrationPlanner
{
    public static IReadOnlyList<AdminRoleMigrationSubjectPlan> Plan(
        IEnumerable<AdminRoleMigrationSubject> subjects,
        IReadOnlySet<string> ownerRoleIds,
        IReadOnlySet<string> ownerMemberIds,
        string tenantManagementRoleId,
        string userManagementRoleId)
    {
        var plans = new List<AdminRoleMigrationSubjectPlan>();
        foreach (var subject in subjects
                     .OrderBy(s => s.Kind)
                     .ThenBy(s => s.RtId, StringComparer.Ordinal))
        {
            if (!subject.DirectRoleIds.Contains(tenantManagementRoleId)
                || !subject.DirectRoleIds.Contains(userManagementRoleId))
            {
                continue;
            }

            var join = !ownerMemberIds.Contains(subject.RtId);
            var remove = subject.DirectRoleIds
                .Where(ownerRoleIds.Contains)
                .OrderBy(r => r, StringComparer.Ordinal)
                .ToList();
            if (join || remove.Count > 0)
            {
                plans.Add(new AdminRoleMigrationSubjectPlan(subject.Kind, subject.RtId, join, remove));
            }
        }

        return plans;
    }
}
