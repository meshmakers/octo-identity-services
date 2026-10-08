namespace IdentityServerPersistence.Services.FileRoles;

/// <summary>Kind of subject that holds a role through an <c>AssignedRole</c> edge.</summary>
internal enum FileRoleGrantSubjectKind
{
    User,
    Group,
    Client
}

/// <summary>
///     One source → target pair of the grant: every direct holder of <see cref="SourceRoleId"/> receives
///     <see cref="TargetRoleId"/> (e.g. ReportingViewer → FileViewer).
/// </summary>
internal sealed record FileRoleGrantPair(string SourceRoleId, string TargetRoleId);

/// <summary>
///     Snapshot of the direct role holdings of a tenant, keyed by subject rtId (hex). Group-inherited roles
///     are deliberately not expanded: a group that holds the source role gets the target role on the group
///     itself, so its members inherit it the same way they inherited the source role.
/// </summary>
/// <param name="UserRoles">User rtId → rtIds of the roles its outbound <c>AssignedRole</c> edges point to.</param>
/// <param name="GroupRoles">Group rtId → rtIds of the roles its outbound <c>AssignedRole</c> edges point to.</param>
/// <param name="ClientRoles">Client rtId → rtIds of the roles its outbound <c>AssignedRole</c> edges point to.</param>
/// <param name="MappingRoles">
///     ExternalTenantUserMapping rtId → its <c>MappedRoleIds</c> (role rtIds as strings; the attribute is a free
///     string list, so it may also contain stale or non-id values, which never match).
/// </param>
internal sealed record FileRoleGrantInput(
    IReadOnlyDictionary<string, IReadOnlySet<string>> UserRoles,
    IReadOnlyDictionary<string, IReadOnlySet<string>> GroupRoles,
    IReadOnlyDictionary<string, IReadOnlySet<string>> ClientRoles,
    IReadOnlyDictionary<string, IReadOnlySet<string>> MappingRoles);

/// <summary>A new <c>AssignedRole</c> edge from <see cref="SubjectId"/> to <see cref="RoleId"/>.</summary>
internal sealed record FileRoleGrantEdge(FileRoleGrantSubjectKind Kind, string SubjectId, string RoleId);

/// <summary>Result of <see cref="FileRoleGrantPlanner.Plan"/>.</summary>
/// <param name="Edges">AssignedRole edges to insert, ordered by kind, subject and role.</param>
/// <param name="MappingAdditions">
///     ExternalTenantUserMapping rtId → role rtIds to append to its <c>MappedRoleIds</c>, ordered by mapping id.
/// </param>
internal sealed record FileRoleGrantPlan(
    IReadOnlyList<FileRoleGrantEdge> Edges,
    IReadOnlyList<KeyValuePair<string, IReadOnlyList<string>>> MappingAdditions)
{
    public bool IsEmpty => Edges.Count == 0 && MappingAdditions.Count == 0;
}

/// <summary>
///     AB#6180: pure planning rule of the one-time File-role grant (<see cref="FileRoleGrant"/>).
/// </summary>
/// <remarks>
///     <para>
///         For every pair (ReportingManagement → FileManagement, ReportingViewer → FileViewer): every user, group
///         and client that holds the source role through a <strong>direct</strong> <c>AssignedRole</c> edge, and
///         every external tenant user mapping whose <c>MappedRoleIds</c> contains the source role, receives the
///         target role in the same way — unless it already holds the target role.
///     </para>
///     <para>
///         Mirroring the direct holdings is sufficient and minimal: anybody who receives the source role through a
///         group (nested groups and cross-tenant mappings included) receives the target role through the very same
///         group, because the group itself is granted. Additive only — the plan never removes anything.
///     </para>
/// </remarks>
internal static class FileRoleGrantPlanner
{
    public static FileRoleGrantPlan Plan(FileRoleGrantInput input, IReadOnlyList<FileRoleGrantPair> pairs)
    {
        var edges = new List<FileRoleGrantEdge>();
        AddEdges(FileRoleGrantSubjectKind.User, input.UserRoles);
        AddEdges(FileRoleGrantSubjectKind.Group, input.GroupRoles);
        AddEdges(FileRoleGrantSubjectKind.Client, input.ClientRoles);

        var mappingAdditions = new List<KeyValuePair<string, IReadOnlyList<string>>>();
        foreach (var (mappingId, roleIds) in input.MappingRoles.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var additions = TargetsToGrant(roleIds);
            if (additions.Count > 0)
            {
                mappingAdditions.Add(new KeyValuePair<string, IReadOnlyList<string>>(mappingId, additions));
            }
        }

        return new FileRoleGrantPlan(edges, mappingAdditions);

        void AddEdges(FileRoleGrantSubjectKind kind, IReadOnlyDictionary<string, IReadOnlySet<string>> holdings)
        {
            foreach (var (subjectId, roleIds) in holdings.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            {
                edges.AddRange(TargetsToGrant(roleIds).Select(roleId => new FileRoleGrantEdge(kind, subjectId, roleId)));
            }
        }

        List<string> TargetsToGrant(IReadOnlySet<string> heldRoleIds)
        {
            var targets = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var pair in pairs)
            {
                if (ContainsRole(heldRoleIds, pair.SourceRoleId) && !ContainsRole(heldRoleIds, pair.TargetRoleId))
                {
                    targets.Add(pair.TargetRoleId);
                }
            }

            return targets.ToList();
        }
    }

    /// <summary>
    ///     Role rtIds are hex strings; the stored casing may differ from <c>OctoObjectId.ToString()</c>
    ///     (e.g. a <c>MappedRoleIds</c> entry written by hand), so compare case-insensitively.
    /// </summary>
    private static bool ContainsRole(IReadOnlySet<string> heldRoleIds, string roleId) =>
        heldRoleIds.Contains(roleId) || heldRoleIds.Any(r => string.Equals(r, roleId, StringComparison.OrdinalIgnoreCase));
}
