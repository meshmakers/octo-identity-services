namespace IdentityServerPersistence.Services.SecretManagement;

/// <summary>One external tenant user mapping as the planner sees it.</summary>
/// <param name="RtId">The mapping rtId.</param>
/// <param name="SourceTenantId">The tenant the mapped user comes from.</param>
/// <param name="MappedRoleIds">The role rtIds listed in <c>MappedRoleIds</c>.</param>
/// <param name="IsTenantOwnersMember">True when the mapping is a direct member of <c>TenantOwners</c>.</param>
internal sealed record TenantOwnersGrantMapping(
    string RtId,
    string SourceTenantId,
    IReadOnlyCollection<string> MappedRoleIds,
    bool IsTenantOwnersMember);

/// <summary>
///     AB#8161: decides which external tenant user mappings need <c>SecretManagement</c> appended to their
///     <c>MappedRoleIds</c>. Pure function — no I/O.
/// </summary>
/// <remarks>
///     A mapping qualifies when its source tenant is the system tenant (octosystem), it carries
///     <c>TenantManagement</c> in <c>MappedRoleIds</c>, does not hold <c>SecretManagement</c> there yet and is
///     not a member of <c>TenantOwners</c> (members inherit the role from the group). Mappings of any other
///     source tenant and mappings without <c>TenantManagement</c> are never touched.
/// </remarks>
internal static class TenantOwnersSecretManagementGrantPlanner
{
    /// <returns>The mapping rtIds to extend, ordered ordinally.</returns>
    public static IReadOnlyList<string> PlanMappings(
        IEnumerable<TenantOwnersGrantMapping> mappings,
        string systemTenantId,
        string tenantManagementRoleId,
        string secretManagementRoleId)
    {
        return mappings
            .Where(m => string.Equals(m.SourceTenantId, systemTenantId, StringComparison.OrdinalIgnoreCase)
                        && !m.IsTenantOwnersMember
                        && m.MappedRoleIds.Contains(tenantManagementRoleId, StringComparer.OrdinalIgnoreCase)
                        && !m.MappedRoleIds.Contains(secretManagementRoleId, StringComparer.OrdinalIgnoreCase))
            .Select(m => m.RtId)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();
    }
}
