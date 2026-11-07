namespace IdentityServerPersistence.Services.ShadowUserCleanup;

/// <summary>Kind of an association edge of a shadow user.</summary>
internal enum ShadowUserEdgeKind
{
    /// <summary><c>System.Identity/AssignedRole</c>: the user holds a role directly.</summary>
    AssignedRole,

    /// <summary><c>System.Identity/GroupMember</c>: the user is a member of a group.</summary>
    GroupMember,

    /// <summary>Any other association, in either direction.</summary>
    Other
}

/// <summary>One association edge of a shadow user, in either direction.</summary>
internal sealed record ShadowUserEdge(ShadowUserEdgeKind Kind, string RoleId);

/// <summary>What the cleanup knows about one <c>xt_</c> user of a tenant.</summary>
/// <param name="HasDirectUseData">
///     Names of the direct-use evidence the user carries (password, two-factor, external logins, user tokens, claims,
///     OAuth tokens or authorizations). Empty for a user that only the token exchange created.
/// </param>
internal sealed record ShadowUserFacts(
    string RtId,
    string UserName,
    DateTime? CreatedAt,
    IReadOnlyCollection<ShadowUserEdge> Edges,
    IReadOnlyCollection<string> HasDirectUseData);

/// <summary>The source identity of an external tenant user mapping.</summary>
internal sealed record ShadowUserMappingSource(string SourceTenantId, string SourceUserId, string SourceUserName);

/// <summary>The decision for one <c>xt_</c> user: a candidate when <see cref="SkipReasons" /> is empty.</summary>
internal sealed record ShadowUserCleanupDecision(
    string RtId,
    string UserName,
    DateTime? CreatedAt,
    IReadOnlyList<string> SkipReasons)
{
    public bool IsCandidate => SkipReasons.Count == 0;
}

/// <summary>
///     AB#8305: decides which cross-tenant shadow users (<c>xt_</c>) of one tenant are left-overs without any right and
///     may be deleted. Pure function — no I/O.
/// </summary>
/// <remarks>
///     A user is a candidate only when ALL rules hold; every rule that fails is a skip reason:
///     <list type="number">
///         <item>the user name is a shadow user name (<see cref="CrossTenantShadowUserName.IsShadowUserName" />) —
///             other users are not part of the result at all;</item>
///         <item><c>role</c>: no AssignedRole edge;</item>
///         <item><c>group</c>: no GroupMember edge;</item>
///         <item><c>association:&lt;id&gt;</c>: no other association of any kind, in either direction;</item>
///         <item><c>mapping</c>: no external tenant user mapping in this tenant for any identity of its name chain.
///             Every tier of a chain <c>xt_a_xt_r_n</c> (<c>a/xt_r_n</c>, <c>r/n</c>) is a suffix of the name, so a
///             mapping whose <c>{SourceTenantId}_{SourceUserName}</c> ends the name (case-insensitive) blocks it. This
///             needs no tenant registry and errs on the side of keeping a user;</item>
///         <item><c>chain-source</c>: no mapping in any tenant uses this user as its source (source tenant = this
///             tenant and source user name = this user name or source user id = this rtId);</item>
///         <item><c>direct-use:&lt;kind&gt;</c>: no password, two-factor, external login, user token, claim, OAuth
///             token or authorization — evidence the user was used other than through the token exchange.</item>
///     </list>
/// </remarks>
internal static class ShadowUserCleanupPlanner
{
    public static IReadOnlyList<ShadowUserCleanupDecision> Plan(
        string tenantId,
        IEnumerable<ShadowUserFacts> users,
        IReadOnlyCollection<ShadowUserMappingSource> mappingsInTenant,
        IReadOnlyCollection<ShadowUserMappingSource> mappingsInAllTenants)
    {
        var decisions = new List<ShadowUserCleanupDecision>();
        foreach (var user in users
                     .Where(u => CrossTenantShadowUserName.IsShadowUserName(u.UserName))
                     .OrderBy(u => u.RtId, StringComparer.Ordinal))
        {
            var reasons = new List<string>();
            if (user.Edges.Any(e => e.Kind == ShadowUserEdgeKind.AssignedRole))
            {
                reasons.Add("role");
            }

            if (user.Edges.Any(e => e.Kind == ShadowUserEdgeKind.GroupMember))
            {
                reasons.Add("group");
            }

            reasons.AddRange(user.Edges
                .Where(e => e.Kind == ShadowUserEdgeKind.Other)
                .Select(e => $"association:{e.RoleId}")
                .Distinct(StringComparer.Ordinal)
                .OrderBy(r => r, StringComparer.Ordinal));

            if (mappingsInTenant.Any(m => IsMappingOfChain(user.UserName, m)))
            {
                reasons.Add("mapping");
            }

            if (mappingsInAllTenants.Any(m => UsesAsSource(tenantId, user, m)))
            {
                reasons.Add("chain-source");
            }

            reasons.AddRange(user.HasDirectUseData
                .Distinct(StringComparer.Ordinal)
                .OrderBy(d => d, StringComparer.Ordinal)
                .Select(d => $"direct-use:{d}"));

            decisions.Add(new ShadowUserCleanupDecision(user.RtId, user.UserName, user.CreatedAt, reasons));
        }

        return decisions;
    }

    /// <summary>True when the mapping's source identity is one tier of the shadow user's name chain.</summary>
    internal static bool IsMappingOfChain(string userName, ShadowUserMappingSource mapping)
    {
        if (string.IsNullOrEmpty(mapping.SourceTenantId) || string.IsNullOrEmpty(mapping.SourceUserName))
        {
            return false;
        }

        var rest = userName[CrossTenantShadowUserName.Prefix.Length..];
        var tier = $"{mapping.SourceTenantId}_{mapping.SourceUserName}";
        return string.Equals(rest, tier, StringComparison.OrdinalIgnoreCase)
               || rest.EndsWith("_" + tier, StringComparison.OrdinalIgnoreCase);
    }

    private static bool UsesAsSource(string tenantId, ShadowUserFacts user, ShadowUserMappingSource mapping)
        => string.Equals(mapping.SourceTenantId, tenantId, StringComparison.OrdinalIgnoreCase)
           && (string.Equals(mapping.SourceUserName, user.UserName, StringComparison.OrdinalIgnoreCase)
               || string.Equals(mapping.SourceUserId, user.RtId, StringComparison.Ordinal));
}
