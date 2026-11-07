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

/// <summary>
///     The OAuth tokens and authorizations whose subject is the user. They never keep a user (rule A, AB#8305): a token
///     cannot carry a role the user cannot obtain, so Apply revokes them together with the user.
/// </summary>
/// <param name="ActiveTokens">Tokens with status <c>valid</c> that have not expired.</param>
/// <param name="InactiveTokens">Revoked, redeemed, expired or otherwise inactive tokens.</param>
/// <param name="ActiveAuthorizations">Authorizations with status <c>valid</c>.</param>
/// <param name="InactiveAuthorizations">Revoked or otherwise inactive authorizations.</param>
internal sealed record ShadowUserOAuthUse(
    int ActiveTokens,
    int InactiveTokens,
    int ActiveAuthorizations,
    int InactiveAuthorizations)
{
    public static readonly ShadowUserOAuthUse None = new(0, 0, 0, 0);

    public bool Any => ActiveTokens + InactiveTokens + ActiveAuthorizations + InactiveAuthorizations > 0;
}

/// <summary>What the cleanup knows about one <c>xt_</c> user of a tenant.</summary>
/// <param name="HasDirectUseData">
///     Names of the direct-use evidence the user carries (password, two-factor, external logins, user tokens, claims).
///     Empty for a user that only the token exchange created. OAuth tokens and authorizations are not direct-use data
///     any more (rule A); they are in <paramref name="OAuth" />.
/// </param>
internal sealed record ShadowUserFacts(
    string RtId,
    string UserName,
    DateTime? CreatedAt,
    IReadOnlyCollection<ShadowUserEdge> Edges,
    IReadOnlyCollection<string> HasDirectUseData,
    ShadowUserOAuthUse? OAuth = null);

/// <summary>An external tenant user mapping as the cleanup sees it.</summary>
/// <param name="MappingRtId">The mapping's rtId; empty where only the source identity matters (chain-source rule).</param>
/// <param name="GrantsRole">
///     Rule A (AB#8305): true when the mapping actually grants a role — a non-empty <c>MappedRoleIds</c> list, or a
///     membership in a group that holds at least one role (nested groups included, as at token time) — or carries any
///     association other than a group membership. Only such a mapping keeps its <c>xt_</c> user. Defaults to true so that a
///     mapping whose grant was not evaluated always keeps the user.
/// </param>
internal sealed record ShadowUserMappingSource(
    string SourceTenantId,
    string SourceUserId,
    string SourceUserName,
    string MappingRtId = "",
    bool GrantsRole = true);

/// <summary>The decision for one <c>xt_</c> user: a candidate when <see cref="SkipReasons" /> is empty.</summary>
/// <param name="EmptyMappingIds">
///     For a candidate: the rtIds of the empty mappings of its name chain (no role grant) that Apply deletes together with
///     the user. A mapping a kept <c>xt_</c> user of the tenant depends on (its nearest tier, or its only mappings) is not
///     listed. Empty for a kept user.
/// </param>
/// <param name="OAuth">The user's OAuth tokens and authorizations; Apply revokes them together with the user.</param>
internal sealed record ShadowUserCleanupDecision(
    string RtId,
    string UserName,
    DateTime? CreatedAt,
    IReadOnlyList<string> SkipReasons,
    IReadOnlyList<string> EmptyMappingIds,
    ShadowUserOAuthUse OAuth)
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
///         <item><c>mapping</c>: no external tenant user mapping in this tenant for any identity of its name chain
///             that grants a role (<see cref="ShadowUserMappingSource.GrantsRole" />, rule A). Every tier of a chain
///             <c>xt_a_xt_r_n</c> (<c>a/xt_r_n</c>, <c>r/n</c>) is a suffix of the name, so a mapping whose
///             <c>{SourceTenantId}_{SourceUserName}</c> ends the name (case-insensitive) belongs to it. This needs no
///             tenant registry and errs on the side of keeping a user. An empty mapping (no role, no group with a role)
///             does not keep the user; it is listed in <see cref="ShadowUserCleanupDecision.EmptyMappingIds" /> and
///             deleted with it, unless a kept <c>xt_</c> user depends on it (<see cref="MappingsAKeptUserDependsOn" />);</item>
///         <item><c>chain-source</c>: no mapping in any tenant uses this user as its source (source tenant = this
///             tenant and source user name = this user name or source user id = this rtId);</item>
///         <item><c>direct-use:&lt;kind&gt;</c>: no password, two-factor, external login, user token or claim —
///             evidence the user was used other than through the token exchange.</item>
///     </list>
///     OAuth tokens and authorizations never keep a user (rule A): revoked, redeemed or expired ones are history, and a
///     still valid one of a user who cannot obtain any role cannot carry a role either. Apply revokes them with the user.
/// </remarks>
internal static class ShadowUserCleanupPlanner
{
    public static IReadOnlyList<ShadowUserCleanupDecision> Plan(
        string tenantId,
        IEnumerable<ShadowUserFacts> users,
        IReadOnlyCollection<ShadowUserMappingSource> mappingsInTenant,
        IReadOnlyCollection<ShadowUserMappingSource> mappingsInAllTenants)
    {
        var planned = new List<(ShadowUserFacts User, List<string> Reasons, List<ShadowUserMappingSource> ChainMappings)>();
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

            var chainMappings = mappingsInTenant.Where(m => IsMappingOfChain(user.UserName, m)).ToList();
            if (chainMappings.Any(m => m.GrantsRole))
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

            planned.Add((user, reasons, chainMappings));
        }

        // An empty mapping that a kept user depends on stays: deleting it would change that user's state.
        var mappingsOfKeptUsers = planned
            .Where(p => p.Reasons.Count > 0)
            .SelectMany(p => MappingsAKeptUserDependsOn(p.User.UserName, p.ChainMappings))
            .Select(m => m.MappingRtId)
            .ToHashSet(StringComparer.Ordinal);

        return planned
            .Select(p => new ShadowUserCleanupDecision(
                p.User.RtId,
                p.User.UserName,
                p.User.CreatedAt,
                p.Reasons,
                p.Reasons.Count > 0
                    ? []
                    : p.ChainMappings
                        .Where(m => !m.GrantsRole && !string.IsNullOrEmpty(m.MappingRtId)
                                                  && !mappingsOfKeptUsers.Contains(m.MappingRtId))
                        .Select(m => m.MappingRtId)
                        .Distinct(StringComparer.Ordinal)
                        .OrderBy(id => id, StringComparer.Ordinal)
                        .ToList(),
                p.User.OAuth ?? ShadowUserOAuthUse.None))
            .ToList();
    }

    /// <summary>
    ///     The mappings of a kept user's name chain that deleting would change that user's state with (AB#8305, chained
    ///     names). A chained name shares the deeper tiers of its chain with shorter shadow users of the same person:
    ///     <c>xt_karlplus_xt_acc_xt_os_n</c> and <c>xt_acc_xt_os_n</c> both match a mapping <c>acc/xt_os_n</c>. For the
    ///     longer, kept user such a deeper-tier mapping only matters when it grants something (never deleted anyway) or
    ///     when it is the user's only evidence of explicit provisioning:
    ///     <list type="bullet">
    ///         <item>an empty mapping adds no role (token-time role resolution reads only role and group grants);</item>
    ///         <item>a sibling tenant switch checks the mapping of the immediate source, the nearest tier, only;</item>
    ///         <item>explicit provisioning and the allowed tenants need any one mapping of the chain.</item>
    ///     </list>
    ///     So a kept user depends on its nearest-tier mappings always, and on all its chain mappings when it has neither a
    ///     nearest-tier nor a role-granting mapping.
    /// </summary>
    internal static IEnumerable<ShadowUserMappingSource> MappingsAKeptUserDependsOn(
        string userName, IReadOnlyCollection<ShadowUserMappingSource> chainMappings)
    {
        var nearest = chainMappings.Where(m => IsNearestTierMapping(userName, m)).ToList();
        return nearest.Count > 0 || chainMappings.Any(m => m.GrantsRole) ? nearest : chainMappings;
    }

    /// <summary>
    ///     True when the mapping's source identity is the nearest tier of the shadow user's name chain: its whole name is
    ///     <c>xt_{SourceTenantId}_{SourceUserName}</c> (case-insensitive), the name the exchange builds for that source.
    /// </summary>
    internal static bool IsNearestTierMapping(string userName, ShadowUserMappingSource mapping)
        => !string.IsNullOrEmpty(mapping.SourceTenantId) && !string.IsNullOrEmpty(mapping.SourceUserName)
           && string.Equals(userName, CrossTenantShadowUserName.Build(mapping.SourceTenantId, mapping.SourceUserName),
               StringComparison.OrdinalIgnoreCase);

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
