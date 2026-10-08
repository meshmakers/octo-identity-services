namespace IdentityServerPersistence.Services;

/// <summary>
///     Naming convention of cross-tenant shadow users: <c>xt_{sourceTenantId}_{sourceUserName}</c>.
/// </summary>
/// <remarks>
///     <para>
///         A shadow user's source user may itself be a shadow user of a tenant further up, so a name can
///         nest: <c>xt_karlplus_xt_meshmakers_gerald</c> in a child of <c>karlplus</c> is the shadow of
///         <c>xt_meshmakers_gerald</c> in <c>karlplus</c>, which is the shadow of <c>gerald</c> in
///         <c>meshmakers</c>. Every tier of that chain is the same person, which is the identity rule
///         behind the AB#4966 exchange candidates, <c>allowed_tenants</c> and — since AB#5708 — the
///         effective roles of a shadow user and the one-shadow-user-per-person lookup.
///     </para>
///     <para>
///         The prefix is reserved (AB#5708): users created through the user API must not carry it, otherwise
///         an administrator of an ancestor tenant could mint a local user that unwinds to somebody else's
///         identity.
///     </para>
///     <para>
///         🔴 <b>Tenant ids MAY contain underscores</b> (<c>TenantContext.ValidateTenantIdFormat</c> allows
///         ASCII letters, digits, <c>-</c> and <c>_</c>), so the name alone is ambiguous:
///         <c>xt_evil_xt_meshmakers_gerald</c> is the shadow of <c>meshmakers_gerald</c> in tenant
///         <c>evil_xt</c> just as much as the shadow of <c>xt_meshmakers_gerald</c> in tenant <c>evil</c>.
///         A naive split at the first separator would let an ordinary user of <c>evil_xt</c> unwind to
///         <c>gerald@meshmakers</c> (AB#5708 review). <see cref="GetSourceChainAsync" /> therefore splits
///         each tier only at a prefix that is a registered tenant id and stops — fail closed — when no
///         registered tenant or more than one fits.
///     </para>
/// </remarks>
public static class CrossTenantShadowUserName
{
    /// <summary>The reserved user name prefix of cross-tenant shadow users.</summary>
    public const string Prefix = "xt_";

    private const int MaxDepth = 10;

    /// <summary>Builds the shadow user name for a source identity.</summary>
    public static string Build(string sourceTenantId, string sourceUserName)
        => $"{Prefix}{sourceTenantId}_{sourceUserName}";

    /// <summary>True when <paramref name="userName" /> carries the reserved shadow user prefix.</summary>
    public static bool IsShadowUserName(string? userName)
        => userName != null && userName.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    ///     Unwinds a shadow user name into its source identities, nearest first:
    ///     <c>xt_a_xt_r_n</c> → <c>(a, xt_r_n)</c>, <c>(r, n)</c>. A name without the prefix yields nothing.
    /// </summary>
    /// <remarks>
    ///     Each tier is split only after a prefix that <paramref name="isTenantRegistered" /> confirms as a
    ///     tenant id. When no candidate prefix is a registered tenant (deleted tenant, malformed name) or
    ///     more than one is (<c>a</c> and <c>a_b</c> both exist), the chain ends at the previous tier: an
    ///     ambiguous identity grants nothing.
    /// </remarks>
    /// <param name="userName">The (possibly nested) shadow user name.</param>
    /// <param name="isTenantRegistered">Registry probe for a candidate tenant id (case-insensitive).</param>
    public static async Task<IReadOnlyList<(string TenantId, string UserName)>> GetSourceChainAsync(
        string? userName, Func<string, Task<bool>> isTenantRegistered)
    {
        ArgumentNullException.ThrowIfNull(isTenantRegistered);

        var chain = new List<(string TenantId, string UserName)>();
        var current = userName;

        while (IsShadowUserName(current) && chain.Count < MaxDepth)
        {
            var remainder = current![Prefix.Length..];
            (string TenantId, string UserName)? tier = null;
            var matches = 0;

            // Every separator is a candidate end of the tenant id; the user part must stay non-empty.
            for (var i = remainder.IndexOf('_'); i > 0 && i < remainder.Length - 1; i = remainder.IndexOf('_', i + 1))
            {
                var candidateTenantId = remainder[..i];
                if (!await isTenantRegistered(candidateTenantId))
                {
                    continue;
                }

                matches++;
                tier = (candidateTenantId, remainder[(i + 1)..]);
            }

            if (matches != 1)
            {
                break;
            }

            chain.Add(tier!.Value);
            current = tier.Value.UserName;
        }

        return chain;
    }

    /// <summary>
    ///     The identity a source identity unwinds to: the last tier of the chain of
    ///     <paramref name="userName" />, or the identity itself when it is not a shadow user.
    /// </summary>
    public static async Task<(string TenantId, string UserName)> GetRootIdentityAsync(
        string tenantId, string userName, Func<string, Task<bool>> isTenantRegistered)
    {
        var chain = await GetSourceChainAsync(userName, isTenantRegistered);
        return chain.Count == 0 ? (tenantId, userName) : chain[^1];
    }

    /// <summary>Case-insensitive comparison of two identities (tenant id + user name).</summary>
    public static bool IsSameIdentity(
        (string TenantId, string UserName) left, (string TenantId, string UserName) right)
        => string.Equals(left.TenantId, right.TenantId, StringComparison.OrdinalIgnoreCase)
           && string.Equals(left.UserName, right.UserName, StringComparison.OrdinalIgnoreCase);
}
