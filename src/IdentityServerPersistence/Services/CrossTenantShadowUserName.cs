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
///         identity. Tenant ids never contain an underscore, so the first two separators are unambiguous.
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
    public static IReadOnlyList<(string TenantId, string UserName)> GetSourceChain(string? userName)
    {
        var chain = new List<(string TenantId, string UserName)>();
        var current = userName;

        while (IsShadowUserName(current) && chain.Count < MaxDepth)
        {
            var parts = current!.Split('_', 3);
            if (parts.Length < 3 || string.IsNullOrEmpty(parts[1]) || string.IsNullOrEmpty(parts[2]))
            {
                break;
            }

            chain.Add((parts[1], parts[2]));
            current = parts[2];
        }

        return chain;
    }

    /// <summary>
    ///     The identity a source identity unwinds to: the last tier of the chain of
    ///     <paramref name="userName" />, or the identity itself when it is not a shadow user.
    /// </summary>
    public static (string TenantId, string UserName) GetRootIdentity(string tenantId, string userName)
    {
        var chain = GetSourceChain(userName);
        return chain.Count == 0 ? (tenantId, userName) : chain[^1];
    }

    /// <summary>Case-insensitive comparison of two identities (tenant id + user name).</summary>
    public static bool IsSameIdentity(
        (string TenantId, string UserName) left, (string TenantId, string UserName) right)
        => string.Equals(left.TenantId, right.TenantId, StringComparison.OrdinalIgnoreCase)
           && string.Equals(left.UserName, right.UserName, StringComparison.OrdinalIgnoreCase);
}
