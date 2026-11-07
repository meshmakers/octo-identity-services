namespace IdentityServerPersistence.Services;

/// <summary>
///     Why a token exchange from a source tenant S that is no registry ancestor of the target tenant T is refused
///     (AB#8343, AB#8344). The exchange answers <c>access_denied</c> for every value except <see cref="None" />.
/// </summary>
public enum SiblingGrantRefusal
{
    /// <summary>
    ///     No sibling grant explains the refusal: S is a registry ancestor of T, T never granted the user, or the state
    ///     cannot be read. The exchange refuses as for an unrelated tenant (<c>unauthorized_client</c>).
    /// </summary>
    None,

    /// <summary>T holds a mapping for the user, but S does not permit T (any more, AB#8343).</summary>
    NotPermitted,

    /// <summary>
    ///     T holds a mapping for the user and S permits T, but the mapping grants no role: neither its direct
    ///     <c>MappedRoleIds</c> nor the groups it is a member of (nested groups included) name a role that exists in T
    ///     (AB#8344). Roles attached directly to the <c>xt_</c> shadow user do not count for a sibling source.
    /// </summary>
    NoEffectiveRole,

    /// <summary>
    ///     T holds no mapping for the user any more, but the user's <c>xt_</c> shadow user exists in T: the grant was
    ///     removed after the user switched into T (AB#8344).
    /// </summary>
    Removed
}
