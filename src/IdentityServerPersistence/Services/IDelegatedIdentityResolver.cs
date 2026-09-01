namespace IdentityServerPersistence.Services;

/// <summary>
///     Why a delegation ("on-behalf-of") request could not be resolved into an effective identity.
///     These are <b>expected</b> outcomes, not exceptions — the resolver never throws for them so the
///     caller can map each one onto a specific OAuth error without exception-driven control flow.
/// </summary>
public enum DelegationDenialReason
{
    /// <summary>Not a denial — the delegation was resolved.</summary>
    None = 0,

    /// <summary>
    ///     No <c>Client</c> with the requested <c>client_id</c> exists in the request tenant. The
    ///     service account is not provisioned here, so no roles can be intersected.
    /// </summary>
    ServiceAccountNotFound = 1,

    /// <summary>
    ///     The <c>sub</c> carried by the <c>subject_token</c> does not resolve to a user in the
    ///     request tenant (unknown, deleted, or a malformed subject identifier).
    /// </summary>
    UserNotFound = 2
}

/// <summary>
///     Outcome of resolving a delegation: either granted (with the effective role set) or denied
///     (with a reason). An <b>empty</b> <see cref="EffectiveRoleNames" /> on a granted result is a
///     legitimate outcome — the token is still issued, it simply carries no <c>role</c> claims, and
///     every role-gated downstream consumer therefore fails closed.
/// </summary>
public sealed record DelegatedIdentityResult
{
    private DelegatedIdentityResult(
        bool isGranted,
        DelegationDenialReason denialReason,
        IReadOnlySet<string> effectiveRoleNames,
        IReadOnlySet<string> serviceAccountRoleNames,
        IReadOnlySet<string> userRoleNames)
    {
        IsGranted = isGranted;
        DenialReason = denialReason;
        EffectiveRoleNames = effectiveRoleNames;
        ServiceAccountRoleNames = serviceAccountRoleNames;
        UserRoleNames = userRoleNames;
    }

    /// <summary>True when the delegation resolved. See <see cref="EffectiveRoleNames" /> for the roles.</summary>
    public bool IsGranted { get; }

    /// <summary>Why the delegation was denied; <see cref="DelegationDenialReason.None" /> when granted.</summary>
    public DelegationDenialReason DenialReason { get; }

    /// <summary>
    ///     The intersection of the service account's and the user's effective role names — the roles
    ///     the delegated token carries. May be empty (see the type remarks).
    /// </summary>
    public IReadOnlySet<string> EffectiveRoleNames { get; }

    /// <summary>The service account's effective roles (direct + group-inherited). Diagnostics / audit only.</summary>
    public IReadOnlySet<string> ServiceAccountRoleNames { get; }

    /// <summary>The user's effective roles (direct + group-inherited). Diagnostics / audit only.</summary>
    public IReadOnlySet<string> UserRoleNames { get; }

    /// <summary>Creates a granted result.</summary>
    public static DelegatedIdentityResult Granted(
        IReadOnlySet<string> effectiveRoleNames,
        IReadOnlySet<string> serviceAccountRoleNames,
        IReadOnlySet<string> userRoleNames) =>
        new(true, DelegationDenialReason.None, effectiveRoleNames, serviceAccountRoleNames, userRoleNames);

    /// <summary>Creates a denied result.</summary>
    public static DelegatedIdentityResult Denied(DelegationDenialReason reason) =>
        new(false, reason, EmptySet, EmptySet, EmptySet);

    private static IReadOnlySet<string> EmptySet => new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
///     Resolves the effective identity of a delegation ("on-behalf-of") request: a service-account
///     <c>Client</c> acting for a <c>User</c>, both in the <b>same</b> tenant (AB#5026).
/// </summary>
/// <remarks>
///     <para>
///         The delegated token's authority is deliberately the <b>intersection</b> of what the
///         service account may do and what the user may do — neither side can grant the other
///         anything it does not already hold. A service account with broad roles acting for a
///         low-privilege user gets the user's narrow set; a low-privilege service account acting for
///         an administrator gets the service account's narrow set.
///     </para>
///     <para>
///         This service is intentionally <b>free of any Duende IdentityServer type</b>. The grant
///         validator that drives it is a thin protocol adapter, so the delegation policy survives the
///         planned move off Duende (Epic 4989) and is unit-testable without protocol mocks.
///     </para>
///     <para>
///         Every store it composes reads through the <b>request tenant</b> repository, so the caller
///         must guarantee the request is wired to the intended tenant before calling
///         (<c>OidcTenantResolutionMiddleware</c> does this from <c>acr_values=tenant:…</c>).
///     </para>
/// </remarks>
public interface IDelegatedIdentityResolver
{
    /// <summary>
    ///     Resolves the delegation of <paramref name="userSubjectId" /> to the service account
    ///     <paramref name="serviceAccountClientId" />, both looked up in the current request tenant.
    /// </summary>
    /// <param name="serviceAccountClientId">The <c>client_id</c> of the authenticated service account.</param>
    /// <param name="userSubjectId">The <c>sub</c> (user RtId) carried by the subject token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    ///     A granted result carrying the role intersection, or a denied result with the reason.
    ///     Never throws for an unknown client or user.
    /// </returns>
    Task<DelegatedIdentityResult> ResolveAsync(
        string serviceAccountClientId,
        string userSubjectId,
        CancellationToken cancellationToken = default);
}
