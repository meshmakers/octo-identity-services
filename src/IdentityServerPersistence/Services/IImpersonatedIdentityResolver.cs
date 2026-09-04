namespace IdentityServerPersistence.Services;

/// <summary>
///     Why an impersonation request could not be resolved into the target client's identity
///     (AB#5114). Expected outcomes, not exceptions — the resolver never throws for them, so the
///     caller can map each onto a specific OAuth error without exception-driven control flow
///     (same convention as <see cref="DelegationDenialReason" />).
/// </summary>
public enum ImpersonationDenialReason
{
    /// <summary>Not a denial — the impersonation was resolved.</summary>
    None = 0,

    /// <summary>
    ///     The authenticated actor client has no <c>Client</c> entity in the request tenant. Without
    ///     one there can be no <c>MayActAs</c> edge, so nothing can be authorized.
    /// </summary>
    ActorNotFound = 1,

    /// <summary>No <c>Client</c> with the requested <c>client_id</c> exists in the request tenant.</summary>
    TargetNotFound = 2,

    /// <summary>The target client exists but is disabled — a disabled client must not be issuable, not even sideways.</summary>
    TargetDisabled = 3,

    /// <summary>
    ///     No <c>System.Identity/MayActAs</c> edge actor→target exists in the request tenant. The
    ///     edge IS the authorization model — no edge, no token.
    /// </summary>
    NotAuthorized = 4
}

/// <summary>
///     Outcome of resolving an impersonation: either granted (with the TARGET client's effective
///     role names — the roles a plain <c>client_credentials</c> token of the target would carry) or
///     denied with a reason.
/// </summary>
public sealed record ImpersonatedIdentityResult
{
    private ImpersonatedIdentityResult(bool isGranted, ImpersonationDenialReason denialReason,
        IReadOnlySet<string> effectiveRoleNames)
    {
        IsGranted = isGranted;
        DenialReason = denialReason;
        EffectiveRoleNames = effectiveRoleNames;
    }

    /// <summary>True when the impersonation resolved.</summary>
    public bool IsGranted { get; }

    /// <summary>Why the impersonation was denied; <see cref="ImpersonationDenialReason.None" /> when granted.</summary>
    public ImpersonationDenialReason DenialReason { get; }

    /// <summary>
    ///     The target client's effective role names (direct <c>AssignedRole</c> + group-inherited) —
    ///     exactly what <c>TokenEndpointController.HandleClientCredentialsAsync</c> would put on the
    ///     target's own token. Never the actor's roles.
    /// </summary>
    public IReadOnlySet<string> EffectiveRoleNames { get; }

    /// <summary>Creates a granted result.</summary>
    public static ImpersonatedIdentityResult Granted(IReadOnlySet<string> effectiveRoleNames) =>
        new(true, ImpersonationDenialReason.None, effectiveRoleNames);

    /// <summary>Creates a denied result.</summary>
    public static ImpersonatedIdentityResult Denied(ImpersonationDenialReason reason) =>
        new(false, reason, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
}

/// <summary>
///     Resolves the identity of an impersonation request (AB#5114): an authenticated actor
///     <c>Client</c> becoming a target <c>Client</c> (typically an adapter becoming its pipeline
///     service account), both in the <b>same</b> tenant, authorized exclusively by the explicit
///     <c>System.Identity/MayActAs</c> edge actor→target.
/// </summary>
/// <remarks>
///     <para>
///         Unlike delegation (<see cref="IDelegatedIdentityResolver" />) there is no intersection:
///         the issued authority is the <b>target's</b> effective role set, whole — the edge is an
///         operator-level statement that the actor may hold everything the target holds. What keeps
///         this contained is that edges are only materialised by the communication reconcile for
///         adapter→pipeline-service-account pairs (plus explicit operator writes), never implied.
///     </para>
///     <para>
///         Free of protocol-stack types, like every resolver here; the processor driving it
///         (<c>ImpersonationProcessor</c>) is a thin protocol adapter. Every store it composes reads
///         through the request tenant, so the caller must guarantee the request is wired to the
///         intended tenant first (<c>OidcTenantResolutionMiddleware</c>).
///     </para>
/// </remarks>
public interface IImpersonatedIdentityResolver
{
    /// <summary>
    ///     Resolves the impersonation of <paramref name="targetClientId" /> by
    ///     <paramref name="actorClientId" />, both looked up in the current request tenant:
    ///     authorization gate (<see cref="AuthorizeActorAsync" />) plus the target's effective roles.
    /// </summary>
    /// <returns>A granted result carrying the TARGET's roles, or a denied result with the reason. Never throws for unknown clients.</returns>
    Task<ImpersonatedIdentityResult> ResolveAsync(
        string actorClientId, string targetClientId, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Only the authorization gate — actor and target exist, target enabled, <c>MayActAs</c>
    ///     edge present — without resolving the target's roles. Used by the on-behalf-of grant's
    ///     <c>requested_client_id</c> extension (AB#5114), where the roles that matter are the
    ///     SA ∩ user intersection resolved by <see cref="IDelegatedIdentityResolver" /> afterwards.
    /// </summary>
    /// <returns><see cref="ImpersonationDenialReason.None" /> when authorized; the denial reason otherwise.</returns>
    Task<ImpersonationDenialReason> AuthorizeActorAsync(
        string actorClientId, string targetClientId, CancellationToken cancellationToken = default);
}
