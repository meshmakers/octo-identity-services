using Duende.IdentityServer.Events;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Audit event raised when a delegation ("on-behalf-of") grant succeeds (AB#5026): a service
///     account was issued an access token running on a user's subject, carrying the intersection of
///     both parties' roles.
/// </summary>
/// <remarks>
///     Category and IDs are namespaced under <c>Delegation</c> so they never collide with Duende's
///     built-in event catalogue. <c>OctoEventSink</c> persists only Error / Failure events to the
///     runtime event log, so this success event is intentionally log-only.
/// </remarks>
public class DelegationSuccessEvent : Event
{
    /// <summary>Creates the success audit event.</summary>
    /// <param name="actorClientId">The <c>client_id</c> of the delegating service account.</param>
    /// <param name="userSubjectId">The <c>sub</c> of the user the token was issued for.</param>
    /// <param name="tenantId">The tenant the delegation ran in (same for both parties in v1).</param>
    /// <param name="effectiveRoleCount">
    ///     Number of roles in the intersection. Zero is a legitimate outcome — the token carries no
    ///     role claims and every role-gated consumer fails closed — and worth auditing as such.
    /// </param>
    public DelegationSuccessEvent(string actorClientId, string userSubjectId, string tenantId,
        int effectiveRoleCount)
        : base(EventCategories.Delegation, "Delegation Success", EventTypes.Success,
            EventIds.DelegationSuccess,
            $"Service account '{actorClientId}' acted for user '{userSubjectId}' in tenant '{tenantId}' with {effectiveRoleCount} effective role(s)")
    {
        ActorClientId = actorClientId;
        UserSubjectId = userSubjectId;
        TenantId = tenantId;
        EffectiveRoleCount = effectiveRoleCount;
    }

    /// <summary>The <c>client_id</c> of the delegating service account (the <c>act</c> claim value).</summary>
    public string ActorClientId { get; }

    /// <summary>The <c>sub</c> of the user the delegated token was issued for.</summary>
    public string UserSubjectId { get; }

    /// <summary>The tenant the delegation ran in.</summary>
    public string TenantId { get; }

    /// <summary>Number of roles in the service-account ∩ user intersection.</summary>
    public int EffectiveRoleCount { get; }
}

/// <summary>
///     Audit event raised when a delegation ("on-behalf-of") grant is rejected (AB#5026) — e.g. the
///     tenant was not wired into the request, the subject token belonged to a different tenant, or
///     the service account / user does not exist in the tenant.
/// </summary>
/// <remarks>Being a Failure event, this is persisted to the runtime event log by <c>OctoEventSink</c>.</remarks>
public class DelegationFailureEvent : Event
{
    /// <summary>Creates the failure audit event.</summary>
    /// <param name="actorClientId">The <c>client_id</c> of the authenticated service account.</param>
    /// <param name="userSubjectId">The <c>sub</c> extracted from the subject token, if any.</param>
    /// <param name="tenantId">The tenant the delegation was requested for.</param>
    /// <param name="reason">A short, non-sensitive description of why the delegation was rejected.</param>
    public DelegationFailureEvent(string actorClientId, string userSubjectId, string tenantId, string reason)
        : base(EventCategories.Delegation, "Delegation Failure", EventTypes.Failure,
            EventIds.DelegationFailure,
            $"Delegation by service account '{actorClientId}' for user '{userSubjectId}' in tenant '{tenantId}' rejected: {reason}")
    {
        ActorClientId = actorClientId;
        UserSubjectId = userSubjectId;
        TenantId = tenantId;
        Reason = reason;
    }

    /// <summary>The <c>client_id</c> of the authenticated service account.</summary>
    public string ActorClientId { get; }

    /// <summary>The <c>sub</c> extracted from the subject token, if any.</summary>
    public string UserSubjectId { get; }

    /// <summary>The tenant the delegation was requested for.</summary>
    public string TenantId { get; }

    /// <summary>A short, non-sensitive description of why the delegation was rejected.</summary>
    public string Reason { get; }
}
