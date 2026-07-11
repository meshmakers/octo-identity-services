using Duende.IdentityServer.Events;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Audit event raised when a cross-tenant RFC 8693 token exchange succeeds (AB#4338): the
///     home-tenant (A) user was issued a target-tenant (B) access token running on the B-shadow
///     user's subject.
/// </summary>
/// <remarks>
///     Category and IDs are namespaced under <c>TokenExchange</c> so they never collide with
///     Duende's built-in event catalogue. Success events are surfaced via structured logging and the
///     IdentityServer diagnostics pipeline; <c>OctoEventSink</c> persists only Error / Failure events
///     to the runtime event log, so this success event is intentionally log-only.
/// </remarks>
public class TokenExchangeSuccessEvent : Event
{
    /// <summary>
    ///     Creates the success audit event.
    /// </summary>
    /// <param name="sourceUserId">The <c>sub</c> of the user in the home tenant (A).</param>
    /// <param name="sourceTenantId">The home tenant (A) the subject token was issued for.</param>
    /// <param name="targetTenantId">The target tenant (B) the exchanged token is minted for.</param>
    /// <param name="shadowRtId">The RtId (subject) of the provisioned B-shadow user.</param>
    public TokenExchangeSuccessEvent(string sourceUserId, string sourceTenantId, string targetTenantId,
        string shadowRtId)
        : base(EventCategories.TokenExchange, "Token Exchange Success", EventTypes.Success,
            EventIds.TokenExchangeSuccess,
            $"Cross-tenant token exchange from '{sourceTenantId}' to '{targetTenantId}' for shadow user '{shadowRtId}'")
    {
        SourceUserId = sourceUserId;
        SourceTenantId = sourceTenantId;
        TargetTenantId = targetTenantId;
        ShadowRtId = shadowRtId;
    }

    /// <summary>The <c>sub</c> of the user in the home tenant (A).</summary>
    public string SourceUserId { get; }

    /// <summary>The home tenant (A) the subject token was issued for.</summary>
    public string SourceTenantId { get; }

    /// <summary>The target tenant (B) the exchanged token is minted for.</summary>
    public string TargetTenantId { get; }

    /// <summary>The RtId (subject) of the provisioned B-shadow user.</summary>
    public string ShadowRtId { get; }
}

/// <summary>
///     Audit event raised when a cross-tenant RFC 8693 token exchange is rejected (AB#4338) — e.g.
///     the target tenant was not wired into the request, cross-tenant access was denied, or the
///     B-shadow user could not be provisioned.
/// </summary>
/// <remarks>
///     Being a Failure event, this is persisted to the runtime event log by <c>OctoEventSink</c>.
/// </remarks>
public class TokenExchangeFailureEvent : Event
{
    /// <summary>
    ///     Creates the failure audit event.
    /// </summary>
    /// <param name="sourceUserId">The <c>sub</c> extracted from the subject token, if any.</param>
    /// <param name="sourceTenantId">The home tenant (A) extracted from the subject token, if any.</param>
    /// <param name="targetTenantId">The requested target tenant (B).</param>
    /// <param name="reason">A short, non-sensitive description of why the exchange was rejected.</param>
    public TokenExchangeFailureEvent(string sourceUserId, string sourceTenantId, string targetTenantId,
        string reason)
        : base(EventCategories.TokenExchange, "Token Exchange Failure", EventTypes.Failure,
            EventIds.TokenExchangeFailure,
            $"Cross-tenant token exchange from '{sourceTenantId}' to '{targetTenantId}' rejected: {reason}")
    {
        SourceUserId = sourceUserId;
        SourceTenantId = sourceTenantId;
        TargetTenantId = targetTenantId;
        Reason = reason;
    }

    /// <summary>The <c>sub</c> extracted from the subject token, if any.</summary>
    public string SourceUserId { get; }

    /// <summary>The home tenant (A) extracted from the subject token, if any.</summary>
    public string SourceTenantId { get; }

    /// <summary>The requested target tenant (B).</summary>
    public string TargetTenantId { get; }

    /// <summary>A short, non-sensitive description of why the exchange was rejected.</summary>
    public string Reason { get; }
}

/// <summary>Event categories for OctoMesh-defined IdentityServer events.</summary>
internal static class EventCategories
{
    /// <summary>Category for cross-tenant token-exchange events (AB#4338).</summary>
    public const string TokenExchange = "TokenExchange";
}

/// <summary>Stable event IDs for OctoMesh-defined IdentityServer events.</summary>
internal static class EventIds
{
    /// <summary>ID for <see cref="TokenExchangeSuccessEvent" />.</summary>
    public const int TokenExchangeSuccess = 43380;

    /// <summary>ID for <see cref="TokenExchangeFailureEvent" />.</summary>
    public const int TokenExchangeFailure = 43381;
}
