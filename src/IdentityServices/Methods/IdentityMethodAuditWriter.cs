using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Writes the identity-side security record of a CK method call into the event log of the tenant (AB#5672).
/// </summary>
/// <remarks>
///     <para>
///         Not <c>IIdentityAuditService</c>: that one reads the tenant from the HTTP request (a bus handler has none, the event
///         would land in the system tenant) and persists failures only. This record also covers success and names the tenant
///         explicitly. It is the identity-side detail of a security-relevant change (category <c>Identity.Method</c>: who
///         changed whose password, with which outcome). The generic one-per-invocation record <c>Method.Invocation</c> of the
///         gateway (AB#6919, <c>ICkMethodAuditRecorder</c>) is written where the call is dispatched, not in the remote
///         handler host, and is a different category; the two do not duplicate each other.
///     </para>
///     <para>
///         Only identifiers and the outcome code are written, never a parameter value, hash, token or the text of a
///         password check. A failing write is logged and never fails the call.
///     </para>
/// </remarks>
internal interface IIdentityMethodAuditWriter
{
    /// <summary>Records the outcome of one method call.</summary>
    /// <param name="tenantId">Tenant of the call.</param>
    /// <param name="methodId">Qualified method id.</param>
    /// <param name="invocationId">Invocation id of the call.</param>
    /// <param name="targetRtId">Entity the method was called on, if any.</param>
    /// <param name="callerSubject">Subject (user id) or client id of the validated caller, if known.</param>
    /// <param name="outcome"><c>SUCCESS</c> or the error code of the answer.</param>
    /// <param name="extraDetails">
    ///     Method-specific facts (identifiers and flags only, never a parameter value), for example
    ///     <c>lockoutLifted</c> of <c>User.ResetPassword</c>.
    /// </param>
    Task RecordAsync(string tenantId, string methodId, Guid invocationId, string? targetRtId, string? callerSubject,
        string outcome, IReadOnlyList<KeyValuePair<string, string>>? extraDetails = null);
}

internal sealed class IdentityMethodAuditWriter(
    IEventRepository eventRepository,
    ILogger<IdentityMethodAuditWriter> logger) : IIdentityMethodAuditWriter
{
    /// <summary>Category of the events written by this writer.</summary>
    public const string Category = "Identity.Method";

    /// <summary>Outcome of a call that succeeded.</summary>
    public const string SuccessOutcome = "SUCCESS";

    public async Task RecordAsync(string tenantId, string methodId, Guid invocationId, string? targetRtId,
        string? callerSubject, string outcome, IReadOnlyList<KeyValuePair<string, string>>? extraDetails = null)
    {
        var success = outcome == SuccessOutcome;
        var details = new List<KeyValuePair<string, string>>
        {
            new("methodId", methodId),
            new("invocationId", invocationId.ToString()),
            new("outcome", outcome)
        };
        if (!string.IsNullOrEmpty(targetRtId))
        {
            details.Add(new("targetRtId", targetRtId));
        }

        if (!string.IsNullOrEmpty(callerSubject))
        {
            details.Add(new("callerSubject", callerSubject));
        }

        if (extraDetails != null)
        {
            details.AddRange(extraDetails);
        }

        try
        {
            await eventRepository.StoreEventAsync(tenantId, RtEventSourcesEnum.IdentityService,
                    success ? RtEventLevelsEnum.Information : RtEventLevelsEnum.Warning,
                    $"CK method {methodId} on '{targetRtId}': {outcome}", Category, details)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Auditing never breaks the method call itself (same rule as IdentityAuditService).
            logger.LogWarning(ex, "Failed to persist the identity audit event of CK method {MethodId} ({InvocationId})",
                methodId, invocationId);
        }
    }
}
