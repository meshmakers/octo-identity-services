using Duende.IdentityServer.Events;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Audit event raised when a <c>client_credentials</c> token request is rejected because the
///     issuing tenant cannot be determined (AB#5058): the request carried no
///     <c>acr_values=tenant:{tenantId}</c> and the presented <c>client_id</c> is <b>not</b>
///     unambiguously bound to a single tenant.
/// </summary>
/// <remarks>
///     <para>
///         Being a Failure event, this is persisted to the runtime event log by
///         <c>OctoEventSink</c>. It is the only trace an operator gets of a caller that used to rely
///         on the (now removed) implicit fall-back to the system tenant, so it deliberately carries
///         the client id and the machine-readable reason.
///     </para>
///     <para>
///         No secret, scope or token material is included — the event is written to a durable log
///         that tenant administrators can read.
///     </para>
/// </remarks>
public class ClientCredentialsTenantAmbiguityEvent : Event
{
    /// <summary>
    ///     Creates the failure audit event.
    /// </summary>
    /// <param name="clientId">The <c>client_id</c> whose tenant binding is ambiguous.</param>
    /// <param name="reason">A short, non-sensitive description of why the binding is ambiguous.</param>
    public ClientCredentialsTenantAmbiguityEvent(string clientId, string reason)
        : base(EventCategories.ClientCredentials, "Client Credentials Tenant Ambiguity", EventTypes.Failure,
            EventIds.ClientCredentialsTenantAmbiguity,
            $"Rejected client_credentials token request for client '{clientId}' without acr_values: {reason}")
    {
        ClientId = clientId;
        Reason = reason;
    }

    /// <summary>The <c>client_id</c> whose tenant binding is ambiguous.</summary>
    public string ClientId { get; }

    /// <summary>A short, non-sensitive description of why the binding is ambiguous.</summary>
    public string Reason { get; }
}
