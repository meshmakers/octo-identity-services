using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Decides which tenant a <c>client_credentials</c> token is issued for (AB#5032) and refuses
///     the request when that tenant cannot be determined without guessing (AB#5058). Ported from
///     the pre-migration <c>ClientCredentialsRoleTokenValidator</c>, whose Duende extension point
///     (<c>ICustomTokenRequestValidator</c>) has no OpenIddict counterpart: OpenIddict builds the
///     principal in <c>TokenEndpointController.HandleClientCredentialsAsync</c>, so the policy
///     lives here — protocol-free, like <see cref="OnBehalfOfProcessor" /> — and the controller
///     turns the outcome into a stamped claim or a <c>Forbid</c>.
/// </summary>
/// <remarks>
///     <para>
///         <b>Why <c>tenant_id</c> matters (AB#5032).</b> <c>TenantAuthorizationMiddleware</c> in
///         octo-common-services used to skip its tenant check for every token without a <c>sub</c>
///         claim — i.e. for every client-credentials token, because such a token carried nothing to
///         check it against. Together with <c>ValidateAudience = false</c> on the consuming
///         services that let any client-credentials client of this authority address any tenant.
///         Stamping the issuing tenant makes the check possible; the middleware then narrows the
///         exemption behind its own staged switch.
///     </para>
///     <para>
///         The tenant is the one the request was resolved to by
///         <c>OidcTenantResolutionMiddleware</c> (<c>acr_values=tenant:{tenantId}</c> on
///         <c>/connect/token</c>) — which is by construction the tenant whose database the client
///         was loaded from.
///     </para>
///     <para>
///         🔴 <b>Why "no <c>acr_values</c>" is not silently the system tenant (AB#5058).</b>
///         AB#5032 fell back to the system tenant on a request without <c>acr_values</c>, reasoning
///         that the client store had resolved the client there, so that is where the token belongs.
///         That reasoning does not survive client mirroring: <c>AutoProvisionInChildTenants</c>
///         provisions the <b>same</b> <c>ClientId</c> with the <b>same</b> secret into every child
///         tenant (<c>ClientMirrorProvisioningService.CreateMirrorClient</c> copies
///         <c>ClientSecrets</c> verbatim). For such a client id, "found in the system tenant" is not
///         evidence of "belongs to the system tenant" — the binding is simply <b>ambiguous</b>, and
///         a caller that omits <c>acr_values</c> would be handed a system-tenant token for free.
///         Every authorization that asks "is the caller in the system tenant" — which is what the
///         hardening of the system routes builds on (AB#5055) — would be trivially satisfiable with
///         a service token.
///     </para>
///     <para>
///         The fix does not depend on the caller being honest: ambiguity is decided <b>server-side</b>
///         from state the caller cannot influence — the <c>AutoProvisionInChildTenants</c> flag, the
///         <c>ProvisionedByParentTenantId</c> mirror marker, and the <c>RtClientMirror</c> tracking
///         rows in the system tenant. An ambiguous request is refused with <c>invalid_request</c>
///         rather than guessed at, and the refusal is persisted through
///         <see cref="IIdentityAuditService" />. Only an <b>unambiguous</b> client id — the
///         overwhelmingly common case, see the caller inventory in <c>docs/authentication.md</c> —
///         is still stamped with the system tenant, so no caller that legitimately omits
///         <c>acr_values</c> today changes behaviour.
///     </para>
///     <para>
///         ⚠️ <b>Residual, and deliberately not closed here.</b> Because a mirror still carries a
///         copy of the parent's secret (AB#5061 added an own secret next to it but could not remove
///         the inherited one), whoever holds a mirror's credentials also holds the parent's, and can
///         therefore ask for the system tenant <i>explicitly</i> with
///         <c>acr_values=tenant:{systemTenant}</c>. No check at the token endpoint can tell those two
///         callers apart. This processor therefore logs a warning whenever a mirroring source obtains
///         a system-tenant token, and AB#5055 must not treat <c>tenant_id == systemTenant</c> on a
///         client-credentials token as proof of provenance on its own.
///     </para>
///     <para>
///         <b>Gone with Duende:</b> the <c>ClientClaimsPrefix</c> dance. Duende prefixed every claim
///         added via <c>ValidatedRequest.ClientClaims</c> with the client's prefix (default
///         <c>client_</c>), so the prefix had to be cleared per request to emit an unprefixed
///         <c>tenant_id</c>. OpenIddict has no such concept — the controller puts the claim straight
///         onto the <c>ClaimsIdentity</c> and <see cref="OctoClaimsDestinations" /> routes it into
///         the access token.
///     </para>
/// </remarks>
public class ClientCredentialsTenantProcessor(
    IClientMirrorProvisioningService clientMirrorProvisioningService,
    IHttpContextAccessor httpContextAccessor,
    ISystemContext systemContext,
    IIdentityAuditService auditService,
    ILogger<ClientCredentialsTenantProcessor> logger)
{
    /// <summary>
    ///     Error description returned for a request whose issuing tenant is ambiguous (AB#5058). It
    ///     names the remedy, so an integrator who hits it is not left guessing — the same rationale
    ///     as the <c>offline_access</c> refusal in <see cref="OnBehalfOfProcessor" />.
    /// </summary>
    public const string AmbiguousTenantErrorDescription =
        "acr_values=tenant:{tenantId} is required for this client: its client id exists in more " +
        "than one tenant, so the issuing tenant cannot be determined from the request.";

    /// <summary>Name of the persisted audit entry for a refused, ambiguous request.</summary>
    public const string AmbiguityAuditEventName = "Client Credentials Tenant Ambiguity";

    /// <summary>
    ///     Outcome of the tenant binding: either the tenant to stamp, or an OAuth error that must
    ///     abort the token request before any claim is composed.
    /// </summary>
    public sealed record TenantBindingOutcome
    {
        /// <summary>The tenant the token is issued for. <c>null</c> when <see cref="Error" /> is set.</summary>
        public string? TenantId { get; init; }

        public string? Error { get; init; }
        public string? ErrorDescription { get; init; }

        public static TenantBindingOutcome Failed(string error, string description) =>
            new() { Error = error, ErrorDescription = description };

        public static TenantBindingOutcome Bound(string tenantId) => new() { TenantId = tenantId };

        /// <summary>
        ///     No tenant could be determined and nothing is wrong with the request — the token is
        ///     issued without a <c>tenant_id</c> claim, exactly as before AB#5032. Only reachable
        ///     when the installation has no system tenant id configured at all.
        /// </summary>
        public static TenantBindingOutcome Unstamped() => new();
    }

    /// <summary>
    ///     Resolves the issuing tenant for an already client-authenticated <c>client_credentials</c>
    ///     request.
    /// </summary>
    /// <param name="clientId">The authenticated <c>client_id</c>.</param>
    /// <param name="client">
    ///     The client record as resolved from the request's tenant directory, or <c>null</c> when the
    ///     directory holds no such record.
    /// </param>
    public async Task<TenantBindingOutcome> ResolveAsync(string clientId, RtClient? client)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        // For client_credentials, OidcTenantResolutionMiddleware writes HttpContext.Items only from
        // acr_values — so a value here means the caller named its tenant explicitly.
        var tenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;

        if (!string.IsNullOrEmpty(tenantId))
        {
            WarnOnInstanceWideCredential(clientId, client, tenantId);
            return TenantBindingOutcome.Bound(tenantId);
        }

        var ambiguityReason = await DetermineTenantAmbiguityAsync(clientId, client);
        if (ambiguityReason != null)
        {
            logger.LogWarning(
                "Rejected client_credentials token request for client '{ClientId}' sent without " +
                "acr_values: {AmbiguityReason} (AB#5058)", clientId, ambiguityReason);

            await auditService.StoreFailureAsync(AmbiguityAuditEventName,
                $"ClientId: {clientId} - Reason: {ambiguityReason}");

            return TenantBindingOutcome.Failed(Errors.InvalidRequest, AmbiguousTenantErrorDescription);
        }

        // Unambiguous: this client id exists in the system tenant only, so the directory that
        // authenticated it is also the tenant the token belongs to (unchanged AB#5032 behaviour).
        var systemTenantId = systemContext.TenantId;
        if (string.IsNullOrEmpty(systemTenantId))
        {
            logger.LogWarning(
                "Could not determine the issuing tenant for client_credentials client '{ClientId}'; " +
                "the token is issued without a tenant_id claim (AB#5032)", clientId);
            return TenantBindingOutcome.Unstamped();
        }

        return TenantBindingOutcome.Bound(systemTenantId);
    }

    /// <summary>
    ///     Decides whether the client id can be bound to exactly one tenant without the caller saying
    ///     which (AB#5058). Returns <c>null</c> when the binding is unambiguous, otherwise a short,
    ///     non-sensitive reason suitable for the audit log.
    /// </summary>
    /// <remarks>
    ///     Ordered cheapest-first: the two flags come from the client record the controller loaded
    ///     anyway; only a client that looks clean costs the extra mirror query. That query runs
    ///     exclusively on the no-<c>acr_values</c> path, so the added latency never touches the
    ///     callers that already name their tenant (mesh adapter, AI services, octo-cli).
    /// </remarks>
    private async Task<string?> DetermineTenantAmbiguityAsync(string clientId, RtClient? client)
    {
        if (client == null)
        {
            // Not registered in the directory the request resolved to. Nothing can have been
            // mirrored from here, and OpenIddict will have failed the client authentication anyway.
            return null;
        }

        if (client.AutoProvisionInChildTenants)
        {
            return "the client is flagged AutoProvisionInChildTenants, so the same client id and " +
                   "secret are provisioned into its child tenants";
        }

        if (!string.IsNullOrEmpty(client.ProvisionedByParentTenantId))
        {
            return $"the resolved client is itself a mirror provisioned by tenant " +
                   $"'{client.ProvisionedByParentTenantId}'";
        }

        var systemTenantId = systemContext.TenantId;
        if (string.IsNullOrEmpty(systemTenantId))
        {
            // Without a system tenant there is no mirror bookkeeping to consult — and nothing to
            // stamp either; ResolveAsync degrades to its "cannot determine" warning.
            return null;
        }

        try
        {
            var mirrors = await clientMirrorProvisioningService.GetMirrorsAsync(systemTenantId, clientId);
            if (mirrors.Count > 0)
            {
                // Covers a client whose AutoProvisionInChildTenants flag was switched off again:
                // the flag stops further mirroring, it does not retract the mirrors already made.
                return $"the client id is mirrored into {mirrors.Count} child tenant(s)";
            }
        }
        catch (Exception ex)
        {
            // Fail closed. The blast radius is limited to the already-ambiguous path (no acr_values),
            // and guessing "system tenant" here is exactly the escalation this check exists to stop.
            logger.LogError(ex,
                "Could not determine the mirror state of client '{ClientId}'; refusing the " +
                "client_credentials request that carried no acr_values (AB#5058)", clientId);
            return "the mirror state of the client id could not be determined";
        }

        return null;
    }

    /// <summary>
    ///     Logs the residual reach of a mirroring source that just obtained a system-tenant token
    ///     (AB#5058). Observation only — see the class remarks for why this case cannot be refused
    ///     without breaking the mirroring feature itself.
    /// </summary>
    private void WarnOnInstanceWideCredential(string clientId, RtClient? client, string tenantId)
    {
        if (client is not { AutoProvisionInChildTenants: true })
        {
            return;
        }

        if (!string.Equals(tenantId, systemContext.TenantId, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        logger.LogWarning(
            "Client '{ClientId}' obtained a system-tenant token although its credentials are " +
            "mirrored into child tenants — tenant_id='{TenantId}' states the requested target, not " +
            "the caller's provenance, and must not be used alone to authorize system-tenant " +
            "operations (AB#5058)", clientId, tenantId);
    }
}
