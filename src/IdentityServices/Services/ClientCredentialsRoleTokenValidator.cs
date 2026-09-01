using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using IdentityModel;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Enriches the access token minted for the <c>client_credentials</c> grant with
///     <list type="bullet">
///         <item>
///             the <c>tenant_id</c> of the tenant the token was issued for (AB#5032), and
///         </item>
///         <item>
///             the resolved role claims of the <c>Client</c>, from its direct <c>AssignedRole</c>
///             associations plus any roles inherited from group memberships (AB#4183).
///         </item>
///     </list>
///     so that a machine-to-machine caller carries the <b>same</b> claim shape as a user token.
///     Consumers such as the <c>FromHttpRequest</c> trigger node and the octo-common-services
///     authorization middleware therefore need no client-specific code path.
///     It also <b>rejects</b> a request whose issuing tenant cannot be determined (AB#5058).
/// </summary>
/// <remarks>
///     <para>
///         <b>Why <c>tenant_id</c> matters (AB#5032).</b> <c>TenantAuthorizationMiddleware</c> in
///         octo-common-services used to skip its tenant check for every token without a <c>sub</c>
///         claim — i.e. for every client-credentials token — because such a token carried nothing to
///         check it against. Together with <c>ValidateAudience = false</c> that let any
///         client-credentials client of this authority address any tenant. Stamping the issuing
///         tenant makes the check possible; the middleware then narrows the exemption behind its own
///         staged switch.
///     </para>
///     <para>
///         The tenant is the one the request was resolved to by
///         <c>OidcTenantResolutionMiddleware</c> (<c>acr_values=tenant:{tenantId}</c> on
///         <c>/connect/token</c>) — which is by construction the tenant whose database the client was
///         loaded from.
///     </para>
///     <para>
///         🔴 <b>Why "no <c>acr_values</c>" is no longer silently the system tenant (AB#5058).</b>
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
///         rather than guessed at, and the refusal is audited
///         (<see cref="ClientCredentialsTenantAmbiguityEvent" />). Only an <b>unambiguous</b> client
///         id — the overwhelmingly common case, see the caller inventory in
///         <c>docs/authentication.md</c> — is still stamped with the system tenant, so no caller that
///         legitimately omits <c>acr_values</c> today changes behaviour.
///     </para>
///     <para>
///         ⚠️ <b>Residual, and deliberately not closed here.</b> Because a mirror shares the parent's
///         secret, whoever holds a mirror's credentials also holds the parent's, and can therefore
///         ask for the system tenant <i>explicitly</i> with <c>acr_values=tenant:{systemTenant}</c>.
///         No check at the token endpoint can tell those two callers apart — the credential really is
///         instance-wide by construction of the mirroring feature. This validator therefore logs a
///         warning whenever a mirroring source obtains a system-tenant token, and AB#5055 must not
///         treat <c>tenant_id == systemTenant</c> on a client-credentials token as proof of
///         provenance on its own. Closing it for real needs per-tenant mirror secrets.
///     </para>
///     <para>
///         Duende prefixes claims added via <see cref="ValidatedRequest.ClientClaims" /> with the
///         client's <c>ClientClaimsPrefix</c> (default <c>client_</c>). To emit unprefixed
///         <c>tenant_id</c> / <c>role</c> claims that match user tokens, the prefix is cleared on the
///         per-request client model — this mutation affects only the token issued for this single
///         request, never the persisted client configuration. Note that clearing it also un-prefixes
///         any claim configured on the client itself; that was already the case for every client with
///         roles and is what platform consumers expect.
///     </para>
/// </remarks>
public class ClientCredentialsRoleTokenValidator(
    IOctoClientStore clientStore,
    IClientRoleStore clientRoleStore,
    IClientMirrorProvisioningService clientMirrorProvisioningService,
    IEventService events,
    IHttpContextAccessor httpContextAccessor,
    ISystemContext systemContext,
    ILogger<ClientCredentialsRoleTokenValidator> logger) : ICustomTokenRequestValidator
{
    internal const string TenantIdClaimType = "tenant_id";

    /// <summary>
    ///     Error description returned for a request whose issuing tenant is ambiguous (AB#5058). It
    ///     names the remedy, so an integrator who hits it is not left guessing — the same rationale
    ///     as the <c>offline_access</c> refusal in <c>OnBehalfOfGrantValidator</c>.
    /// </summary>
    internal const string AmbiguousTenantErrorDescription =
        "acr_values=tenant:{tenantId} is required for this client: its client id exists in more " +
        "than one tenant, so the issuing tenant cannot be determined from the request.";

    public async Task ValidateAsync(CustomTokenRequestValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var request = context.Result?.ValidatedRequest;
        if (request?.Client == null)
        {
            return;
        }

        // Only the client_credentials grant — other flows (authorization_code, refresh_token,
        // device_code, password) already carry user tenant_id and role claims via the profile service.
        if (!string.Equals(request.GrantType, GrantType.ClientCredentials, StringComparison.Ordinal))
        {
            return;
        }

        var clientId = request.ClientId;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return;
        }

        // Resolved once and reused: the ambiguity decision (AB#5058) and the role branch (AB#4183)
        // both need the persisted client, and the store hits the tenant repository on every call.
        var rtClient = await clientStore.FindRtClientByIdAsync(clientId);

        // For client_credentials, OidcTenantResolutionMiddleware writes HttpContext.Items only from
        // acr_values — so a value here means the caller named its tenant explicitly.
        var tenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(tenantId))
        {
            var ambiguityReason = await DetermineTenantAmbiguityAsync(clientId, rtClient);
            if (ambiguityReason != null)
            {
                await RejectAmbiguousRequestAsync(context, clientId, ambiguityReason, cancellationToken);
                return;
            }

            // Unambiguous: this client id exists in the system tenant only, so the directory that
            // authenticated it is also the tenant the token belongs to (unchanged AB#5032 behaviour).
            tenantId = systemContext.TenantId;
        }
        else
        {
            WarnOnInstanceWideCredential(clientId, rtClient, tenantId);
        }

        AddTenantIdClaim(request, clientId, tenantId);

        if (rtClient == null)
        {
            return;
        }

        var roleNames = await clientRoleStore.GetEffectiveRoleNamesAsync(rtClient.RtId);
        if (roleNames.Count == 0)
        {
            return;
        }

        // Emit unprefixed role claims (see remarks): clear the prefix on this request's client model.
        request.Client.ClientClaimsPrefix = null;

        foreach (var roleName in roleNames)
        {
            var alreadyPresent = request.ClientClaims.Any(
                c => c.Type == JwtClaimTypes.Role && string.Equals(c.Value, roleName, StringComparison.Ordinal));
            if (!alreadyPresent)
            {
                request.ClientClaims.Add(new Claim(JwtClaimTypes.Role, roleName));
            }
        }

        logger.LogInformation(
            "Injected {RoleCount} role claim(s) into client_credentials token for client '{ClientId}'",
            roleNames.Count, clientId);
    }

    /// <summary>
    ///     Decides whether the client id can be bound to exactly one tenant without the caller saying
    ///     which (AB#5058). Returns <c>null</c> when the binding is unambiguous, otherwise a short,
    ///     non-sensitive reason suitable for the audit log.
    /// </summary>
    /// <remarks>
    ///     Ordered cheapest-first: the two flags come from the client record that was loaded anyway;
    ///     only a client that looks clean costs the extra mirror query. That query runs exclusively on
    ///     the no-<c>acr_values</c> path, so the added latency never touches the callers that already
    ///     name their tenant (mesh adapter, AI services, octo-cli).
    /// </remarks>
    private async Task<string?> DetermineTenantAmbiguityAsync(string clientId, RtClient? rtClient)
    {
        if (rtClient == null)
        {
            // Not registered in the directory the request resolved to. Nothing can have been
            // mirrored from here, and Duende will have failed the client authentication anyway.
            return null;
        }

        if (rtClient.AutoProvisionInChildTenants)
        {
            return "the client is flagged AutoProvisionInChildTenants, so the same client id and " +
                   "secret are provisioned into its child tenants";
        }

        if (!string.IsNullOrEmpty(rtClient.ProvisionedByParentTenantId))
        {
            return $"the resolved client is itself a mirror provisioned by tenant " +
                   $"'{rtClient.ProvisionedByParentTenantId}'";
        }

        var systemTenantId = systemContext.TenantId;
        if (string.IsNullOrEmpty(systemTenantId))
        {
            // Without a system tenant there is no mirror bookkeeping to consult — and nothing to
            // stamp either; AddTenantIdClaim degrades to its "cannot determine" warning below.
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
    ///     Refuses the token request. Duende's <c>TokenRequestValidator</c> honours an
    ///     <c>IsError</c> result from a custom validator and aborts before the token is minted.
    /// </summary>
    private async Task RejectAmbiguousRequestAsync(CustomTokenRequestValidationContext context,
        string clientId, string reason, CancellationToken cancellationToken)
    {
        logger.LogWarning(
            "Rejected client_credentials token request for client '{ClientId}' sent without " +
            "acr_values: {AmbiguityReason} (AB#5058)", clientId, reason);

        await events.RaiseAsync(new ClientCredentialsTenantAmbiguityEvent(clientId, reason), cancellationToken);

        context.Result!.IsError = true;
        context.Result.Error = OidcConstants.TokenErrors.InvalidRequest;
        context.Result.ErrorDescription = AmbiguousTenantErrorDescription;
    }

    /// <summary>
    ///     Logs the residual reach of a mirroring source that just obtained a system-tenant token
    ///     (AB#5058). Observation only — see the class remarks for why this case cannot be refused
    ///     without breaking the mirroring feature itself.
    /// </summary>
    private void WarnOnInstanceWideCredential(string clientId, RtClient? rtClient, string tenantId)
    {
        if (rtClient is not { AutoProvisionInChildTenants: true })
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

    /// <summary>
    ///     Stamps the issuing tenant onto the token (AB#5032). Idempotent: a <c>tenant_id</c> claim
    ///     already configured on the client is left alone rather than duplicated — a duplicate would
    ///     turn the consumer's single-valued lookup into an arbitrary pick.
    /// </summary>
    private void AddTenantIdClaim(ValidatedTokenRequest request, string clientId, string? tenantId)
    {
        if (string.IsNullOrEmpty(tenantId))
        {
            logger.LogWarning(
                "Could not determine the issuing tenant for client_credentials client '{ClientId}'; " +
                "the token is issued without a tenant_id claim (AB#5032)", clientId);
            return;
        }

        if (request.ClientClaims.Any(c => c.Type == TenantIdClaimType))
        {
            return;
        }

        request.Client.ClientClaimsPrefix = null;
        request.ClientClaims.Add(new Claim(TenantIdClaimType, tenantId));

        logger.LogDebug("Stamped tenant_id '{TenantId}' on client_credentials token for client '{ClientId}'",
            tenantId, clientId);
    }
}
