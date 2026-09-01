using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using IdentityModel;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;

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
///         loaded from. When no <c>acr_values</c> was sent the client lookup falls back to the system
///         tenant, so that is what is stamped: the claim always states the truth about which
///         directory authenticated the client.
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
    IHttpContextAccessor httpContextAccessor,
    ISystemContext systemContext,
    ILogger<ClientCredentialsRoleTokenValidator> logger) : ICustomTokenRequestValidator
{
    internal const string TenantIdClaimType = "tenant_id";

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

        AddTenantIdClaim(request, clientId);

        var rtClient = await clientStore.FindRtClientByIdAsync(clientId);
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
    ///     Stamps the issuing tenant onto the token (AB#5032). Idempotent: a <c>tenant_id</c> claim
    ///     already configured on the client is left alone rather than duplicated — a duplicate would
    ///     turn the consumer's single-valued lookup into an arbitrary pick.
    /// </summary>
    private void AddTenantIdClaim(ValidatedTokenRequest request, string clientId)
    {
        var tenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(tenantId))
        {
            // No acr_values on /connect/token: the client store resolved against the system tenant,
            // so that is the tenant this token belongs to.
            tenantId = systemContext.TenantId;
        }

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
