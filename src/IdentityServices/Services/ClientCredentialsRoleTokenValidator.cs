using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using IdentityModel;
using IdentityServerPersistence.SystemStores;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Injects the resolved role claims of a <c>Client</c> into the access token minted for the
///     <c>client_credentials</c> grant. The roles are resolved from the client's direct
///     <c>AssignedRole</c> associations plus any roles inherited from group memberships, so a
///     machine-to-machine caller carries the <b>same</b> <c>role</c> claim shape as a user token
///     (AB#4183). Consumers such as the <c>FromHttpRequest</c> trigger node and the
///     octo-common-services authorization middleware therefore need no client-specific code path.
/// </summary>
/// <remarks>
///     Duende prefixes claims added via <see cref="ValidatedRequest.ClientClaims" /> with the
///     client's <c>ClientClaimsPrefix</c> (default <c>client_</c>). To emit unprefixed <c>role</c>
///     claims that match user tokens, the prefix is cleared on the per-request client model — this
///     mutation affects only the token issued for this single request, never the persisted client
///     configuration.
/// </remarks>
public class ClientCredentialsRoleTokenValidator(
    IOctoClientStore clientStore,
    IClientRoleStore clientRoleStore,
    ILogger<ClientCredentialsRoleTokenValidator> logger) : ICustomTokenRequestValidator
{
    public async Task ValidateAsync(CustomTokenRequestValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var request = context.Result?.ValidatedRequest;
        if (request?.Client == null)
        {
            return;
        }

        // Only the client_credentials grant — other flows (authorization_code, refresh_token,
        // device_code, password) already carry user role claims via the profile service.
        if (!string.Equals(request.GrantType, GrantType.ClientCredentials, StringComparison.Ordinal))
        {
            return;
        }

        var clientId = request.ClientId;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return;
        }

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
}
