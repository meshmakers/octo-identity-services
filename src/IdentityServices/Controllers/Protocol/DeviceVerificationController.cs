using System.Collections.Immutable;
using System.Security.Claims;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Protocol;

/// <summary>
///     OpenIddict end-user verification endpoint for the device flow (AB#4993), replacing the
///     pre-migration interaction-service path of <c>DeviceApiController</c>. The Angular
///     device page (<c>/{tenantId}/device</c>) collects the user code and drives this endpoint via
///     XHR:
///     <list type="bullet">
///         <item><c>GET ?user_code=…</c> — validates the code and returns the consent context
///             (client, scopes) as JSON (same DTO the SPA consumed before).</item>
///         <item><c>POST</c> (form: <c>user_code</c>, optional <c>deny</c>,
///             <c>scopes_consented</c>, <c>remember_consent</c>) — completes or denies the
///             verification. The JSON result body is written by
///             <see cref="OctoDeviceVerificationResponseHandler" />.</item>
///     </list>
///     The approving session's subject must exist in the tenant the device code was wired to; otherwise
///     the approval is refused with <c>access_denied</c> (AB#7884). The former cross-tenant provisioning
///     branch here was unreachable (the session cookie is scoped to that tenant) and was removed;
///     cross-tenant device logins use a child-tenant session or the token exchange.
/// </summary>
[ApiController]
[Authorize]
[IgnoreAntiforgeryToken]
public class DeviceVerificationController(
    IOctoClientStore clientStore,
    IOctoResourceStore resourceStore,
    IOctoTokenClaimsService tokenClaimsService,
    IOpenIddictTokenManager tokenManager,
    UserManager<RtUser> userManager,
    ILogger<DeviceVerificationController> logger) : ControllerBase
{
    [HttpGet("~/connect/deviceverification")]
    [Produces("application/json")]
    public async Task<IActionResult> GetContext()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

        if (string.IsNullOrEmpty(request.UserCode))
        {
            return BadRequest("User code is required");
        }

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: not null } ||
            !await IsUserCodePendingAsync(result.Principal))
        {
            // Unknown, expired, already approved or denied: no consent dialog for it (AB#7090).
            return NotFound("Invalid or expired device code");
        }

        var clientId = result.Principal.GetClaim(Claims.ClientId) ?? request.ClientId;
        var client = clientId != null ? await clientStore.FindRtClientByIdAsync(clientId) : null;

        var (identityScopes, apiScopes) = await ResolveScopeItemsAsync(result.Principal.GetScopes());

        return Ok(new DeviceAuthorizationContextDto
        {
            UserCode = request.UserCode,
            ClientName = client?.ClientName ?? clientId,
            ClientUrl = client?.ClientUri,
            ClientLogoUrl = client?.LogoUri,
            IdentityScopes = identityScopes,
            ApiScopes = apiScopes,
            ConfirmUserCode = true
        });
    }

    [HttpPost("~/connect/deviceverification")]
    public async Task<IActionResult> Verify()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: not null } ||
            !await IsUserCodePendingAsync(result.Principal))
        {
            // A used or unknown code must answer invalid_token here, in the same JSON shape the
            // response handler writes (OctoDeviceVerificationResponseHandler). Neither Forbid (the
            // challenge handler needs an authenticated principal and throws for an unknown code) nor
            // SignIn (OpenIddict throws for a device code that is already authorized) can be used.
            return Ok(new
            {
                success = false,
                errorMessage = "Invalid or expired device code",
                error = Errors.InvalidToken
            });
        }

        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (string.Equals(form["deny"].FirstOrDefault(), "true", StringComparison.OrdinalIgnoreCase))
        {
            // A denied user code permanently rejects the pending device code — the polling
            // device must receive access_denied instead of polling forever on
            // authorization_pending.
            if (!string.IsNullOrEmpty(request.UserCode))
            {
                var userCodeToken = await tokenManager.FindByReferenceIdAsync(
                    request.UserCode, HttpContext.RequestAborted);
                if (userCodeToken != null)
                {
                    await tokenManager.TryRejectAsync(userCodeToken, HttpContext.RequestAborted);
                }
            }

            logger.LogInformation("Device authorization denied by user '{Subject}'",
                User.FindFirstValue(Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier));
            return ForbidWithError(Errors.AccessDenied, "The device authorization was denied.");
        }

        // The approving user must exist in the tenant this device code was wired to (HttpContext.Items via
        // OidcTenantResolutionMiddleware). AB#7884: no cross-tenant provisioning here any more.
        var tenantId = HttpContext.Items[InfrastructureCommon.TenantIdName] as string ?? "System";
        var user = await FindSessionUserAsync(tenantId);
        if (user == null)
        {
            return ForbidWithError(Errors.AccessDenied, "The signed-in user does not exist in this tenant.");
        }

        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        await tokenClaimsService.PopulateUserClaimsAsync(identity, user, tenantId);

        // Session-style claims for parity with interactive logins; the session id comes from
        // the cookie session (stamped by OctoTicketStore) so logout can address it. The authentication
        // methods are the session's (AB#7804): a sign-in with a second factor stamps amr=mfa, and a device
        // token without it could never be exchanged into a child tenant by a 2FA user (octo-cli -ttid).
        var sessionMethods = User.FindAll(Claims.AuthenticationMethodReference)
            .Select(c => c.Value).Where(v => !string.IsNullOrEmpty(v)).Distinct(StringComparer.Ordinal).ToImmutableArray();
        identity.SetClaims(Claims.AuthenticationMethodReference, sessionMethods.IsEmpty ? ["pwd"] : sessionMethods);
        identity.SetClaim("idp", "local");
        var sessionId = User.FindFirstValue("sid");
        if (!string.IsNullOrEmpty(sessionId))
        {
            identity.SetClaim("sid", sessionId);
        }
        identity.AddClaim(new Claim(Claims.AuthenticationTime,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));

        // Honor the scope subset the user consented to (defaults to everything requested).
        var requestedScopes = result.Principal.GetScopes();
        var consented = form["scopes_consented"].Where(s => !string.IsNullOrEmpty(s)).Select(s => s!).ToList();
        var grantedScopes = consented.Count > 0
            ? requestedScopes.Intersect(consented).ToImmutableArray()
            : requestedScopes;

        identity.SetScopes(grantedScopes);
        identity.SetResources(await tokenClaimsService.ResolveAudiencesAsync(grantedScopes));

        var deviceClientId = result.Principal.GetClaim(Claims.ClientId) ?? request.ClientId;
        var deviceClient = deviceClientId != null
            ? await clientStore.FindRtClientByIdAsync(deviceClientId)
            : null;
        identity.SetDestinations(
            OctoClaimsDestinations.ForClient(deviceClient?.AlwaysIncludeUserClaimsInIdToken == true));

        logger.LogInformation(
            "Device authorization approved by user '{UserName}' for client '{ClientId}' in tenant '{TenantId}'",
            user.UserName, result.Principal.GetClaim(Claims.ClientId) ?? "unknown", tenantId);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    ///     True while the user code token of the authenticated verification request is still
    ///     <c>valid</c>; approved, denied, redeemed or expired codes are not pending any more.
    ///     OpenIddict keeps authenticating such a code on the verification endpoint, so the
    ///     controller has to check the token status itself.
    /// </summary>
    private async Task<bool> IsUserCodePendingAsync(ClaimsPrincipal principal)
    {
        var tokenId = principal.GetTokenId();
        if (string.IsNullOrEmpty(tokenId))
        {
            return false;
        }

        var token = await tokenManager.FindByIdAsync(tokenId, HttpContext.RequestAborted);
        return token != null &&
               await tokenManager.HasStatusAsync(token, Statuses.Valid, HttpContext.RequestAborted);
    }

    /// <summary>
    ///     The session user in the request tenant, or <c>null</c> (with a warning) when the session's subject does not
    ///     exist there (AB#7884).
    /// </summary>
    private async Task<RtUser?> FindSessionUserAsync(string tenantId)
    {
        var subjectId = User.FindFirstValue(Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = subjectId == null ? null : await userManager.FindByIdAsync(subjectId);
        if (user == null)
        {
            logger.LogWarning(
                "Device authorization refused: the session subject '{SubjectId}' does not exist in tenant '{TenantId}'",
                subjectId ?? "(none)", tenantId);
        }

        return user;
    }

    private async Task<(List<ScopeItemDto> IdentityScopes, List<ScopeItemDto> ApiScopes)>
        ResolveScopeItemsAsync(IEnumerable<string> scopes)
    {
        var identityScopes = new List<ScopeItemDto>();
        var apiScopes = new List<ScopeItemDto>();

        foreach (var scope in scopes)
        {
            if (string.Equals(scope, Scopes.OfflineAccess, StringComparison.Ordinal))
            {
                identityScopes.Add(new ScopeItemDto
                {
                    Name = Scopes.OfflineAccess,
                    DisplayName = "Offline Access",
                    Description = "Access to your applications when you are offline",
                    Emphasize = true,
                    Required = false,
                    Checked = true
                });
                continue;
            }

            var identityResource = await resourceStore.GetIdentityResourceByNameAsync(scope);
            if (identityResource != null)
            {
                identityScopes.Add(new ScopeItemDto
                {
                    Name = identityResource.Name,
                    DisplayName = identityResource.DisplayName ?? identityResource.Name,
                    Description = identityResource.Description,
                    Emphasize = identityResource.IsEmphasized,
                    Required = identityResource.IsRequired,
                    Checked = true
                });
                continue;
            }

            var apiScope = await resourceStore.GetApiScopeByNameAsync(scope);
            if (apiScope != null)
            {
                apiScopes.Add(new ScopeItemDto
                {
                    Name = apiScope.Name,
                    DisplayName = apiScope.DisplayName ?? apiScope.Name,
                    Description = apiScope.Description,
                    Emphasize = apiScope.IsEmphasized,
                    Required = apiScope.IsRequired,
                    Checked = true
                });
            }
        }

        return (identityScopes, apiScopes);
    }

    private IActionResult ForbidWithError(string error, string description) => Forbid(
        new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        }),
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
