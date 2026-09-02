using System.Collections.Immutable;
using System.Security.Claims;
using IdentityServerPersistence.Services;
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
///     Duende <c>IDeviceFlowInteractionService</c> path of <c>DeviceApiController</c>. The Angular
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
///     Cross-tenant approval parity: when the cookie user does not exist in the request tenant
///     (session from a parent tenant), the B-shadow user is provisioned and signed in before the
///     device code is bound — otherwise redemption would fail with <c>invalid_grant</c>.
/// </summary>
[ApiController]
[Authorize]
[IgnoreAntiforgeryToken]
public class DeviceVerificationController(
    IOctoClientStore clientStore,
    IOctoResourceStore resourceStore,
    IOctoTokenClaimsService tokenClaimsService,
    IOpenIddictTokenManager tokenManager,
    ICrossTenantAuthenticationService crossTenantAuthService,
    ICrossTenantUserProvisioningService crossTenantUserProvisioningService,
    IOctoIdentityProviderStore identityProviderStore,
    UserManager<RtUser> userManager,
    SignInManager<RtUser> signInManager,
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
        if (result is not { Succeeded: true, Principal: not null })
        {
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
        if (result is not { Succeeded: true, Principal: not null })
        {
            return ForbidWithError(Errors.InvalidToken, "Invalid or expired device code");
        }

        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (string.Equals(form["deny"].FirstOrDefault(), "true", StringComparison.OrdinalIgnoreCase))
        {
            // Duende parity: a denied user code permanently rejects the pending device code —
            // the polling device receives access_denied instead of authorization_pending.
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

        // Cross-tenant approval: the cookie user must exist in the tenant this device code was
        // wired to (HttpContext.Items via OidcTenantResolutionMiddleware) — provision the shadow
        // user first when the session belongs to a parent tenant (ported from DeviceApiController).
        var tenantId = HttpContext.Items[InfrastructureCommon.TenantIdName] as string ?? "System";
        var user = await ResolveOrProvisionUserAsync(tenantId);
        if (user == null)
        {
            return ForbidWithError(Errors.AccessDenied, "Cross-tenant access denied");
        }

        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        await tokenClaimsService.PopulateUserClaimsAsync(identity, user, tenantId);

        // Session-style claims for parity with interactive logins; the session id comes from
        // the cookie session (stamped by OctoTicketStore) so logout can address it.
        identity.SetClaim(Claims.AuthenticationMethodReference, "pwd");
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
    ///     Returns the cookie user in the request tenant, provisioning the cross-tenant shadow
    ///     user (and re-signing-in) when the session subject only exists in a parent tenant.
    /// </summary>
    private async Task<RtUser?> ResolveOrProvisionUserAsync(string tenantId)
    {
        var subjectId = User.FindFirstValue(Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (subjectId == null)
        {
            return null;
        }

        var existingUser = await userManager.FindByIdAsync(subjectId);
        if (existingUser != null)
        {
            return existingUser;
        }

        logger.LogInformation(
            "Device authorization: user '{SubjectId}' not found in tenant '{TenantId}', attempting cross-tenant provisioning",
            subjectId, tenantId);

        var identityProviders = (await identityProviderStore.GetAllAsync())
            .OfType<RtOctoTenantIdentityProvider>()
            .Where(p => p.IsEnabled)
            .ToList();

        CrossTenantAuthResult? crossTenantResult = null;
        foreach (var provider in identityProviders)
        {
            crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
                tenantId, provider.ParentTenantId!, subjectId);
            if (crossTenantResult != null)
            {
                break;
            }
        }

        if (crossTenantResult == null)
        {
            logger.LogWarning(
                "Cross-tenant access denied for device authorization: user '{SubjectId}' in tenant '{TenantId}'",
                subjectId, tenantId);
            return null;
        }

        var localUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
            crossTenantResult, tenantId);
        if (localUser == null)
        {
            return null;
        }

        // Re-sign-in as the local shadow user so follow-up requests run on a subject that
        // exists in the target tenant's database.
        await signInManager.SignInAsync(localUser, isPersistent: false);

        logger.LogInformation(
            "Cross-tenant device authorization: provisioned user '{UserName}' in tenant '{TenantId}'",
            localUser.UserName, tenantId);
        return localUser;
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
