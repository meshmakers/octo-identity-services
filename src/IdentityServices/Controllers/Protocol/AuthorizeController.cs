using System.Collections.Immutable;
using System.Security.Claims;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Protocol;

/// <summary>
///     OpenIddict authorization endpoint passthrough (AB#4990/AB#4995): drives login and consent
///     through the Angular SPA pages and signs in the token principal. Replaces Duende's
///     <c>UserInteraction</c> redirects (and most of <c>TenantLoginRedirectMiddleware</c>): the
///     login/consent redirects are issued tenant-scoped directly, using the tenant that
///     <c>OidcTenantResolutionMiddleware</c> wired into the request.
/// </summary>
[ApiController]
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public class AuthorizeController(
    IOctoClientStore clientStore,
    IOctoTokenClaimsService tokenClaimsService,
    IOctoInteractionService interactionService,
    UserManager<RtUser> userManager,
    SignInManager<RtUser> signInManager,
    ILogger<AuthorizeController> logger) : ControllerBase
{
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

        var tenantId = HttpContext.Items[InfrastructureCommon.TenantIdName] as string ?? "System";

        // Authenticate the tenant-scoped application cookie (never challenge here — WE decide
        // where the login UI lives).
        var cookieResult = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var isAuthenticated = cookieResult is { Succeeded: true, Principal: not null };

        // prompt=none must never render UI: fail with login_required instead (OIDC core).
        if (!isAuthenticated || request.HasPromptValue(PromptValues.Login))
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user is not logged in."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // Redirect to the tenant's login page; strip prompt=login from the returnUrl so the
            // flow does not loop after authentication (Duende behavior).
            var returnUrl = Request.PathBase + Request.Path + QueryString.Create(
                Request.HasFormContentType
                    ? (await Request.ReadFormAsync()).Where(p => p.Key != Parameters.Prompt)
                        .ToDictionary(p => p.Key, p => p.Value.LastOrDefault())
                    : Request.Query.Where(p => p.Key != Parameters.Prompt)
                        .ToDictionary(p => p.Key, p => p.Value.LastOrDefault()));

            return Redirect($"/{tenantId}/login?ReturnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        var subject = cookieResult.Principal!.FindFirstValue(Claims.Subject)
                      ?? cookieResult.Principal!.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = subject != null ? await userManager.FindByIdAsync(subject) : null;
        if (user == null || !await signInManager.CanSignInAsync(user))
        {
            // Session references a user that no longer exists (deleted, cross-tenant edge) —
            // force a fresh login.
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            var returnUrl = Request.PathBase + Request.Path + Request.QueryString;
            return Redirect($"/{tenantId}/login?ReturnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        var client = await clientStore.FindRtClientByIdAsync(request.ClientId!);
        if (client is not { Enabled: true })
        {
            return Forbid(
                new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The client application cannot be found."
                }),
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var requestedScopes = request.GetScopes();
        var grantedScopes = requestedScopes;

        // Consent gate (Duende parity: RequireConsent is false for all first-party clients).
        if (client.RequireConsent == true)
        {
            var consentOutcome = await EvaluateConsentAsync(client, subject!, requestedScopes);
            if (consentOutcome.Denied)
            {
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user denied the authorization request."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (!consentOutcome.Granted)
            {
                if (request.HasPromptValue(PromptValues.None))
                {
                    return Forbid(
                        new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "User consent is required."
                        }),
                        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                var returnUrl = Request.PathBase + Request.Path + Request.QueryString;
                return Redirect($"/{tenantId}/consent?returnUrl={Uri.EscapeDataString(returnUrl)}");
            }

            if (consentOutcome.GrantedScopes is { Count: > 0 })
            {
                grantedScopes = requestedScopes.Intersect(consentOutcome.GrantedScopes).ToImmutableArray();
            }
        }

        // Build the token principal: fresh user/tenant/role claims plus the session claims of the
        // cookie authentication (amr/idp/auth_time from the login, sid from the ticket store).
        var identity = new ClaimsIdentity(
            TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        await tokenClaimsService.PopulateUserClaimsAsync(identity, user, tenantId);
        CopySessionClaims(cookieResult, identity);

        identity.SetScopes(grantedScopes);
        identity.SetResources(await tokenClaimsService.ResolveAudiencesAsync(grantedScopes));
        identity.SetDestinations(OctoClaimsDestinations.Resolve);

        logger.LogDebug("Authorize request approved for client '{ClientId}', user '{Subject}', tenant '{TenantId}'",
            request.ClientId, subject, tenantId);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<(bool Granted, bool Denied, IReadOnlyList<string>? GrantedScopes)> EvaluateConsentAsync(
        RtClient client, string subject, ImmutableArray<string> requestedScopes)
    {
        // 1. One-time decision round-tripped from the consent page (octo_consent parameter).
        var protectedDecision = Request.Query[OctoInteractionService.ConsentParameterName].FirstOrDefault();
        var decision = interactionService.GetConsentDecision(protectedDecision, subject, client.ClientId);
        if (decision != null)
        {
            return decision.Denied
                ? (false, true, null)
                : (true, false, decision.ScopesConsented);
        }

        // 2. Remembered consent: a permanent authorization covering all requested scopes.
        var remembered = await interactionService.FindRememberedConsentAsync(
            subject, client.ClientId, requestedScopes.ToList());
        if (remembered != null)
        {
            return (true, false, null);
        }

        return (false, false, null);
    }

    private static void CopySessionClaims(AuthenticateResult cookieResult, ClaimsIdentity target)
    {
        var principal = cookieResult.Principal!;

        foreach (var type in (string[])[Claims.AuthenticationMethodReference, "idp", "sid"])
        {
            foreach (var claim in principal.Claims.Where(c => c.Type == type))
            {
                if (!target.HasClaim(c => c.Type == type && c.Value == claim.Value))
                {
                    target.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType));
                }
            }
        }

        // amr/idp defaults for local password logins that did not stamp them explicitly.
        if (!target.HasClaim(c => c.Type == Claims.AuthenticationMethodReference))
        {
            target.AddClaim(new Claim(Claims.AuthenticationMethodReference, "pwd"));
        }

        if (!target.HasClaim(c => c.Type == "idp"))
        {
            target.AddClaim(new Claim("idp", "local"));
        }

        // auth_time from the cookie issue time (Duende parity: time of the interactive login).
        // OpenIddict requires the numeric claim value type.
        var authTime = (cookieResult.Properties?.IssuedUtc ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        target.AddClaim(new Claim(Claims.AuthenticationTime, authTime.ToString(),
            ClaimValueTypes.Integer64));
    }
}
