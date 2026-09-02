using System.Security.Claims;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
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
///     OpenIddict token endpoint passthrough (AB#4990/AB#4992): builds the principal for every
///     grant OpenIddict cannot complete on its own and re-validates redeemed user grants.
///     <list type="bullet">
///         <item><c>client_credentials</c>: effective client role claims (AB#4183 parity with the
///             former <c>ClientCredentialsRoleTokenValidator</c>).</item>
///         <item>RFC 8693 token exchange: cross-tenant gate via
///             <see cref="TenantExchangeProcessor" />, token minted on the B-shadow subject.</item>
///         <item><c>authorization_code</c> / <c>refresh_token</c> /
///             <c>urn:ietf:params:oauth:grant-type:device_code</c>: the stored principal is
///             refreshed — user existence/lockout re-checked, roles and tenant claims re-resolved
///             (Duende parity: our clients set <c>UpdateAccessTokenClaimsOnRefresh</c>).</item>
///     </list>
///     OpenIddict has already authenticated the client (secret validation via
///     <c>OctoApplicationManager</c>) and validated grant/scope permissions before this action runs.
/// </summary>
[ApiController]
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public class TokenEndpointController(
    IOctoClientStore clientStore,
    IOctoTokenClaimsService tokenClaimsService,
    TenantExchangeProcessor tenantExchangeProcessor,
    UserManager<RtUser> userManager,
    SignInManager<RtUser> signInManager,
    ILogger<TokenEndpointController> logger) : ControllerBase
{
    [HttpPost("~/connect/token")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

        if (request.IsClientCredentialsGrantType())
        {
            return await HandleClientCredentialsAsync(request);
        }

        if (request.IsTokenExchangeGrantType())
        {
            return await HandleTokenExchangeAsync(request);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType() ||
            request.IsDeviceCodeGrantType())
        {
            return await HandleUserGrantAsync(request);
        }

        return ForbidWithError(Errors.UnsupportedGrantType, "The specified grant type is not supported.");
    }

    private async Task<IActionResult> HandleClientCredentialsAsync(OpenIddictRequest request)
    {
        // The client is already authenticated by OpenIddict at this point.
        var client = await clientStore.FindRtClientByIdAsync(request.ClientId!);
        if (client == null)
        {
            return ForbidWithError(Errors.InvalidClient, "The client application cannot be found.");
        }

        var identity = CreateIdentity();

        // OpenIddict requires a subject on the sign-in principal; Duende-parity access tokens
        // must NOT carry it — OctoAccessTokenShapeHandler strips it at token generation.
        identity.SetClaim(Claims.Subject, request.ClientId);

        // Effective client roles (direct AssignedRole + group-inherited), unprefixed (AB#4183).
        await tokenClaimsService.PopulateClientClaimsAsync(identity, client);

        var scopes = request.GetScopes();
        identity.SetScopes(scopes);
        identity.SetResources(await tokenClaimsService.ResolveAudiencesAsync(scopes));
        identity.SetDestinations(OctoClaimsDestinations.Resolve);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> HandleTokenExchangeAsync(OpenIddictRequest request)
    {
        var outcome = await tenantExchangeProcessor.ProcessAsync(
            (string?)request[Parameters.SubjectToken],
            (string?)request[Parameters.SubjectTokenType],
            (string?)request["acr_values"],
            HttpContext.RequestAborted);

        if (outcome.Error != null || outcome.ShadowUser == null)
        {
            return ForbidWithError(outcome.Error ?? Errors.InvalidGrant,
                outcome.ErrorDescription ?? "token exchange failed");
        }

        var identity = CreateIdentity();

        // The linchpin: claims are built for the B-shadow subject against the B tenant repository
        // (wired into the request by OidcTenantResolutionMiddleware) — B roles, tenant_id=B.
        await tokenClaimsService.PopulateUserClaimsAsync(identity, outcome.ShadowUser, outcome.TargetTenantId!);
        identity.SetClaim(Claims.AuthenticationMethodReference, TenantExchangeProcessor.AuthenticationMethod);

        // v1 semantics: exchanged tokens are short-lived and re-exchanged from the still-valid A
        // token — never grant offline_access, so no refresh token is issued.
        var scopes = request.GetScopes().Remove(Scopes.OfflineAccess);
        identity.SetScopes(scopes);
        identity.SetResources(await tokenClaimsService.ResolveAudiencesAsync(scopes));
        identity.SetDestinations(OctoClaimsDestinations.Resolve);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> HandleUserGrantAsync(OpenIddictRequest request)
    {
        // Retrieve the principal stored in the authorization code / refresh token / device code.
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: not null })
        {
            return ForbidWithError(Errors.InvalidGrant, "The token is no longer valid.");
        }

        var storedPrincipal = result.Principal;
        var subject = storedPrincipal.GetClaim(Claims.Subject);
        var loginTenantId = storedPrincipal.GetClaim(OctoClaimTypes.TenantId) ?? string.Empty;

        var user = subject != null ? await userManager.FindByIdAsync(subject) : null;
        if (user == null || !await signInManager.CanSignInAsync(user))
        {
            logger.LogWarning("Grant redemption rejected: user '{Subject}' no longer exists or cannot sign in",
                subject ?? "(none)");
            return ForbidWithError(Errors.InvalidGrant, "The user is no longer allowed to sign in.");
        }

        // Rebuild the user claims fresh (roles / allowed_tenants may have changed since issuance —
        // Duende parity: our interactive clients set UpdateAccessTokenClaimsOnRefresh), while the
        // session claims (amr/idp/auth_time/sid) survive from the original authentication.
        var identity = CreateIdentity();
        await tokenClaimsService.PopulateUserClaimsAsync(identity, user, loginTenantId);
        CopySessionClaims(storedPrincipal, identity);

        var scopes = storedPrincipal.GetScopes();
        identity.SetScopes(scopes);
        identity.SetResources(await tokenClaimsService.ResolveAudiencesAsync(scopes));

        // Honor the client's AlwaysIncludeUserClaimsInIdToken on redemption/refresh too —
        // the Studio reads its identity, tenant and roles from the (refreshed) id_token.
        var redeemingClient = request.ClientId != null
            ? await clientStore.FindRtClientByIdAsync(request.ClientId)
            : null;
        identity.SetDestinations(
            OctoClaimsDestinations.ForClient(redeemingClient?.AlwaysIncludeUserClaimsInIdToken == true));

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static ClaimsIdentity CreateIdentity() => new(
        TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

    private static void CopySessionClaims(ClaimsPrincipal source, ClaimsIdentity target)
    {
        foreach (var type in (string[])
                 [
                     Claims.AuthenticationMethodReference, "idp", Claims.AuthenticationTime, "sid"
                 ])
        {
            foreach (var claim in source.Claims.Where(c => c.Type == type))
            {
                if (!target.HasClaim(c => c.Type == type && c.Value == claim.Value))
                {
                    target.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType));
                }
            }
        }
    }

    private IActionResult ForbidWithError(string error, string description) => Forbid(
        new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        }),
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
