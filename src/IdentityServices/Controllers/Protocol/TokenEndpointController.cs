using System.Security.Claims;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.Services;
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
///         <item><c>client_credentials</c>: the issuing <c>tenant_id</c> via
///             <see cref="ClientCredentialsTenantProcessor" /> (AB#5032, refusing an ambiguous
///             binding per AB#5058) plus the effective client role claims (AB#4183) — both parity
///             with the former <c>ClientCredentialsRoleTokenValidator</c>.</item>
///         <item>RFC 8693 token exchange: cross-tenant gate via
///             <see cref="TenantExchangeProcessor" />, token minted on the B-shadow subject.</item>
///         <item><c>authorization_code</c> / <c>refresh_token</c> /
///             <c>urn:ietf:params:oauth:grant-type:device_code</c>: the stored principal is
///             refreshed — user existence/lockout re-checked, roles and tenant claims re-resolved
///             on every redemption (our clients set <c>UpdateAccessTokenClaimsOnRefresh</c>, so
///             role/tenant changes must take effect without a re-login).</item>
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
    OnBehalfOfProcessor onBehalfOfProcessor,
    ImpersonationProcessor impersonationProcessor,
    ClientCredentialsTenantProcessor clientCredentialsTenantProcessor,
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

        if (string.Equals(request.GrantType, DelegationConstants.OnBehalfOfGrantType, StringComparison.Ordinal))
        {
            return await HandleOnBehalfOfAsync(request);
        }

        if (string.Equals(request.GrantType, ImpersonationConstants.ImpersonationGrantType, StringComparison.Ordinal))
        {
            return await HandleImpersonationAsync(request);
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

        // Which tenant is this token for (AB#5032)? Refuses the request outright when the client id
        // is mirrored and the caller sent no acr_values, instead of guessing the system tenant
        // (AB#5058). Runs BEFORE any claim is composed, so a refused request can never carry a
        // guessed tenant_id.
        var tenantBinding = await clientCredentialsTenantProcessor.ResolveAsync(request.ClientId!, client);
        if (tenantBinding.Error != null)
        {
            return ForbidWithError(tenantBinding.Error,
                tenantBinding.ErrorDescription ?? "the issuing tenant cannot be determined");
        }

        var identity = CreateIdentity();

        // OpenIddict requires a subject on the sign-in principal; client_credentials access
        // tokens must NOT carry sub (TenantAuthorizationMiddleware identifies service tokens by
        // its absence) — OctoAccessTokenShapeHandler strips it at token generation.
        identity.SetClaim(Claims.Subject, request.ClientId);

        // The issuing tenant (AB#5032) — stamped BEFORE the roles, so a client without any role
        // still carries it. This is the claim the platform's tenant gate authorizes on; without it
        // TenantAuthorizationMiddleware has nothing to check a service token against.
        if (tenantBinding.TenantId != null)
        {
            identity.SetClaim(OctoClaimTypes.TenantId, tenantBinding.TenantId);
        }

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

    private async Task<IActionResult> HandleOnBehalfOfAsync(OpenIddictRequest request)
    {
        var outcome = await onBehalfOfProcessor.ProcessAsync(
            request.ClientId,
            // AB#5114: an authorized actor (MayActAs edge) may name the service account it
            // delegates through instead of authenticating as the SA itself.
            (string?)request[ImpersonationConstants.RequestedClientIdParameter],
            (string?)request[Parameters.SubjectToken],
            (string?)request[Parameters.SubjectTokenType],
            (string?)request["acr_values"],
            request.GetScopes(),
            HttpContext.RequestAborted);

        if (outcome.Error != null || outcome.UserSubjectId == null)
        {
            return ForbidWithError(outcome.Error ?? Errors.InvalidGrant,
                outcome.ErrorDescription ?? "delegation failed");
        }

        var user = await userManager.FindByIdAsync(outcome.UserSubjectId);
        if (user == null || !await signInManager.CanSignInAsync(user))
        {
            return ForbidWithError(Errors.InvalidGrant,
                "the subject_token does not identify a user in this tenant");
        }

        // The load-bearing half of the delegation grant: the user claims are populated normally
        // (which resolves the user's FULL role set), then the naturally resolved role claims are
        // REPLACED by the service-account ∩ user intersection. Without this replacement the
        // delegation would silently grant the user's full authority. An empty intersection removes
        // every role claim and adds none back — the token is issued but authorizes nothing, so
        // role-gated consumers fail closed.
        var identity = CreateIdentity();
        await tokenClaimsService.PopulateUserClaimsAsync(identity, user, outcome.TenantId!);

        // act names the service account so consumers and the audit trail can tell a delegated
        // token apart from one the user obtained themselves (flat client_id string, v1 shape).
        // With the AB#5114 extension this is the SA the delegation ran THROUGH — never the actor
        // that authenticated: downstream consumers keep seeing the identity that acted.
        OnBehalfOfProcessor.ApplyDelegationClaims(identity, outcome.ServiceAccountClientId!,
            outcome.EffectiveRoleNames!);
        identity.SetClaim(Claims.AuthenticationMethodReference, DelegationConstants.AuthenticationMethod);

        // Never a refresh token for delegated identities (the processor already rejected explicit
        // offline_access requests; this keeps implicit grants out too).
        var scopes = request.GetScopes().Remove(Scopes.OfflineAccess);
        identity.SetScopes(scopes);
        identity.SetResources(await tokenClaimsService.ResolveAudiencesAsync(scopes));
        identity.SetDestinations(OctoClaimsDestinations.Resolve);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private async Task<IActionResult> HandleImpersonationAsync(OpenIddictRequest request)
    {
        var outcome = await impersonationProcessor.ProcessAsync(
            request.ClientId,
            (string?)request[ImpersonationConstants.RequestedClientIdParameter],
            (string?)request["acr_values"],
            request.GetScopes(),
            HttpContext.RequestAborted);

        if (outcome.Error != null || outcome.TargetClientId == null)
        {
            return ForbidWithError(outcome.Error ?? Errors.InvalidGrant,
                outcome.ErrorDescription ?? "impersonation failed");
        }

        // The issued token is client-credentials-shaped FOR THE TARGET: sub is set to the target's
        // client id purely because OpenIddict requires a subject on the sign-in principal —
        // OctoAccessTokenShapeHandler re-stamps client_id to this value and strips sub, exactly
        // mirroring the client_credentials handling (a service token is recognized platform-wide
        // by the ABSENCE of sub).
        var identity = CreateIdentity();
        identity.SetClaim(Claims.Subject, outcome.TargetClientId);

        // The issuing tenant — stamped BEFORE the roles, like client_credentials, so a target
        // without any role still carries the claim TenantAuthorizationMiddleware gates on.
        identity.SetClaim(OctoClaimTypes.TenantId, outcome.TenantId);

        // The TARGET's effective roles (direct + group-inherited) plus act = the ACTOR — the only
        // trace of the caller on the issued token.
        ImpersonationProcessor.ApplyImpersonationClaims(identity, request.ClientId!,
            outcome.EffectiveRoleNames!);
        identity.SetClaim(Claims.AuthenticationMethodReference, ImpersonationConstants.AuthenticationMethod);

        // Never a refresh token for impersonated identities (the processor already rejected
        // explicit offline_access requests; this keeps implicit grants out too).
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
        // our interactive clients set UpdateAccessTokenClaimsOnRefresh, so redemption must
        // re-resolve them), while the session claims (amr/idp/auth_time/sid) survive from the
        // original authentication.
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
