using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using IdentityModel;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     RFC 8693 Token Exchange <see cref="IExtensionGrantValidator" /> that mints a
///     <b>target-tenant (B)</b> bearer access token for an already-authenticated user, proven by
///     their current home-tenant (A) access token (AB#4338). It lets the MCP server obtain a B token
///     without a browser / credential prompt while re-resolving the user's roles in B — no privilege
///     leak.
/// </summary>
/// <remarks>
///     <para>
///         <b>The security linchpin.</b> The issued <see cref="GrantValidationResult" /> carries the
///         <b>B-shadow user's</b> <c>sub</c> (<c>xt_{A}_{user}</c>, created / found via
///         <see cref="ICrossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync" /> in B),
///         <b>never</b> the A user with a swapped <c>tenant_id</c>. Because the token is issued for
///         the B-shadow subject, <c>UserProfileService.GetProfileDataAsync</c> and
///         <c>OctoUserStore.GetRolesAsync</c> stamp <c>tenant_id=B</c>, B's <c>allowed_tenants</c>
///         and <b>B-resolved roles</b> automatically — the exact same claim path as a normal login.
///         A naive re-scope of the A token would leak A's roles into B and is rejected by design.
///     </para>
///     <para>
///         The sequence mirrors the browser tenant-switch flow in <c>AuthApiController</c>
///         (validate cross-tenant access → find-or-create the B-shadow user) but, instead of
///         signing in a cookie, returns a <see cref="GrantValidationResult" /> whose subject is the
///         B-shadow user so Duende issues the token for it.
///     </para>
///     <para>
///         Fail-closed at each step: an invalid / expired subject token, a missing target tenant, a
///         B tenant that is not wired into the request (defence against role resolution hitting the
///         wrong database), a non-ancestor relationship between A and B, or a failed shadow-user
///         provisioning each abort the exchange with an OAuth error and raise a failure audit event.
///     </para>
/// </remarks>
public class TenantExchangeGrantValidator(
    IValidationKeysStore validationKeysStore,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    ICrossTenantAuthenticationService crossTenantAuthService,
    ICrossTenantUserProvisioningService crossTenantUserProvisioningService,
    IHttpContextAccessor httpContextAccessor,
    IEventService events,
    ILogger<TenantExchangeGrantValidator> logger) : IExtensionGrantValidator
{
    /// <summary>The RFC 8693 grant type this validator handles.</summary>
    public const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>The RFC 8693 token type identifier for an access token.</summary>
    private const string AccessTokenTypeIdentifier = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>The authentication method recorded on the issued token for auditability.</summary>
    private const string AuthenticationMethod = "token_exchange";

    /// <inheritdoc />
    public string GrantType => TokenExchangeGrantType;

    /// <inheritdoc />
    public async Task ValidateAsync(ExtensionGrantValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var raw = context.Request.Raw;

        // (a) Validate the subject token (the caller's current A access token).
        var subjectToken = raw.Get(OidcConstants.TokenRequest.SubjectToken);
        var subjectTokenType = raw.Get(OidcConstants.TokenRequest.SubjectTokenType);

        if (string.IsNullOrEmpty(subjectToken))
        {
            context.Result = Error(TokenRequestErrors.InvalidRequest, "subject_token is required");
            return;
        }

        if (!string.IsNullOrEmpty(subjectTokenType) &&
            !string.Equals(subjectTokenType, AccessTokenTypeIdentifier, StringComparison.Ordinal))
        {
            context.Result = Error(TokenRequestErrors.InvalidRequest,
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token");
            return;
        }

        // Validate the subject token OUT of the target-tenant request context — signature + issuer +
        // lifetime only, ValidateAudience=false (as the whole platform does). Duende's
        // ITokenValidator.ValidateAccessTokenAsync runs checks bound to the CURRENT request tenant, which
        // here is the TARGET tenant B (resolved from acr_values) while the subject belongs to the SOURCE
        // tenant A — e.g. the A user does not exist in B yet — so it wrongly rejects with invalid_token.
        // Cross-tenant authorization is enforced separately below against the source tenant.
        var validationKeys = await validationKeysStore.GetValidationKeysAsync(cancellationToken);
        var handler = new JsonWebTokenHandler();
        var validation = await handler.ValidateTokenAsync(subjectToken, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/"),
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKeys = validationKeys.Select(k => k.Key)
        });
        if (!validation.IsValid)
        {
            logger.LogWarning("Token exchange rejected: subject_token invalid ({Error})",
                validation.Exception?.Message ?? "validation failed");
            context.Result = Error(TokenRequestErrors.InvalidGrant, "subject_token is invalid or expired");
            return;
        }

        var claims = validation.ClaimsIdentity.Claims.ToList();
        var sourceUserId = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value;
        var sourceTenantId = claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;
        var homeTenantId = claims.FirstOrDefault(c => c.Type == "home_tenant_id")?.Value;
        var userName = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.PreferredUserName)?.Value
                       ?? claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Name)?.Value;

        if (string.IsNullOrEmpty(sourceUserId) || string.IsNullOrEmpty(sourceTenantId))
        {
            logger.LogWarning(
                "Token exchange rejected: subject_token lacks sub or tenant_id (user context required)");
            context.Result = Error(TokenRequestErrors.InvalidGrant,
                "subject_token must carry a user subject and tenant_id");
            return;
        }

        // (b) Read the target tenant B from acr_values=tenant:{B}, and assert the request was wired
        //     to B by OidcTenantResolutionMiddleware. If the resolved tenant is NOT B, the shadow
        //     user and the roles would be resolved against the wrong database — fail closed.
        var targetTenantId = ParseTenantFromAcrValues(raw.Get(OidcConstants.AuthorizeRequest.AcrValues));
        if (string.IsNullOrEmpty(targetTenantId))
        {
            context.Result = Error(TokenRequestErrors.InvalidRequest,
                "acr_values=tenant:{targetTenantId} is required for token exchange");
            return;
        }

        var resolvedTenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(resolvedTenantId) ||
            !string.Equals(resolvedTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogError(
                "Token exchange rejected: request tenant '{ResolvedTenantId}' does not match requested target '{TargetTenantId}' — refusing to resolve roles against the wrong database",
                resolvedTenantId ?? "(none)", targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "target tenant not wired into request", cancellationToken);
            context.Result = Error(TokenRequestErrors.InvalidTarget,
                "target tenant could not be resolved for this request");
            return;
        }

        // (b2) Determine the effective SOURCE identity. A cross-tenant user (shadow username
        //      xt_{home}_{orig}, so the token carries home_tenant_id) must be exchanged from their HOME
        //      tenant — the common ancestor of all tenants they can reach. The current tenant_id is often
        //      a SIBLING of the target (both children of the home tenant) and thus NOT an ancestor of it,
        //      so exchanging from it would be wrongly denied by the ancestry gate. A direct user of the
        //      current tenant (no home_tenant_id, or home == current) keeps tenant_id + sub.
        var effectiveSourceTenantId = sourceTenantId;
        var effectiveSourceUserId = sourceUserId;
        if (!string.IsNullOrEmpty(homeTenantId) &&
            !string.Equals(homeTenantId, sourceTenantId, StringComparison.OrdinalIgnoreCase))
        {
            var shadowPrefix = $"xt_{homeTenantId}_";
            var originalUserName = !string.IsNullOrEmpty(userName) &&
                                   userName.StartsWith(shadowPrefix, StringComparison.OrdinalIgnoreCase)
                ? userName[shadowPrefix.Length..]
                : userName;

            var homeUserId = string.IsNullOrEmpty(originalUserName)
                ? null
                : await crossTenantAuthService.FindUserIdByNameInTenantAsync(homeTenantId, originalUserName);
            if (string.IsNullOrEmpty(homeUserId))
            {
                logger.LogWarning(
                    "Token exchange denied: could not resolve home identity (user '{OriginalUserName}') in home tenant '{HomeTenantId}' for subject '{SourceUserId}'",
                    originalUserName ?? "(none)", homeTenantId, sourceUserId);
                await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                    "home identity not resolvable", cancellationToken);
                context.Result = Error(TokenRequestErrors.UnauthorizedClient,
                    "cross-tenant access to the target tenant is denied");
                return;
            }

            effectiveSourceTenantId = homeTenantId;
            effectiveSourceUserId = homeUserId;
        }

        // (c) B-authorization gate: the (home) source tenant must be an ancestor of B and its user exists.
        var crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
            targetTenantId, effectiveSourceTenantId, effectiveSourceUserId);
        if (crossTenantResult == null)
        {
            logger.LogWarning(
                "Token exchange denied: user '{SourceUserId}' from tenant '{SourceTenantId}' may not access target tenant '{TargetTenantId}'",
                sourceUserId, sourceTenantId, targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "cross-tenant access denied", cancellationToken);
            context.Result = Error(TokenRequestErrors.UnauthorizedClient,
                "cross-tenant access to the target tenant is denied");
            return;
        }

        // (d) Find or create the B-shadow user (roles synced from RtExternalTenantUserMapping in B).
        var shadowUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
            crossTenantResult, targetTenantId);
        if (shadowUser == null)
        {
            logger.LogError(
                "Token exchange failed: could not provision the B-shadow user in tenant '{TargetTenantId}'",
                targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "shadow user provisioning failed", cancellationToken);
            context.Result = Error(TokenRequestErrors.InvalidGrant,
                "failed to provision the target-tenant user");
            return;
        }

        // Issue the token for the B-shadow user's sub. This is the linchpin: the per-tenant profile
        // and role stores key off THIS subject, so tenant_id=B + B-resolved roles are stamped
        // automatically — never A's roles under a swapped tenant_id.
        var shadowSubjectId = shadowUser.RtId.ToString();
        context.Result = new GrantValidationResult(
            subject: shadowSubjectId,
            authenticationMethod: AuthenticationMethod);

        logger.LogInformation(
            "Token exchange succeeded: user '{SourceUserId}' from tenant '{SourceTenantId}' exchanged into tenant '{TargetTenantId}' as shadow user '{ShadowRtId}'",
            sourceUserId, sourceTenantId, targetTenantId, shadowSubjectId);

        await events.RaiseAsync(new TokenExchangeSuccessEvent(
            sourceUserId, sourceTenantId, targetTenantId, shadowSubjectId), cancellationToken);
    }

    private async Task RaiseFailureAsync(string sourceUserId, string sourceTenantId, string targetTenantId,
        string reason, CancellationToken cancellationToken)
    {
        await events.RaiseAsync(new TokenExchangeFailureEvent(
            sourceUserId, sourceTenantId, targetTenantId, reason), cancellationToken);
    }

    private static GrantValidationResult Error(TokenRequestErrors error, string description) =>
        new(error, description);

    /// <summary>
    ///     Parses <c>tenant:{tenantId}</c> from a space-separated <c>acr_values</c> string.
    /// </summary>
    internal static string? ParseTenantFromAcrValues(string? acrValues)
    {
        if (string.IsNullOrEmpty(acrValues))
        {
            return null;
        }

        foreach (var value in acrValues.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (value.StartsWith("tenant:", StringComparison.OrdinalIgnoreCase))
            {
                var tenantId = value["tenant:".Length..];
                if (!string.IsNullOrEmpty(tenantId))
                {
                    return tenantId;
                }
            }
        }

        return null;
    }
}
