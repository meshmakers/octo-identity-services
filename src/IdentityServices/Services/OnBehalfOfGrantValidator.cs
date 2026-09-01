using System.Security.Claims;
using Duende.IdentityServer;
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
///     Delegation ("on-behalf-of") <see cref="IExtensionGrantValidator" /> for
///     <c>grant_type=urn:meshmakers:params:oauth:grant-type:on-behalf-of</c> (AB#5026). A
///     <b>service-account client</b> authenticates with its own client credentials <b>and</b>
///     presents a user's access token as <c>subject_token</c>; the issued token then runs on the
///     <b>user's</b> <c>sub</c> but carries only the <b>intersection</b> of the service account's
///     and the user's roles, plus an <c>act</c> claim naming the service account.
/// </summary>
/// <remarks>
///     <para>
///         <b>This class is a thin protocol adapter.</b> It reads the raw token-request parameters,
///         validates the subject token and the tenant wiring, and hands the decision to
///         <see cref="IDelegatedIdentityResolver" /> — a service free of any Duende type. The policy
///         therefore survives the planned move off Duende (Epic 4989) and is unit-testable without
///         protocol mocks.
///     </para>
///     <para>
///         <b>Own grant-type URN, not the RFC 8693 one.</b> See
///         <see cref="DelegationConstants.OnBehalfOfGrantType" /> for the reasoning: Duende allows
///         one validator per grant type, and the only client carrying the token-exchange grant today
///         is a public client with no secret — a shared URN would hand it delegation for free.
///     </para>
///     <para>
///         <b>Same tenant only (v1).</b> The tenant in <c>acr_values</c>, the <c>tenant_id</c> of the
///         subject token and the tenant the request was wired to must all be the same; any
///         divergence fails closed with <c>invalid_target</c>. Cross-tenant delegation would have to
///         answer which tenant's role catalogue the intersection is taken in and how the service
///         account proves reach into the other tenant — that is v2, and the cross-tenant
///         <b>exchange</b> grant (<c>TenantExchangeGrantValidator</c>) is the supported way to move
///         a user identity across tenants in the meantime.
///     </para>
///     <para>
///         <b>No refresh tokens — enforced, not merely discouraged.</b> A request that asks for
///         <c>offline_access</c> is rejected with <c>invalid_scope</c>, because the role
///         intersection is computed <b>here, at issuance</b>, while a <c>refresh_token</c> request
///         rebuilds the access token from the persisted grant without ever re-entering this
///         validator. The intersection would freeze at first issuance and a role revoked on either
///         side would keep working for the refresh token's whole lifetime. See the check in
///         <see cref="ValidateAsync" /> for why the rejection lives in this validator rather than in
///         client configuration or in a post-hoc manipulation of the request.
///     </para>
///     <para>
///         <b>Empty intersection is not an error.</b> The token is issued and simply carries no
///         <c>role</c> claim, so every role-gated consumer fails closed. This keeps the failure
///         visible where authorization is actually enforced instead of turning a role
///         misconfiguration into an opaque token-endpoint error.
///     </para>
///     <para>
///         <b>Client enablement.</b> Duende rejects the request before this validator runs unless the
///         calling client lists <see cref="DelegationConstants.OnBehalfOfGrantType" /> in its
///         <c>AllowedGrantTypes</c>. Seeding the actual pipeline service account (client, secret and
///         roles) is AB#5027 — this work item ships the grant only.
///     </para>
/// </remarks>
public class OnBehalfOfGrantValidator(
    IValidationKeysStore validationKeysStore,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    IDelegatedIdentityResolver delegatedIdentityResolver,
    IHttpContextAccessor httpContextAccessor,
    IEventService events,
    ILogger<OnBehalfOfGrantValidator> logger) : IExtensionGrantValidator
{
    /// <summary>The RFC 8693 token type identifier for an access token.</summary>
    private const string AccessTokenTypeIdentifier = "urn:ietf:params:oauth:token-type:access_token";

    /// <inheritdoc />
    public string GrantType => DelegationConstants.OnBehalfOfGrantType;

    /// <inheritdoc />
    public async Task ValidateAsync(ExtensionGrantValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var raw = context.Request.Raw;

        // The service account is already authenticated by Duende's client-credential validation
        // before any extension grant validator runs — client_id here is proven, not asserted.
        var actorClientId = context.Request.ClientId;
        if (string.IsNullOrEmpty(actorClientId))
        {
            logger.LogError("Delegation rejected: the token request carries no authenticated client");
            context.Result = Error(TokenRequestErrors.InvalidClient,
                "the delegating service account must be an authenticated client");
            return;
        }

        // (a) No refresh tokens for delegated identities — fail closed BY CONSTRUCTION.
        //
        // The role intersection below is computed at ISSUANCE. A later grant_type=refresh_token
        // request rebuilds the access token from the persisted grant; extension grant validators are
        // by design not re-entered for it (there is no subject_token to re-validate and no hook to
        // recompute anything), so the intersection would be frozen at first issuance and a role
        // revoked on EITHER side — service account or user — would keep working until the refresh
        // token expired. That is precisely the authority creep this grant exists to prevent.
        //
        // Why the rejection belongs *here*, in the validator:
        //   * Duende mints a refresh token iff ValidatedResources.Resources.OfflineAccess is set,
        //     and that flag is only ever derived from a requested offline_access scope. Scope /
        //     resource validation runs BEFORE the extension grant validator, so refusing the request
        //     at this point is sufficient — nothing downstream can put offline_access back.
        //   * GrantValidationResult has no "do not issue a refresh token" switch, so the result
        //     object cannot express the constraint; the request has to be refused instead.
        //   * Silently clearing ValidatedResources.Resources.OfflineAccess would also work
        //     mechanically, but it would hand the integrator a token response missing the
        //     refresh_token they asked for, with nothing explaining why. An explained error is the
        //     difference between a five-minute fix and an afternoon of guessing.
        //   * Relying on AllowOfflineAccess=false on every delegating client is a seeding
        //     convention, not an invariant — any operator (or AB#5027) can flip it back on.
        //
        // The raw scope parameter is what the client actually sent and is available before any I/O;
        // ValidatedResources is checked too because that is the exact flag Duende acts on, and it
        // stays correct if a future Duende version populates it from somewhere else.
        if (RequestsOfflineAccess(raw.Get(OidcConstants.TokenRequest.Scope), context.Request.ValidatedResources))
        {
            var requestedTenantId =
                TenantExchangeGrantValidator.ParseTenantFromAcrValues(
                    raw.Get(OidcConstants.AuthorizeRequest.AcrValues)) ?? "(unknown)";

            logger.LogWarning(
                "Delegation rejected: service account '{ClientId}' requested offline_access for tenant '{TenantId}' — delegated tokens are never refreshable",
                actorClientId, requestedTenantId);
            // The subject token has deliberately not been validated yet, so its `sub` is not
            // trustworthy enough to put into the audit trail.
            await RaiseFailureAsync(actorClientId, "(unknown)", requestedTenantId,
                "offline_access is not supported for delegation", cancellationToken);

            context.Result = Error(TokenRequestErrors.InvalidScope,
                "offline_access is not supported for delegation: the effective roles of a delegated token are the intersection of the service account's and the user's roles, computed when the token is issued. A refresh_token request rebuilds the token from the stored grant without re-evaluating that intersection, so a role revoked on either side would remain in force. Request a new token with the on-behalf-of grant instead.");
            return;
        }

        // (b) Validate the subject token (the user's access token).
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

        // Validated OUT of the request context — signature + issuer + lifetime only,
        // ValidateAudience=false (as the whole platform does). Duende's ITokenValidator runs checks
        // bound to the current request's client/resources; the subject token was minted for a
        // different client entirely, so it would be rejected for reasons that have nothing to do
        // with whether the user's proof of identity is genuine. Same rationale as
        // TenantExchangeGrantValidator.
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
            logger.LogWarning("Delegation rejected: subject_token invalid ({Error})",
                validation.Exception?.Message ?? "validation failed");
            context.Result = Error(TokenRequestErrors.InvalidGrant, "subject_token is invalid or expired");
            return;
        }

        var claims = validation.ClaimsIdentity.Claims.ToList();
        var userSubjectId = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value;
        var subjectTenantId = claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;

        if (string.IsNullOrEmpty(userSubjectId) || string.IsNullOrEmpty(subjectTenantId))
        {
            logger.LogWarning(
                "Delegation rejected: subject_token lacks sub or tenant_id (user context required)");
            context.Result = Error(TokenRequestErrors.InvalidGrant,
                "subject_token must carry a user subject and tenant_id");
            return;
        }

        // (c) Same-tenant gate. acr_values, the subject token's tenant_id and the tenant the request
        //     was actually wired to must agree — otherwise the client and user lookups below (and
        //     with them the role intersection) would run against a different database than the
        //     caller asked for. Fail closed; cross-tenant delegation is v2 (see class remarks).
        var targetTenantId =
            TenantExchangeGrantValidator.ParseTenantFromAcrValues(raw.Get(OidcConstants.AuthorizeRequest.AcrValues));
        if (string.IsNullOrEmpty(targetTenantId))
        {
            context.Result = Error(TokenRequestErrors.InvalidRequest,
                "acr_values=tenant:{tenantId} is required for delegation");
            return;
        }

        var resolvedTenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(resolvedTenantId) ||
            !string.Equals(resolvedTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogError(
                "Delegation rejected: request tenant '{ResolvedTenantId}' does not match requested tenant '{TargetTenantId}' — refusing to resolve roles against the wrong database",
                resolvedTenantId ?? "(none)", targetTenantId);
            await RaiseFailureAsync(actorClientId, userSubjectId, targetTenantId,
                "tenant not wired into request", cancellationToken);
            context.Result = Error(TokenRequestErrors.InvalidTarget,
                "the tenant could not be resolved for this request");
            return;
        }

        if (!string.Equals(subjectTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning(
                "Delegation rejected: subject_token belongs to tenant '{SubjectTenantId}' but delegation was requested for tenant '{TargetTenantId}' — cross-tenant delegation is not supported (v1)",
                subjectTenantId, targetTenantId);
            await RaiseFailureAsync(actorClientId, userSubjectId, targetTenantId,
                "cross-tenant delegation is not supported", cancellationToken);
            context.Result = Error(TokenRequestErrors.InvalidTarget,
                "the subject_token belongs to a different tenant; delegation is same-tenant only");
            return;
        }

        // (d) Resolve the delegation: role intersection, in the Duende-free policy service.
        var delegation = await delegatedIdentityResolver.ResolveAsync(
            actorClientId, userSubjectId, cancellationToken);

        if (!delegation.IsGranted)
        {
            logger.LogWarning(
                "Delegation denied for service account '{ClientId}' acting for user '{UserSubjectId}' in tenant '{TenantId}': {Reason}",
                actorClientId, userSubjectId, targetTenantId, delegation.DenialReason);
            await RaiseFailureAsync(actorClientId, userSubjectId, targetTenantId,
                delegation.DenialReason.ToString(), cancellationToken);

            context.Result = delegation.DenialReason switch
            {
                DelegationDenialReason.ServiceAccountNotFound => Error(TokenRequestErrors.InvalidClient,
                    "the service account is not provisioned in this tenant"),
                _ => Error(TokenRequestErrors.InvalidGrant,
                    "the subject_token does not identify a user in this tenant")
            };
            return;
        }

        // (e) Issue for the USER's sub, carrying the intersection + act. UserProfileService detects
        //     the act claim on this subject and replaces the user's naturally resolved role claims
        //     with the intersection — without that step the intersection would be a no-op, because
        //     AddAspNetIdentity + ProfileService<RtUser> resolve the user's FULL role set from
        //     OctoUserStore for whatever sub the token runs on.
        context.Result = new GrantValidationResult(
            subject: userSubjectId,
            authenticationMethod: DelegationConstants.AuthenticationMethod,
            claims: BuildDelegationClaims(actorClientId, delegation.EffectiveRoleNames));

        logger.LogInformation(
            "Delegation succeeded: service account '{ClientId}' acting for user '{UserSubjectId}' in tenant '{TenantId}' with {RoleCount} effective role(s)",
            actorClientId, userSubjectId, targetTenantId, delegation.EffectiveRoleNames.Count);

        await events.RaiseAsync(new DelegationSuccessEvent(
            actorClientId, userSubjectId, targetTenantId, delegation.EffectiveRoleNames.Count), cancellationToken);
    }

    /// <summary>
    ///     Builds the claims placed on the delegated <see cref="GrantValidationResult" />'s subject:
    ///     the <c>act</c> actor claim plus one internal delegated-role claim per effective role.
    /// </summary>
    /// <remarks>
    ///     The role intersection travels as <see cref="DelegationConstants.DelegatedRoleClaimType" />
    ///     rather than as <c>role</c>, so <c>UserProfileService</c> can tell it apart from the role
    ///     claims the base profile service resolves for the same user. An empty intersection yields
    ///     just the <c>act</c> claim — a token with no roles, which is the intended fail-closed shape.
    /// </remarks>
    internal static IReadOnlyList<Claim> BuildDelegationClaims(
        string actorClientId, IReadOnlySet<string> effectiveRoleNames)
    {
        var claims = new List<Claim>(effectiveRoleNames.Count + 1)
        {
            new(DelegationConstants.ActClaimType, actorClientId)
        };

        claims.AddRange(effectiveRoleNames
            .Select(roleName => new Claim(DelegationConstants.DelegatedRoleClaimType, roleName)));

        return claims;
    }

    /// <summary>
    ///     Decides whether the token request asks for a refresh token, i.e. whether
    ///     <c>offline_access</c> is among the requested scopes.
    /// </summary>
    /// <param name="rawScope">
    ///     The raw, space-separated <c>scope</c> form parameter — what the client actually sent, and
    ///     readable without any I/O.
    /// </param>
    /// <param name="validatedResources">
    ///     The resources Duende resolved for this request before invoking the extension grant, if
    ///     any. Its <c>OfflineAccess</c> flag is the value Duende itself acts on when deciding to
    ///     mint a refresh token, so it is checked as well; it can be <c>null</c> when the request
    ///     carried no <c>scope</c> parameter at all.
    /// </param>
    /// <remarks>
    ///     Scope tokens are case-sensitive per RFC 6749 §3.3, hence the ordinal comparison.
    /// </remarks>
    internal static bool RequestsOfflineAccess(string? rawScope, ResourceValidationResult? validatedResources)
    {
        if (validatedResources?.Resources.OfflineAccess == true)
        {
            return true;
        }

        return rawScope?
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(IdentityServerConstants.StandardScopes.OfflineAccess, StringComparer.Ordinal) == true;
    }

    private async Task RaiseFailureAsync(string actorClientId, string userSubjectId, string tenantId,
        string reason, CancellationToken cancellationToken)
    {
        await events.RaiseAsync(new DelegationFailureEvent(
            actorClientId, userSubjectId, tenantId, reason), cancellationToken);
    }

    private static GrantValidationResult Error(TokenRequestErrors error, string description) =>
        new(error, description);
}
