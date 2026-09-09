using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Delegation ("on-behalf-of") grant processor for
///     <c>grant_type=urn:meshmakers:params:oauth:grant-type:on-behalf-of</c> (AB#5026), ported
///     from the pre-migration extension-grant validator: a <b>service-account client</b>
///     authenticates with its own client credentials <b>and</b> presents a user's access token as
///     <c>subject_token</c>; the issued token then runs on the <b>user's</b> <c>sub</c> but
///     carries only the <b>intersection</b> of the service account's and the user's roles, plus an
///     <c>act</c> claim naming the service account.
/// </summary>
/// <remarks>
///     <para>
///         <b>This class is a thin protocol adapter.</b> It validates the subject token and the
///         tenant wiring and hands the decision to <see cref="IDelegatedIdentityResolver" /> —
///         the protocol-free policy service. <c>TokenEndpointController</c> turns the outcome into
///         the issued principal: the user's claims are populated normally, then the naturally
///         resolved <c>role</c> claims are REPLACED by the intersection — without that step the
///         delegation would silently grant the user's full authority.
///     </para>
///     <para>
///         <b>Own grant-type URN, not the RFC 8693 one</b> — see
///         <see cref="DelegationConstants.OnBehalfOfGrantType" />: a shared URN would hand every
///         token-exchange-enabled client (today a secretless public client) delegation for free.
///     </para>
///     <para>
///         <b>Same tenant only (v1).</b> The tenant in <c>acr_values</c>, the <c>tenant_id</c> of
///         the subject token and the tenant the request was wired to must all agree; any divergence
///         fails closed with <c>invalid_target</c>. Cross-tenant identity movement is what the
///         RFC 8693 exchange grant (<see cref="TenantExchangeProcessor" />) is for.
///     </para>
///     <para>
///         <b>No refresh tokens — enforced, not merely discouraged.</b> A request asking for
///         <c>offline_access</c> is rejected with <c>invalid_scope</c>: the role intersection is
///         computed at ISSUANCE, while a refresh would rebuild the token from the stored principal
///         without re-entering this processor — a role revoked on either side would keep working
///         for the refresh token's whole lifetime.
///     </para>
///     <para>
///         <b>Empty intersection is not an error.</b> The token is issued and simply carries no
///         <c>role</c> claim, so every role-gated consumer fails closed — the failure stays
///         visible where authorization is enforced instead of becoming an opaque token error.
///     </para>
///     <para>
///         <b>AB#5114 extension: delegation without the service account's secret.</b> When the
///         request carries <c>requested_client_id</c> naming a service account that is NOT the
///         authenticated client itself, the authenticated client is treated as an <b>actor</b>
///         (typically the adapter's own AB#5072 chart client) and is authorized against the
///         explicit <c>System.Identity/MayActAs</c> edge actor→service-account. Everything else is
///         byte-identical to plain on-behalf-of: same subject-token validation, same same-tenant
///         rule, same offline_access rejection, intersection = <b>SA roles ∩ user roles</b> (never
///         the actor's roles — the actor's authority contributes nothing), <c>act</c> = the SA's
///         client id (not the actor — downstream consumers keep seeing the identity that acted,
///         which is the SA the actor became). An absent <c>requested_client_id</c> — or one naming
///         the authenticated client itself — keeps today's semantics untouched.
///     </para>
/// </remarks>
public class OnBehalfOfProcessor(
    IOptionsMonitor<OpenIddictServerOptions> serverOptions,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    IDelegatedIdentityResolver delegatedIdentityResolver,
    IImpersonatedIdentityResolver impersonatedIdentityResolver,
    IHttpContextAccessor httpContextAccessor,
    IIdentityAuditService auditService,
    ILogger<OnBehalfOfProcessor> logger)
{
    /// <summary>The RFC 8693 token type identifier for an access token.</summary>
    private const string AccessTokenTypeIdentifier = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>Outcome of a delegation attempt: either the delegated identity or an OAuth error.</summary>
    public sealed record DelegationOutcome
    {
        public string? UserSubjectId { get; init; }
        public string? TenantId { get; init; }
        public IReadOnlySet<string>? EffectiveRoleNames { get; init; }

        /// <summary>
        ///     The service account the delegation ran through — the client id the <c>act</c> claim
        ///     must name. Equals the authenticated client for plain on-behalf-of; equals
        ///     <c>requested_client_id</c> when an authorized actor delegated through a service
        ///     account it holds a <c>MayActAs</c> edge to (AB#5114).
        /// </summary>
        public string? ServiceAccountClientId { get; init; }

        public string? Error { get; init; }
        public string? ErrorDescription { get; init; }

        public static DelegationOutcome Failed(string error, string description) =>
            new() { Error = error, ErrorDescription = description };

        public static DelegationOutcome Succeeded(string userSubjectId, string tenantId,
            IReadOnlySet<string> effectiveRoleNames, string serviceAccountClientId) =>
            new()
            {
                UserSubjectId = userSubjectId, TenantId = tenantId, EffectiveRoleNames = effectiveRoleNames,
                ServiceAccountClientId = serviceAccountClientId
            };
    }

    /// <summary>Validates the delegation request and resolves the role intersection.</summary>
    /// <param name="actorClientId">The already-authenticated client id (the service account itself, or an AB#5114 actor).</param>
    /// <param name="requestedClientId">
    ///     Optional <c>requested_client_id</c> naming the service account to delegate through
    ///     (AB#5114). <c>null</c>, empty or equal to <paramref name="actorClientId" /> keeps the
    ///     original semantics: the authenticated client IS the service account.
    /// </param>
    /// <param name="subjectToken">The user's access token.</param>
    /// <param name="subjectTokenType">The RFC 8693 subject_token_type, if provided.</param>
    /// <param name="acrValues">The raw acr_values parameter carrying <c>tenant:{tenantId}</c>.</param>
    /// <param name="requestedScopes">The scopes the client requested.</param>
    public async Task<DelegationOutcome> ProcessAsync(
        string? actorClientId, string? requestedClientId, string? subjectToken, string? subjectTokenType,
        string? acrValues, IReadOnlyCollection<string> requestedScopes,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(actorClientId))
        {
            logger.LogError("Delegation rejected: the token request carries no authenticated client");
            return DelegationOutcome.Failed(Errors.InvalidClient,
                "the delegating service account must be an authenticated client");
        }

        // (a) No refresh tokens for delegated identities — fail closed BY CONSTRUCTION. The role
        //     intersection below is computed at issuance; a refresh_token redemption rebuilds the
        //     token without re-entering this processor, freezing the intersection until expiry.
        if (requestedScopes.Contains(Scopes.OfflineAccess, StringComparer.Ordinal))
        {
            var requestedTenantId = TenantExchangeProcessor.ParseTenantFromAcrValues(acrValues) ?? "(unknown)";
            logger.LogWarning(
                "Delegation rejected: service account '{ClientId}' requested offline_access for tenant '{TenantId}' — delegated tokens are never refreshable",
                actorClientId, requestedTenantId);
            // The subject token has deliberately not been validated yet, so its sub is not
            // trustworthy enough to put into the audit trail.
            await RaiseFailureAsync(actorClientId, "(unknown)", requestedTenantId,
                "offline_access is not supported for delegation");

            return DelegationOutcome.Failed(Errors.InvalidScope,
                "offline_access is not supported for delegation: the effective roles of a delegated token are the intersection of the service account's and the user's roles, computed when the token is issued. A refresh_token request rebuilds the token from the stored grant without re-evaluating that intersection, so a role revoked on either side would remain in force. Request a new token with the on-behalf-of grant instead.");
        }

        // (b) Validate the subject token (the user's access token): signature + issuer + lifetime,
        //     ValidateAudience=false (platform-wide convention) — the token was minted for a
        //     different client entirely; what matters is that the proof of identity is genuine.
        if (string.IsNullOrEmpty(subjectToken))
        {
            return DelegationOutcome.Failed(Errors.InvalidRequest, "subject_token is required");
        }

        if (!string.IsNullOrEmpty(subjectTokenType) &&
            !string.Equals(subjectTokenType, AccessTokenTypeIdentifier, StringComparison.Ordinal))
        {
            return DelegationOutcome.Failed(Errors.InvalidRequest,
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token");
        }

        var signingKeys = serverOptions.CurrentValue.SigningCredentials
            .Select(c => c.Key)
            .ToList();
        var handler = new JsonWebTokenHandler();
        var validation = await handler.ValidateTokenAsync(subjectToken, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/"),
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKeys = signingKeys
        });
        if (!validation.IsValid)
        {
            logger.LogWarning("Delegation rejected: subject_token invalid ({Error})",
                validation.Exception?.Message ?? "validation failed");
            return DelegationOutcome.Failed(Errors.InvalidGrant, "subject_token is invalid or expired");
        }

        var claims = validation.ClaimsIdentity.Claims.ToList();
        var userSubjectId = claims.FirstOrDefault(c => c.Type == Claims.Subject)?.Value;
        var subjectTenantId = claims.FirstOrDefault(c => c.Type == OctoClaimTypes.TenantId)?.Value;

        if (string.IsNullOrEmpty(userSubjectId) || string.IsNullOrEmpty(subjectTenantId))
        {
            logger.LogWarning(
                "Delegation rejected: subject_token lacks sub or tenant_id (user context required)");
            return DelegationOutcome.Failed(Errors.InvalidGrant,
                "subject_token must carry a user subject and tenant_id");
        }

        // (c) Same-tenant gate: acr_values, the subject token's tenant_id and the tenant the
        //     request was wired to must agree — otherwise the client and user lookups below (and
        //     with them the role intersection) would run against a different database than the
        //     caller asked for. Fail closed; cross-tenant delegation is v2.
        var targetTenantId = TenantExchangeProcessor.ParseTenantFromAcrValues(acrValues);
        if (string.IsNullOrEmpty(targetTenantId))
        {
            return DelegationOutcome.Failed(Errors.InvalidRequest,
                "acr_values=tenant:{tenantId} is required for delegation");
        }

        var resolvedTenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(resolvedTenantId) ||
            !string.Equals(resolvedTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogError(
                "Delegation rejected: request tenant '{ResolvedTenantId}' does not match requested tenant '{TargetTenantId}' — refusing to resolve roles against the wrong database",
                resolvedTenantId ?? "(none)", targetTenantId);
            await RaiseFailureAsync(actorClientId, userSubjectId, targetTenantId,
                "tenant not wired into request");
            return DelegationOutcome.Failed(Errors.InvalidTarget,
                "the tenant could not be resolved for this request");
        }

        if (!string.Equals(subjectTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning(
                "Delegation rejected: subject_token belongs to tenant '{SubjectTenantId}' but delegation was requested for tenant '{TargetTenantId}' — cross-tenant delegation is not supported (v1)",
                subjectTenantId, targetTenantId);
            await RaiseFailureAsync(actorClientId, userSubjectId, targetTenantId,
                "cross-tenant delegation is not supported");
            return DelegationOutcome.Failed(Errors.InvalidTarget,
                "the subject_token belongs to a different tenant; delegation is same-tenant only");
        }

        // (c2) AB#5114: when requested_client_id names a service account other than the
        //      authenticated client, the authenticated client is an ACTOR and must hold the
        //      explicit MayActAs edge actor→SA in this tenant. The gate runs AFTER the tenant
        //      wiring checks by necessity — the edge lives in the tenant database. A
        //      requested_client_id naming the authenticated client itself is a no-op by design:
        //      the SA asking to be itself is exactly the original grant, and demanding a
        //      self-edge would break every caller that sends the parameter redundantly.
        var serviceAccountClientId = actorClientId;
        if (!string.IsNullOrWhiteSpace(requestedClientId) &&
            !string.Equals(requestedClientId, actorClientId, StringComparison.Ordinal))
        {
            var authorization = await impersonatedIdentityResolver.AuthorizeActorAsync(
                actorClientId, requestedClientId, cancellationToken);
            if (authorization != ImpersonationDenialReason.None)
            {
                logger.LogWarning(
                    "Delegation denied: client '{ClientId}' may not delegate through service account '{RequestedClientId}' in tenant '{TenantId}': {Reason}",
                    actorClientId, requestedClientId, targetTenantId, authorization);
                await RaiseFailureAsync(actorClientId, userSubjectId, targetTenantId,
                    $"requested_client_id '{requestedClientId}': {authorization}");

                return authorization switch
                {
                    ImpersonationDenialReason.TargetNotFound => DelegationOutcome.Failed(Errors.InvalidClient,
                        "the service account is not provisioned in this tenant"),
                    ImpersonationDenialReason.TargetDisabled => DelegationOutcome.Failed(Errors.InvalidGrant,
                        "the requested service account is disabled"),
                    _ => DelegationOutcome.Failed(Errors.InvalidGrant,
                        "the authenticated client is not authorized to act as the requested service account")
                };
            }

            serviceAccountClientId = requestedClientId;
        }

        // (d) Resolve the delegation: role intersection, in the protocol-free policy service.
        //     ALWAYS the service account's roles ∩ the user's roles — the AB#5114 actor's own
        //     roles never participate: the actor merely proved it may act as the SA.
        var delegation = await delegatedIdentityResolver.ResolveAsync(
            serviceAccountClientId, userSubjectId, cancellationToken);

        if (!delegation.IsGranted)
        {
            logger.LogWarning(
                "Delegation denied for service account '{ClientId}' acting for user '{UserSubjectId}' in tenant '{TenantId}': {Reason}",
                serviceAccountClientId, userSubjectId, targetTenantId, delegation.DenialReason);
            await RaiseFailureAsync(actorClientId, userSubjectId, targetTenantId,
                delegation.DenialReason.ToString());

            return delegation.DenialReason switch
            {
                DelegationDenialReason.ServiceAccountNotFound => DelegationOutcome.Failed(Errors.InvalidClient,
                    "the service account is not provisioned in this tenant"),
                _ => DelegationOutcome.Failed(Errors.InvalidGrant,
                    "the subject_token does not identify a user in this tenant")
            };
        }

        logger.LogInformation(
            "Delegation succeeded: service account '{ClientId}' (authenticated client '{ActorClientId}') acting for user '{UserSubjectId}' in tenant '{TenantId}' with {RoleCount} effective role(s)",
            serviceAccountClientId, actorClientId, userSubjectId, targetTenantId,
            delegation.EffectiveRoleNames.Count);

        return DelegationOutcome.Succeeded(userSubjectId, targetTenantId, delegation.EffectiveRoleNames,
            serviceAccountClientId);
    }

    /// <summary>
    ///     The load-bearing half of the delegation grant: replaces the naturally resolved
    ///     <c>role</c> claims on the issued identity with the service-account ∩ user intersection
    ///     and stamps the <c>act</c> claim. Without the replacement the delegation would silently
    ///     grant the user's full authority; an empty intersection removes every role claim and adds
    ///     none back, so role-gated consumers fail closed.
    /// </summary>
    public static void ApplyDelegationClaims(System.Security.Claims.ClaimsIdentity identity,
        string actorClientId, IReadOnlySet<string> effectiveRoleNames)
    {
        foreach (var roleClaim in identity.Claims.Where(c => c.Type == Claims.Role).ToList())
        {
            identity.RemoveClaim(roleClaim);
        }

        foreach (var roleName in effectiveRoleNames)
        {
            identity.AddClaim(new System.Security.Claims.Claim(Claims.Role, roleName));
        }

        identity.AddClaim(new System.Security.Claims.Claim(
            DelegationConstants.ActClaimType, actorClientId));
    }

    /// <summary>
    ///     Persists a delegation failure to the runtime event log (success is log-only, matching
    ///     the audit behavior of the other grants).
    /// </summary>
    private async Task RaiseFailureAsync(string actorClientId, string userSubjectId, string tenantId,
        string reason)
    {
        await auditService.StoreFailureAsync("Delegation Failure",
            $"ClientId: {actorClientId} - SubjectId: {userSubjectId} - TenantId: {tenantId} - Reason: {reason}");
    }
}
