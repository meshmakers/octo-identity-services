using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Infrastructure;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Impersonation grant processor for
///     <c>grant_type=urn:meshmakers:params:oauth:grant-type:impersonate</c> (AB#5114): an
///     authenticated <b>confidential</b> client (the actor — typically an adapter's own AB#5072
///     chart client) names a target client via <c>requested_client_id</c> and receives a token that
///     is client-credentials-shaped <b>for the target</b> — <c>client_id</c> and roles of the
///     target, no <c>sub</c> — plus an <c>act</c> claim naming the actor. The target's secret is
///     never involved, which is the whole point: pipeline service accounts stop needing distributed
///     secrets.
/// </summary>
/// <remarks>
///     <para>
///         <b>This class is a thin protocol adapter</b>, like <see cref="OnBehalfOfProcessor" />:
///         it validates the request shape and the tenant wiring and hands the decision to
///         <see cref="IImpersonatedIdentityResolver" /> — the protocol-free policy service whose
///         single authorization source is the explicit <c>System.Identity/MayActAs</c> edge
///         actor→target. <c>TokenEndpointController</c> turns the outcome into the issued
///         principal; <c>OctoAccessTokenShapeHandler</c> re-stamps <c>client_id</c> to the target
///         and strips <c>sub</c> so the wire shape matches a genuine <c>client_credentials</c>
///         token of the target.
///     </para>
///     <para>
///         <b>Same tenant only.</b> The tenant in <c>acr_values</c> and the tenant the request was
///         wired to must agree; a divergence fails closed with <c>invalid_target</c> — otherwise
///         the client lookups and the edge check would run against a different database than the
///         caller asked for.
///     </para>
///     <para>
///         <b>No refresh tokens — enforced, not merely discouraged</b> (same rationale and wording
///         as the on-behalf-of grant): the <c>MayActAs</c> authorization and the target's roles are
///         evaluated at ISSUANCE, while a refresh would rebuild the token from the stored principal
///         without re-entering this processor — a revoked edge or role would keep working for the
///         refresh token's whole lifetime. A request asking for <c>offline_access</c> is rejected
///         with <c>invalid_scope</c>.
///     </para>
/// </remarks>
public class ImpersonationProcessor(
    IImpersonatedIdentityResolver impersonatedIdentityResolver,
    IHttpContextAccessor httpContextAccessor,
    IIdentityAuditService auditService,
    ILogger<ImpersonationProcessor> logger)
{
    /// <summary>Outcome of an impersonation attempt: either the target identity or an OAuth error.</summary>
    public sealed record ImpersonationOutcome
    {
        public string? TargetClientId { get; init; }
        public string? TenantId { get; init; }
        public IReadOnlySet<string>? EffectiveRoleNames { get; init; }
        public string? Error { get; init; }
        public string? ErrorDescription { get; init; }

        public static ImpersonationOutcome Failed(string error, string description) =>
            new() { Error = error, ErrorDescription = description };

        public static ImpersonationOutcome Succeeded(string targetClientId, string tenantId,
            IReadOnlySet<string> effectiveRoleNames) =>
            new() { TargetClientId = targetClientId, TenantId = tenantId, EffectiveRoleNames = effectiveRoleNames };
    }

    /// <summary>Validates the impersonation request and resolves the target's identity.</summary>
    /// <param name="actorClientId">The already-authenticated actor client id.</param>
    /// <param name="requestedClientId">The <c>requested_client_id</c> parameter naming the target.</param>
    /// <param name="acrValues">The raw acr_values parameter carrying <c>tenant:{tenantId}</c>.</param>
    /// <param name="requestedScopes">The scopes the client requested.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<ImpersonationOutcome> ProcessAsync(
        string? actorClientId, string? requestedClientId, string? acrValues,
        IReadOnlyCollection<string> requestedScopes, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(actorClientId))
        {
            logger.LogError("Impersonation rejected: the token request carries no authenticated client");
            return ImpersonationOutcome.Failed(Errors.InvalidClient,
                "the impersonating actor must be an authenticated client");
        }

        // (a) No refresh tokens for impersonated identities — fail closed BY CONSTRUCTION. The
        //     MayActAs authorization and the target's role set are evaluated at issuance; a
        //     refresh_token redemption rebuilds the token without re-entering this processor,
        //     freezing both until expiry.
        if (requestedScopes.Contains(Scopes.OfflineAccess, StringComparer.Ordinal))
        {
            var requestedTenantId = TenantExchangeProcessor.ParseTenantFromAcrValues(acrValues) ?? "(unknown)";
            logger.LogWarning(
                "Impersonation rejected: client '{ClientId}' requested offline_access for tenant '{TenantId}' — impersonated tokens are never refreshable",
                actorClientId, requestedTenantId);
            await RaiseFailureAsync(actorClientId, requestedClientId ?? "(unknown)", requestedTenantId,
                "offline_access is not supported for impersonation");

            return ImpersonationOutcome.Failed(Errors.InvalidScope,
                "offline_access is not supported for impersonation: the MayActAs authorization and the target client's roles are evaluated when the token is issued. A refresh_token request rebuilds the token from the stored grant without re-evaluating them, so a revoked authorization or role would remain in force. Request a new token with the impersonation grant instead.");
        }

        // (b) The target is named explicitly — there is no default, and guessing one would turn a
        //     malformed request into an authorization decision.
        if (string.IsNullOrWhiteSpace(requestedClientId))
        {
            return ImpersonationOutcome.Failed(Errors.InvalidRequest,
                "requested_client_id is required for impersonation");
        }

        // (c) Same-tenant gate: acr_values and the tenant the request was wired to must agree —
        //     otherwise the client lookups and the MayActAs edge check below would run against a
        //     different database than the caller asked for. Fail closed.
        var targetTenantId = TenantExchangeProcessor.ParseTenantFromAcrValues(acrValues);
        if (string.IsNullOrEmpty(targetTenantId))
        {
            return ImpersonationOutcome.Failed(Errors.InvalidRequest,
                "acr_values=tenant:{tenantId} is required for impersonation");
        }

        var resolvedTenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(resolvedTenantId) ||
            !string.Equals(resolvedTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogError(
                "Impersonation rejected: request tenant '{ResolvedTenantId}' does not match requested tenant '{TargetTenantId}' — refusing to authorize against the wrong database",
                resolvedTenantId ?? "(none)", targetTenantId);
            await RaiseFailureAsync(actorClientId, requestedClientId, targetTenantId,
                "tenant not wired into request");
            return ImpersonationOutcome.Failed(Errors.InvalidTarget,
                "the tenant could not be resolved for this request");
        }

        // (d) The authorization decision, in the protocol-free policy service: actor and target
        //     provisioned in the tenant, target enabled, MayActAs edge present, target roles.
        var impersonation = await impersonatedIdentityResolver.ResolveAsync(
            actorClientId, requestedClientId, cancellationToken);

        if (!impersonation.IsGranted)
        {
            logger.LogWarning(
                "Impersonation denied for client '{ClientId}' acting as '{TargetClientId}' in tenant '{TenantId}': {Reason}",
                actorClientId, requestedClientId, targetTenantId, impersonation.DenialReason);
            await RaiseFailureAsync(actorClientId, requestedClientId, targetTenantId,
                impersonation.DenialReason.ToString());

            return impersonation.DenialReason switch
            {
                ImpersonationDenialReason.TargetNotFound => ImpersonationOutcome.Failed(Errors.InvalidGrant,
                    "the requested client is not provisioned in this tenant"),
                ImpersonationDenialReason.TargetDisabled => ImpersonationOutcome.Failed(Errors.InvalidGrant,
                    "the requested client is disabled"),
                _ => ImpersonationOutcome.Failed(Errors.InvalidGrant,
                    "the authenticated client is not authorized to act as the requested client")
            };
        }

        logger.LogInformation(
            "Impersonation succeeded: client '{ClientId}' acting as '{TargetClientId}' in tenant '{TenantId}' with {RoleCount} effective role(s)",
            actorClientId, requestedClientId, targetTenantId, impersonation.EffectiveRoleNames.Count);

        return ImpersonationOutcome.Succeeded(requestedClientId, targetTenantId,
            impersonation.EffectiveRoleNames);
    }

    /// <summary>
    ///     Composes the impersonated identity's claims: the TARGET's role claims (the same claim
    ///     shape <c>IOctoTokenClaimsService.PopulateClientClaimsAsync</c> produces for a genuine
    ///     <c>client_credentials</c> token) plus the <c>act</c> claim naming the ACTOR — the only
    ///     trace of the actor on the issued token, so the audit trail can tell an impersonated
    ///     token apart from one the target obtained with its own secret.
    /// </summary>
    public static void ApplyImpersonationClaims(System.Security.Claims.ClaimsIdentity identity,
        string actorClientId, IReadOnlySet<string> targetRoleNames)
    {
        foreach (var roleName in targetRoleNames)
        {
            identity.AddClaim(new System.Security.Claims.Claim(Claims.Role, roleName));
        }

        identity.AddClaim(new System.Security.Claims.Claim(
            ImpersonationConstants.ActClaimType, actorClientId));
    }

    /// <summary>
    ///     Persists an impersonation failure to the runtime event log (success is log-only,
    ///     matching the audit behavior of the other grants).
    /// </summary>
    private async Task RaiseFailureAsync(string actorClientId, string targetClientId, string tenantId,
        string reason)
    {
        await auditService.StoreFailureAsync("Impersonation Failure",
            $"ClientId: {actorClientId} - TargetClientId: {targetClientId} - TenantId: {tenantId} - Reason: {reason}");
    }
}
