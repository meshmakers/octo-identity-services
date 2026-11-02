using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     RFC 8693 cross-tenant token exchange on OpenIddict (AB#4992), replacing the former
///     <c>TenantExchangeGrantValidator</c>: mints a <b>target-tenant (B)</b> access token for an
///     already-authenticated user, proven by their current home-tenant (A) access token
///     (<c>subject_token</c>), with the roles re-resolved in B.
/// </summary>
/// <remarks>
///     <para>
///         <b>The security linchpin is unchanged:</b> the result carries the <b>B-shadow user</b>
///         (<c>xt_{A}_{user}</c>, found/created via
///         <see cref="ICrossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync" />),
///         never the A user with a swapped <c>tenant_id</c>. The claims for the issued token are
///         built for THIS subject against the B tenant repository, so <c>tenant_id=B</c> and
///         B-resolved roles are stamped automatically — A's roles never leak into B.
///     </para>
///     <para>
///         Fail-closed at each step (invalid subject token, missing target tenant, target tenant
///         not wired into the request by <c>OidcTenantResolutionMiddleware</c>, non-ancestor
///         relationship, failed shadow provisioning) with an OAuth error and a persisted failure
///         audit event. v1 semantics preserved: no refresh token is issued for exchanged tokens.
///     </para>
///     <para>
///         <b>Ancestry is not authority (AB#6839, decision Gerald 2026-10-17).</b> Being a user of an
///         ancestor tenant only lets the exchange <i>reach</i> the target tenant; the roles of the issued
///         token come exclusively from explicit provisioning in B (an <c>ExternalTenantUserMapping</c>
///         with roles or groups, a group membership or a direct role of the shadow user). When the
///         B-shadow user resolves to no role at all the exchange is refused with
///         <see cref="Errors.AccessDenied" /> and a description starting with
///         <see cref="NotProvisionedMarker" />, so clients (octo-cli) can show a clear denial instead of
///         a later 403 on the first call. A token without roles could not pass role enforcement anyway.
///     </para>
/// </remarks>
public class TenantExchangeProcessor(
    IOptionsMonitor<OpenIddictServerOptions> serverOptions,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    ICrossTenantAuthenticationService crossTenantAuthService,
    ICrossTenantUserProvisioningService crossTenantUserProvisioningService,
    ICrossTenantShadowUserChainResolver shadowUserChainResolver,
    IExternalTenantUserMappingStore externalTenantUserMappingStore,
    UserManager<RtUser> userManager,
    IHttpContextAccessor httpContextAccessor,
    IIdentityAuditService auditService,
    ILogger<TenantExchangeProcessor> logger)
{
    /// <summary>The RFC 8693 token type identifier for an access token.</summary>
    private const string AccessTokenTypeIdentifier = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>The <c>amr</c> value recorded on exchanged tokens for auditability.</summary>
    public const string AuthenticationMethod = "token_exchange";

    /// <summary>
    ///     Stable, machine-readable prefix of the <c>error_description</c> of the denial that is returned
    ///     (with <c>error=access_denied</c>) when the caller is a valid ancestor-tenant user but holds no
    ///     role in the target tenant. Clients match on this prefix, never on the free text after it.
    /// </summary>
    public const string NotProvisionedMarker = "tenant_not_provisioned";

    /// <summary>Outcome of a token exchange attempt: either a B-shadow user or an OAuth error.</summary>
    public sealed record ExchangeOutcome
    {
        public RtUser? ShadowUser { get; init; }
        public string? TargetTenantId { get; init; }
        public string? Error { get; init; }
        public string? ErrorDescription { get; init; }

        /// <summary>
        ///     The subject token carried second-factor evidence (<c>amr=mfa</c>); the issued token carries it on, so a
        ///     chained exchange can rely on it (AB#7804).
        /// </summary>
        public bool SecondFactorVerified { get; init; }

        public static ExchangeOutcome Failed(string error, string description) =>
            new() { Error = error, ErrorDescription = description };

        public static ExchangeOutcome Succeeded(RtUser shadowUser, string targetTenantId, bool secondFactorVerified) =>
            new() { ShadowUser = shadowUser, TargetTenantId = targetTenantId, SecondFactorVerified = secondFactorVerified };
    }

    /// <summary>
    ///     Validates the exchange request and resolves the B-shadow user (see class remarks).
    /// </summary>
    /// <param name="subjectToken">The caller's current A access token.</param>
    /// <param name="subjectTokenType">The RFC 8693 subject_token_type, if provided.</param>
    /// <param name="acrValues">The raw acr_values parameter carrying <c>tenant:{B}</c>.</param>
    public async Task<ExchangeOutcome> ProcessAsync(
        string? subjectToken, string? subjectTokenType, string? acrValues,
        CancellationToken cancellationToken = default)
    {
        // (a) Validate the subject token (signature + issuer + lifetime + typ at+jwt, ValidateAudience=false —
        //     platform-wide convention). Deliberately NOT bound to the request tenant: the request
        //     is wired to the TARGET tenant B while the subject belongs to the SOURCE tenant A.
        if (string.IsNullOrEmpty(subjectToken))
        {
            return ExchangeOutcome.Failed(Errors.InvalidRequest, "subject_token is required");
        }

        if (!string.IsNullOrEmpty(subjectTokenType) &&
            !string.Equals(subjectTokenType, AccessTokenTypeIdentifier, StringComparison.Ordinal))
        {
            return ExchangeOutcome.Failed(Errors.InvalidRequest,
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token");
        }

        var signingKeys = serverOptions.CurrentValue.SigningCredentials
            .Select(c => c.Key)
            .ToList();
        var handler = new JsonWebTokenHandler();
        // AB#7860: only an access token (typ at+jwt) is a valid subject, never an id_token.
        var validation = await handler.ValidateTokenAsync(subjectToken,
            SubjectTokenValidation.ForAccessToken(octoIdentityOptions.Value.AuthorityUrl, signingKeys));
        if (!validation.IsValid)
        {
            logger.LogWarning("Token exchange rejected: subject_token invalid ({Error})",
                validation.Exception?.Message ?? "validation failed");
            return ExchangeOutcome.Failed(Errors.InvalidGrant, "subject_token is invalid or expired");
        }

        var claims = validation.ClaimsIdentity.Claims.ToList();
        var sourceUserId = claims.FirstOrDefault(c => c.Type == Claims.Subject)?.Value;
        var sourceTenantId = claims.FirstOrDefault(c => c.Type == OctoClaimTypes.TenantId)?.Value;

        if (string.IsNullOrEmpty(sourceUserId) || string.IsNullOrEmpty(sourceTenantId))
        {
            logger.LogWarning(
                "Token exchange rejected: subject_token lacks sub or tenant_id (user context required)");
            return ExchangeOutcome.Failed(Errors.InvalidGrant,
                "subject_token must carry a user subject and tenant_id");
        }

        // (b) Target tenant B from acr_values, asserted against the tenant the middleware wired
        //     into the request — otherwise shadow user + roles would resolve against the wrong DB.
        var targetTenantId = ParseTenantFromAcrValues(acrValues);
        if (string.IsNullOrEmpty(targetTenantId))
        {
            return ExchangeOutcome.Failed(Errors.InvalidRequest,
                "acr_values=tenant:{targetTenantId} is required for token exchange");
        }

        var resolvedTenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(resolvedTenantId) ||
            !string.Equals(resolvedTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogError(
                "Token exchange rejected: request tenant '{ResolvedTenantId}' does not match requested target '{TargetTenantId}' — refusing to resolve roles against the wrong database",
                resolvedTenantId ?? "(none)", targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "target tenant not wired into request");
            return ExchangeOutcome.Failed(Errors.InvalidTarget,
                "target tenant could not be resolved for this request");
        }

        return await ExchangeAsync(sourceTenantId, sourceUserId, targetTenantId,
            subjectHasSecondFactor: SecondFactorEvidence.IsPresent(claims));
    }

    /// <summary>
    ///     The authorization half of the exchange, after the subject token and the target tenant were
    ///     validated: B-authorization gate, B-shadow user, and the refusal of a caller without any role
    ///     in B (see class remarks). Separated from <see cref="ProcessAsync" /> so the real exchange path
    ///     can be tested without minting and signing a subject token.
    /// </summary>
    /// <param name="sourceTenantId">Tenant of the subject token.</param>
    /// <param name="sourceUserId">Subject of the subject token.</param>
    /// <param name="targetTenantId">The tenant the token is exchanged into.</param>
    /// <param name="subjectHasSecondFactor">The subject token carries <c>amr=mfa</c> (AB#7804).</param>
    internal async Task<ExchangeOutcome> ExchangeAsync(
        string sourceTenantId, string sourceUserId, string targetTenantId, bool subjectHasSecondFactor)
    {
        // (b2)+(c) Pick the source identity and run the B-authorization gate on it.
        var crossTenantResult = await ResolveExchangeSourceAsync(targetTenantId, sourceTenantId, sourceUserId);
        if (crossTenantResult == null)
        {
            logger.LogWarning(
                "Token exchange denied: user '{SourceUserId}' from tenant '{SourceTenantId}' may not access target tenant '{TargetTenantId}'",
                sourceUserId, sourceTenantId, targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId, "cross-tenant access denied");
            return ExchangeOutcome.Failed(Errors.UnauthorizedClient,
                "cross-tenant access to the target tenant is denied");
        }

        // (c2) AB#7804: a source user with 2FA (itself or anywhere in its xt_ chain) needs second-factor evidence in
        //      the subject token. Without it the exchange would turn a password-only token into a target-tenant token.
        if (crossTenantResult.SourceUserRequiresSecondFactor && !subjectHasSecondFactor)
        {
            logger.LogWarning(
                "Token exchange denied: user '{SourceUserId}' from tenant '{SourceTenantId}' has two-factor authentication enabled, but the subject token carries no second-factor evidence",
                sourceUserId, sourceTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "second factor required, subject token has no amr=mfa");
            return ExchangeOutcome.Failed(Errors.AccessDenied,
                $"{SecondFactorEvidence.RequiredMarker}: the user has two-factor authentication enabled; " +
                "sign in again with the second factor and use that token");
        }

        // (d) Find or create the B-shadow user (roles synced from RtExternalTenantUserMapping in B).
        //     No mapping is stored here (AB#7088): the exchange only needs the shadow user to read its roles. A
        //     role-less mapping stored for a refused user used to make ProvisionCurrentUser report "already
        //     provisioned" while the user stayed denied.
        var shadowUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
            crossTenantResult, targetTenantId, storeMappingIfMissing: false);
        if (shadowUser == null)
        {
            logger.LogError(
                "Token exchange failed: could not provision the B-shadow user in tenant '{TargetTenantId}'",
                targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "shadow user provisioning failed");
            return ExchangeOutcome.Failed(Errors.InvalidGrant, "failed to provision the target-tenant user");
        }

        // (e) Ancestry gives no roles. The same store that stamps the token's role claims decides: a
        //     shadow user without a single effective role in B is not provisioned there.
        if ((await userManager.GetRolesAsync(shadowUser)).Count == 0)
        {
            logger.LogWarning(
                "Token exchange denied: user '{SourceUserId}' from tenant '{SourceTenantId}' holds no role in target tenant '{TargetTenantId}' (not provisioned)",
                sourceUserId, sourceTenantId, targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "not provisioned in target tenant (no role)");
            return ExchangeOutcome.Failed(Errors.AccessDenied,
                $"{NotProvisionedMarker}: the user holds no role in tenant '{targetTenantId}'; " +
                "an administrator of that tenant must provision the user there (ProvisionCurrentUser -ttid)");
        }

        logger.LogInformation(
            "Token exchange succeeded: user '{SourceUserId}' from tenant '{SourceTenantId}' exchanged into tenant '{TargetTenantId}' as shadow user '{ShadowRtId}'",
            sourceUserId, sourceTenantId, targetTenantId, shadowUser.RtId);

        return ExchangeOutcome.Succeeded(shadowUser, targetTenantId, subjectHasSecondFactor);
    }

    /// <summary>
    ///     Picks the source identity to exchange from and runs the B-authorization gate on it —
    ///     identical semantics to the pre-migration validator (incl. the AB#4966
    ///     shadow-user/ancestor dual-candidate rule). Returns <c>null</c> when no candidate may
    ///     reach the target.
    /// </summary>
    internal async Task<CrossTenantAuthResult?> ResolveExchangeSourceAsync(
        string targetTenantId, string sourceTenantId, string sourceUserId)
    {
        var sourceUserName = await crossTenantAuthService.FindUserNameByIdInTenantAsync(
            sourceTenantId, sourceUserId);

        var candidates = new List<(string TenantId, string UserId)> { (sourceTenantId, sourceUserId) };

        if (CrossTenantShadowUserName.IsShadowUserName(sourceUserName))
        {
            // xt_{homeTenantId}_{originalUserName}, split against the tenant registry (AB#5708): tenant
            // ids may contain '_', so the first separator is not necessarily the end of the home tenant
            // id. An ambiguous or unregistered prefix yields no home candidate — fail closed, only the
            // immediate source identity is judged.
            var chain = await shadowUserChainResolver.GetSourceChainAsync(sourceUserName);
            var homeTenantId = chain.Count > 0 ? chain[0].TenantId : null;
            var originalUserName = chain.Count > 0 ? chain[0].UserName : null;

            var homeUserId = string.IsNullOrEmpty(homeTenantId) || string.IsNullOrEmpty(originalUserName)
                ? null
                : await crossTenantAuthService.FindUserIdByNameInTenantAsync(homeTenantId, originalUserName);

            if (string.IsNullOrEmpty(homeUserId))
            {
                // Not fatal on its own — the immediate source may still be an ancestor of the target.
                logger.LogWarning(
                    "Token exchange: could not resolve home identity (user '{OriginalUserName}') in home tenant '{HomeTenantId}' for shadow user '{ShadowUserName}'",
                    originalUserName ?? "(none)", homeTenantId ?? "(none)", sourceUserName);
            }
            else
            {
                candidates.Add((homeTenantId!, homeUserId));
            }
        }

        CrossTenantAuthResult? authorizedWithoutMapping = null;

        foreach (var (candidateTenantId, candidateUserId) in candidates)
        {
            var candidateResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
                targetTenantId, candidateTenantId, candidateUserId);
            if (candidateResult == null)
            {
                continue;
            }

            authorizedWithoutMapping ??= candidateResult;

            var mapping = await externalTenantUserMappingStore.FindBySourceUserAsync(
                candidateTenantId, candidateUserId);
            if (mapping != null)
            {
                return candidateResult;
            }
        }

        return authorizedWithoutMapping;
    }

    private Task RaiseFailureAsync(string sourceUserId, string sourceTenantId, string targetTenantId,
        string reason)
        => auditService.StoreFailureAsync("Token Exchange Failure",
            $"Source user '{sourceUserId}' (tenant '{sourceTenantId}') → target tenant '{targetTenantId}': {reason}");

    /// <summary>Parses <c>tenant:{tenantId}</c> from a space-separated <c>acr_values</c> string.</summary>
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
