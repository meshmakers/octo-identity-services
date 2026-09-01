using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     RFC 8693 cross-tenant token exchange on OpenIddict (AB#4992), replacing the Duende
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
/// </remarks>
public class TenantExchangeProcessor(
    IOptionsMonitor<OpenIddictServerOptions> serverOptions,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    ICrossTenantAuthenticationService crossTenantAuthService,
    ICrossTenantUserProvisioningService crossTenantUserProvisioningService,
    IExternalTenantUserMappingStore externalTenantUserMappingStore,
    IHttpContextAccessor httpContextAccessor,
    IIdentityAuditService auditService,
    ILogger<TenantExchangeProcessor> logger)
{
    /// <summary>The RFC 8693 token type identifier for an access token.</summary>
    private const string AccessTokenTypeIdentifier = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>The <c>amr</c> value recorded on exchanged tokens for auditability.</summary>
    public const string AuthenticationMethod = "token_exchange";

    /// <summary>Outcome of a token exchange attempt: either a B-shadow user or an OAuth error.</summary>
    public sealed record ExchangeOutcome
    {
        public RtUser? ShadowUser { get; init; }
        public string? TargetTenantId { get; init; }
        public string? Error { get; init; }
        public string? ErrorDescription { get; init; }

        public static ExchangeOutcome Failed(string error, string description) =>
            new() { Error = error, ErrorDescription = description };

        public static ExchangeOutcome Succeeded(RtUser shadowUser, string targetTenantId) =>
            new() { ShadowUser = shadowUser, TargetTenantId = targetTenantId };
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
        // (a) Validate the subject token (signature + issuer + lifetime, ValidateAudience=false —
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

        // (d) Find or create the B-shadow user (roles synced from RtExternalTenantUserMapping in B).
        var shadowUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
            crossTenantResult, targetTenantId);
        if (shadowUser == null)
        {
            logger.LogError(
                "Token exchange failed: could not provision the B-shadow user in tenant '{TargetTenantId}'",
                targetTenantId);
            await RaiseFailureAsync(sourceUserId, sourceTenantId, targetTenantId,
                "shadow user provisioning failed");
            return ExchangeOutcome.Failed(Errors.InvalidGrant, "failed to provision the target-tenant user");
        }

        logger.LogInformation(
            "Token exchange succeeded: user '{SourceUserId}' from tenant '{SourceTenantId}' exchanged into tenant '{TargetTenantId}' as shadow user '{ShadowRtId}'",
            sourceUserId, sourceTenantId, targetTenantId, shadowUser.RtId);

        return ExchangeOutcome.Succeeded(shadowUser, targetTenantId);
    }

    /// <summary>
    ///     Picks the source identity to exchange from and runs the B-authorization gate on it —
    ///     identical semantics to the Duende validator (incl. the AB#4966 shadow-user/ancestor
    ///     dual-candidate rule). Returns <c>null</c> when no candidate may reach the target.
    /// </summary>
    internal async Task<CrossTenantAuthResult?> ResolveExchangeSourceAsync(
        string targetTenantId, string sourceTenantId, string sourceUserId)
    {
        var sourceUserName = await crossTenantAuthService.FindUserNameByIdInTenantAsync(
            sourceTenantId, sourceUserId);

        var candidates = new List<(string TenantId, string UserId)> { (sourceTenantId, sourceUserId) };

        if (sourceUserName != null && sourceUserName.StartsWith("xt_", StringComparison.OrdinalIgnoreCase))
        {
            // Same parsing convention as the claims layer: xt_{homeTenantId}_{originalUserName}
            var parts = sourceUserName.Split('_', 3);
            var homeTenantId = parts.Length == 3 ? parts[1] : null;
            var originalUserName = parts.Length == 3 ? parts[2] : null;

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
