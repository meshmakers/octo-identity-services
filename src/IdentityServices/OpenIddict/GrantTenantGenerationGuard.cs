using Meshmakers.Octo.Services.Infrastructure.TenantGeneration;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     The tenant generation check of identity's grants (AB#9017, security item AB#8970): a token-exchange or
///     on-behalf-of <c>subject_token</c>, or a redeemed refresh token, authorization code or device code, must belong to
///     the <b>current</b> tenant with its <c>tenant_id</c>, not to an earlier tenant with the same id that was deleted and
///     created again. Without this check an old credential became a new token stamped with the <b>new</b> generation
///     (AB#8997 reads <c>tenant_gen</c> fresh at issuance), which resource services then accept.
/// </summary>
/// <remarks>
///     <para>
///         A thin adapter over <see cref="ITenantGenerationCheck" /> of octo-common-services (AB#8999): the same
///         evaluator, the same cached reader, the same option <c>TenantAuthorization:TenantGenerationEnforcement</c>
///         (Disabled / LogOnly / Enforce, default LogOnly) and the same metric
///         <c>octo.tenant_auth.generation_checks</c>, here with <c>transport=grant</c> and a <c>grant_type</c> label from
///         <see cref="GrantTenantGenerationGrantTypes" />. One option per environment therefore switches resource services
///         and identity together (AB#9000).
///     </para>
///     <para>
///         <see cref="TenantGenerationDecision.Deny" /> (Enforce: <c>mismatch</c> or <c>missing</c>) is answered with
///         <c>invalid_grant</c>, <see cref="TenantGenerationDecision.Unavailable" /> (Enforce: the generation could not be
///         read) with <c>server_error</c>. In LogOnly the check only logs and counts; the grant behaves as before. The
///         system tenant and tenants without a generation are never refused (<c>not_checked</c>).
///     </para>
/// </remarks>
public interface IGrantTenantGenerationGuard
{
    /// <summary>Checks the generation a subject token or a stored grant carries.</summary>
    /// <param name="tokenTenantId">The <c>tenant_id</c> of the subject token or of the stored grant.</param>
    /// <param name="generation">
    ///     The generation it carries: <c>tenant_gen</c> of a subject token, or the private
    ///     <see cref="OctoClaimTypes.GrantTenantGeneration" /> of a stored grant; <c>null</c> when it carries none.
    /// </param>
    /// <param name="grantType">Metric label, one of <see cref="GrantTenantGenerationGrantTypes" />.</param>
    /// <param name="clientId">
    ///     The client the checked token or grant was issued to (metric label and log; never a token value).
    /// </param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    ValueTask<GrantTenantGenerationResult> CheckAsync(string? tokenTenantId, TenantGenerationClaim? generation,
        string grantType, string? clientId, CancellationToken cancellationToken = default);
}

/// <summary>
///     Result of <see cref="IGrantTenantGenerationGuard.CheckAsync" />. <see cref="Error" /> is set only when the grant
///     must be refused; the default value is an allowed <see cref="TenantGenerationOutcome.Match" />.
/// </summary>
/// <param name="Outcome">The evaluation (also in LogOnly, where nothing is refused).</param>
/// <param name="Error">The OAuth error (<c>invalid_grant</c> or <c>server_error</c>), or <c>null</c>.</param>
/// <param name="ErrorDescription">The <c>error_description</c>, or <c>null</c>.</param>
public readonly record struct GrantTenantGenerationResult(
    TenantGenerationOutcome Outcome,
    string? Error = null,
    string? ErrorDescription = null)
{
    /// <summary>The grant must be refused with <see cref="Error" />.</summary>
    public bool IsRefused => Error != null;
}

/// <summary>The values of the metric label <c>grant_type</c> identity passes (AB#9017).</summary>
public static class GrantTenantGenerationGrantTypes
{
    /// <summary>RFC 8693 token exchange (subject token).</summary>
    public const string TokenExchange = "token_exchange";

    /// <summary>On-behalf-of delegation, also through an actor (subject token).</summary>
    public const string OnBehalfOf = "on_behalf_of";

    /// <summary>Refresh token redemption (stored grant).</summary>
    public const string RefreshToken = "refresh_token";

    /// <summary>Authorization code redemption (stored grant).</summary>
    public const string AuthorizationCode = "authorization_code";

    /// <summary>Device code redemption (stored grant).</summary>
    public const string DeviceCode = "device_code";
}

/// <inheritdoc />
public sealed class GrantTenantGenerationGuard(ITenantGenerationCheck check) : IGrantTenantGenerationGuard
{
    /// <summary>The <c>error_description</c> of a refused grant. Names no tenant, value or token.</summary>
    public const string RefusedDescription =
        "The token or grant was issued for an earlier tenant with the same id, or before the tenant generation was " +
        "recorded. Sign in again.";

    /// <summary>The <c>error_description</c> when the generation could not be verified (Enforce only).</summary>
    public const string UnavailableDescription = "The tenant generation could not be verified. Try again later.";

    /// <inheritdoc />
    public async ValueTask<GrantTenantGenerationResult> CheckAsync(string? tokenTenantId,
        TenantGenerationClaim? generation, string grantType, string? clientId,
        CancellationToken cancellationToken = default)
    {
        // The check logs missing/mismatch (rate-limited, never the value) and counts every outcome.
        var result = await check.CheckAsync(new TenantGenerationCheckRequest(tokenTenantId, generation,
            TenantGenerationTransports.Grant, clientId, grantType), cancellationToken).ConfigureAwait(false);

        return result.Decision switch
        {
            TenantGenerationDecision.Deny => new GrantTenantGenerationResult(result.Outcome, Errors.InvalidGrant,
                RefusedDescription),
            TenantGenerationDecision.Unavailable => new GrantTenantGenerationResult(result.Outcome,
                Errors.ServerError, UnavailableDescription),
            _ => new GrantTenantGenerationResult(result.Outcome)
        };
    }
}
