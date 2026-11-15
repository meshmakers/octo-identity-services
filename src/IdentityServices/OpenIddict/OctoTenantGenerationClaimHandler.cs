using System.Globalization;
using System.Security.Claims;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.TenantLifecycle;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Stamps the <c>tenant_gen</c> claim on every access token identity issues (AB#8997, security item AB#8970).
///     <para>
///         <c>tenant_gen</c> names the generation of the tenant in the token's <c>tenant_id</c> claim: the
///         <see cref="TenantLifecycleRecord.CreatedUtc" /> of its lifecycle record (system database) as Unix
///         milliseconds, written as a decimal string. A new creation cycle of a tenant id sets a new value, a restore over
///         the existing tenant keeps it. Resource services compare it with the current generation of the tenant
///         (AB#8999), so a token of a deleted tenant is not accepted by a new tenant with the same id.
///     </para>
///     Three OpenIddict <c>ProcessSignInContext</c> handlers:
///     <list type="bullet">
///         <item><see cref="Lookup" /> — token endpoint only, right after <c>ValidateSignInDemand</c> and
///             <b>before</b> <c>RedeemTokenEntry</c>: reads the lifecycle record of the <c>tenant_id</c> the
///             principal built by <c>TokenEndpointController</c> carries. A failing read refuses the request with
///             <c>server_error</c> before the authorization code, device code or refresh token is redeemed, so the
///             client can retry with the same value. One read per token request.</item>
///         <item><see cref="StampAccessToken" /> — after <c>PrepareAccessTokenPrincipal</c>, when an access token is
///             generated (every grant except RFC 8693 token exchange).</item>
///         <item><see cref="StampIssuedToken" /> — after <c>PrepareIssuedTokenPrincipal</c>, when the RFC 8693 token
///             exchange issues an access token (OpenIddict generates it as the "issued token", not as the access
///             token).</item>
///     </list>
///     Since AB#9017 three more handlers stamp the <b>stored grants</b>: <see cref="StampAuthorizationCode" />,
///     <see cref="StampRefreshToken" /> and <see cref="StampDeviceCode" /> (after <c>PrepareAuthorizationCodePrincipal</c>,
///     <c>PrepareRefreshTokenPrincipal</c>, <c>PrepareDeviceCodePrincipal</c>) add the generation read at issuance as the
///     private claim <see cref="OctoClaimTypes.GrantTenantGeneration" /> (no destination). <c>TokenEndpointController</c>
///     compares it with the current generation when the grant is redeemed (<see cref="IGrantTenantGenerationGuard" />).
///     Issuing an authorization code (authorization endpoint) or approving a device code (end-user verification
///     endpoint) therefore costs one lifecycle read too, and refuses with <c>server_error</c> when it fails.
///     <list type="bullet">
///         <item>The claim is added to the access-token (or issued access-token) principal only: it never reaches the
///             id token, the userinfo response, or the principal stored in a refresh token / authorization code. A
///             refresh grant therefore reads the generation again at issuance instead of copying it. The stored grant
///             carries its own private claim instead (AB#9017, above).</item>
///         <item>No lifecycle record, or a record without <c>CreatedUtc</c> (legacy tenants, a system tenant without a
///             record): no claim, issuance succeeds.</item>
///         <item>The lifecycle read fails: the token request fails with <c>server_error</c> — never a token without the
///             claim for a tenant that may have a generation. The log names the tenant and the exception, never a token
///             or a secret.</item>
///         <item>At most one lifecycle read per token request; nothing on token validation.</item>
///     </list>
/// </summary>
public static class OctoTenantGenerationClaimHandler
{
    /// <summary>Transaction property that carries the lookup result from <see cref="Lookup" /> to the stamps.</summary>
    internal const string LookupPropertyName = "octo:tenant_generation";

    /// <summary>
    ///     Transaction property set by <c>TokenEndpointController</c> when a redeemed grant carried a generation that
    ///     does not match (LogOnly lets the request through): the rotated refresh token keeps that value instead of the
    ///     current one, so the evidence survives until Enforce refuses it (AB#9017). Value:
    ///     <see cref="CarriedGrantGeneration" />.
    /// </summary>
    internal const string CarriedGrantGenerationPropertyName = "octo:grant_tenant_generation_carried";

    /// <summary>The value a rotated grant keeps (see <see cref="CarriedGrantGenerationPropertyName" />).</summary>
    internal sealed record CarriedGrantGeneration(string TenantId, string Value);

    /// <summary>Result of the lifecycle read for one tenant id; <see cref="Value" /> is null without a generation.</summary>
    internal sealed record LookupResult(string TenantId, string? Value);

    /// <summary>
    ///     Reads the generation before anything is redeemed (token endpoint). See the class summary.
    /// </summary>
    public sealed class Lookup(
        ITenantLifecycleStore lifecycleStore,
        ILogger<Lookup> logger) : IOpenIddictServerHandler<ProcessSignInContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<Lookup>()
                .SetOrder(OpenIddictServerHandlers.ValidateSignInDemand.Descriptor.Order + 1)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Only the token endpoint issues access tokens on this server (no implicit or hybrid flow). The
            // authorization and device-verification endpoints issue codes; their generation is read by the grant stamps
            // (AB#9017) after the principal is prepared, never before the code is redeemed.
            if (context.EndpointType != OpenIddictServerEndpointType.Token)
            {
                return;
            }

            // An RFC 8693 exchange that asks for another token type (refresh or id token) issues no access token,
            // so its request must neither cost a read nor fail on one.
            if (context.Request?.IsTokenExchangeGrantType() == true &&
                context.Request.RequestedTokenType is { Length: > 0 } requested &&
                requested is not TokenTypeIdentifiers.AccessToken)
            {
                return;
            }

            var tenantId = context.Principal?.FindFirst(OctoClaimTypes.TenantId)?.Value;
            if (string.IsNullOrWhiteSpace(tenantId))
            {
                return;
            }

            var result = await ReadAsync(context, lifecycleStore, logger, tenantId);
            if (result != null)
            {
                context.Transaction.Properties[LookupPropertyName] = result;
            }
        }
    }

    /// <summary>Adds the claim to the access-token principal (all grants except RFC 8693 token exchange).</summary>
    public sealed class StampAccessToken(
        ITenantLifecycleStore lifecycleStore,
        ILogger<StampAccessToken> logger) : IOpenIddictServerHandler<ProcessSignInContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireAccessTokenGenerated>()
                .UseSingletonHandler<StampAccessToken>()
                .SetOrder(OpenIddictServerHandlers.PrepareAccessTokenPrincipal.Descriptor.Order + 1)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return StampAsync(context, context.AccessTokenPrincipal, lifecycleStore, logger);
        }
    }

    /// <summary>
    ///     Adds the claim to the issued-token principal when the RFC 8693 token exchange issues an access token.
    /// </summary>
    public sealed class StampIssuedToken(
        ITenantLifecycleStore lifecycleStore,
        ILogger<StampIssuedToken> logger) : IOpenIddictServerHandler<ProcessSignInContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireIssuedTokenGenerated>()
                .UseSingletonHandler<StampIssuedToken>()
                .SetOrder(OpenIddictServerHandlers.PrepareIssuedTokenPrincipal.Descriptor.Order + 1)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            // Only an issued ACCESS token names a tenant generation; an issued refresh/id token does not.
            if (context.IssuedTokenType is not TokenTypeIdentifiers.AccessToken)
            {
                return default;
            }

            return StampAsync(context, context.IssuedTokenPrincipal, lifecycleStore, logger);
        }
    }

    /// <summary>Stores the generation in an authorization code (AB#9017).</summary>
    public sealed class StampAuthorizationCode(
        ITenantLifecycleStore lifecycleStore,
        ILogger<StampAuthorizationCode> logger) : IOpenIddictServerHandler<ProcessSignInContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireAuthorizationCodeGenerated>()
                .UseSingletonHandler<StampAuthorizationCode>()
                .SetOrder(OpenIddictServerHandlers.PrepareAuthorizationCodePrincipal.Descriptor.Order + 1)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return StampGrantAsync(context, context.AuthorizationCodePrincipal, lifecycleStore, logger);
        }
    }

    /// <summary>Stores the generation in a refresh token (AB#9017).</summary>
    public sealed class StampRefreshToken(
        ITenantLifecycleStore lifecycleStore,
        ILogger<StampRefreshToken> logger) : IOpenIddictServerHandler<ProcessSignInContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireRefreshTokenGenerated>()
                .UseSingletonHandler<StampRefreshToken>()
                .SetOrder(OpenIddictServerHandlers.PrepareRefreshTokenPrincipal.Descriptor.Order + 1)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return StampGrantAsync(context, context.RefreshTokenPrincipal, lifecycleStore, logger);
        }
    }

    /// <summary>
    ///     Stores the generation in a device code (AB#9017). The device authorization request has no user and usually no
    ///     tenant claim yet (nothing to stamp); the end-user verification sign-in updates the device code with the user's
    ///     principal, and that one is stamped.
    /// </summary>
    public sealed class StampDeviceCode(
        ITenantLifecycleStore lifecycleStore,
        ILogger<StampDeviceCode> logger) : IOpenIddictServerHandler<ProcessSignInContext>
    {
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<OpenIddictServerHandlerFilters.RequireDeviceCodeGenerated>()
                .UseSingletonHandler<StampDeviceCode>()
                .SetOrder(OpenIddictServerHandlers.PrepareDeviceCodePrincipal.Descriptor.Order + 1)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            ArgumentNullException.ThrowIfNull(context);
            return StampGrantAsync(context, context.DeviceCodePrincipal, lifecycleStore, logger);
        }
    }

    /// <summary>All descriptors, in the order OpenIddict runs them.</summary>
    public static IReadOnlyList<OpenIddictServerHandlerDescriptor> Descriptors { get; } =
    [
        Lookup.Descriptor, StampAccessToken.Descriptor, StampIssuedToken.Descriptor, StampAuthorizationCode.Descriptor,
        StampRefreshToken.Descriptor, StampDeviceCode.Descriptor
    ];

    private static async ValueTask StampGrantAsync(ProcessSignInContext context, ClaimsPrincipal? principal,
        ITenantLifecycleStore lifecycleStore, ILogger logger)
    {
        if (principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        // The stored value is always the one decided for this issuance; drop anything copied in.
        foreach (var stale in identity.FindAll(OctoClaimTypes.GrantTenantGeneration).ToList())
        {
            identity.TryRemoveClaim(stale);
        }

        var tenantId = identity.FindFirst(OctoClaimTypes.TenantId)?.Value;
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            return;
        }

        var normalized = NormalizeTenantId(tenantId);
        string? value;
        if (context.Transaction.Properties.TryGetValue(CarriedGrantGenerationPropertyName, out var carried) &&
            carried is CarriedGrantGeneration carriedValue &&
            string.Equals(carriedValue.TenantId, normalized, StringComparison.Ordinal))
        {
            // A mismatched grant redeemed in LogOnly: the rotated grant keeps the old value (see the property).
            value = carriedValue.Value;
        }
        else
        {
            var result = context.Transaction.Properties.TryGetValue(LookupPropertyName, out var stored) &&
                         stored is LookupResult lookup &&
                         string.Equals(lookup.TenantId, normalized, StringComparison.Ordinal)
                ? lookup
                : await ReadAsync(context, lifecycleStore, logger, tenantId);
            if (result != null)
            {
                // Later stamps of the same request (access token, other grants) reuse this read.
                context.Transaction.Properties[LookupPropertyName] = result;
            }

            value = result?.Value;
        }

        if (value is null)
        {
            return;
        }

        // No destination: the claim stays in the stored (encrypted) grant and never reaches a token or userinfo.
        identity.AddClaim(new Claim(OctoClaimTypes.GrantTenantGeneration, value, ClaimValueTypes.String));
    }

    private static async ValueTask StampAsync(ProcessSignInContext context, ClaimsPrincipal? principal,
        ITenantLifecycleStore lifecycleStore, ILogger logger)
    {
        if (principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        // A principal built by this service never carries tenant_gen; drop anything that might have been copied in,
        // so the value on the token is always the one read for this request.
        foreach (var stale in identity.FindAll(OctoClaimTypes.TenantGeneration).ToList())
        {
            identity.TryRemoveClaim(stale);
        }

        var tenantId = identity.FindFirst(OctoClaimTypes.TenantId)?.Value;
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            return;
        }

        // Normally Lookup has read the record before redemption. Fall back to a read here only when it did not run
        // for this tenant (another endpoint issuing an access token, or a principal whose tenant changed).
        var result = context.Transaction.Properties.TryGetValue(LookupPropertyName, out var stored) &&
                     stored is LookupResult lookup &&
                     string.Equals(lookup.TenantId, NormalizeTenantId(tenantId), StringComparison.Ordinal)
            ? lookup
            : await ReadAsync(context, lifecycleStore, logger, tenantId);
        if (result?.Value is not { } value)
        {
            return;
        }

        var claim = new Claim(OctoClaimTypes.TenantGeneration, value, ClaimValueTypes.String);
        claim.SetDestinations(Destinations.AccessToken);
        identity.AddClaim(claim);
    }

    /// <summary>Reads the generation; rejects the context with <c>server_error</c> and returns null on a failure.</summary>
    private static async Task<LookupResult?> ReadAsync(ProcessSignInContext context,
        ITenantLifecycleStore lifecycleStore, ILogger logger, string tenantId)
    {
        var normalized = NormalizeTenantId(tenantId);
        TenantLifecycleRecord? record;
        try
        {
            record = await lifecycleStore.GetAsync(normalized, context.CancellationToken);
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && context.CancellationToken.IsCancellationRequested))
        {
            logger.LogError(ex,
                "Access token for tenant '{TenantId}' refused: the tenant generation could not be read ({ExceptionType})",
                tenantId, ex.GetType().Name);
            context.Reject(
                error: Errors.ServerError,
                description: "The tenant generation could not be read. Try again later.");
            return null;
        }

        return new LookupResult(normalized, record is null ? null : FormatGeneration(record.CreatedUtc));
    }

    /// <summary>
    ///     The <c>tenant_gen</c> value of a lifecycle <c>CreatedUtc</c>: Unix milliseconds as an invariant decimal
    ///     string, or <c>null</c> when the record has no creation time. The value is normalised to UTC exactly like
    ///     <c>CkMethodTenantLifecycleGeneration</c> (octo-common-services, AB#8881): <c>Utc</c> as is, <c>Local</c>
    ///     converted, <c>Unspecified</c> taken as UTC. Sub-millisecond ticks are truncated (BSON dates have
    ///     millisecond precision, so the value read back from MongoDB has none).
    /// </summary>
    public static string? FormatGeneration(DateTime createdUtc)
    {
        if (createdUtc == default)
        {
            return null;
        }

        var utc = createdUtc.Kind switch
        {
            DateTimeKind.Utc => createdUtc,
            DateTimeKind.Local => createdUtc.ToUniversalTime(),
            _ => DateTime.SpecifyKind(createdUtc, DateTimeKind.Utc)
        };

        // Integer division of the ticks since the epoch: truncation, never rounding.
        var milliseconds = (utc.Ticks - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerMillisecond;
        return milliseconds.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>The key of the lifecycle record (same form as AB#8881: trimmed, lower case).</summary>
    internal static string NormalizeTenantId(string tenantId) => tenantId.Trim().ToLowerInvariant();
}
