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
///         the existing tenant keeps it. Resource services compare it with the current generation of the tenant (AB#8999), so a token of a
///         deleted tenant is not accepted by a new tenant with the same id.
///     </para>
///     <list type="bullet">
///         <item>Runs once per sign-in that generates an access token, after OpenIddict built the access-token
///             principal — so it covers every grant (authorization code, device code, refresh token, client
///             credentials, token exchange, on-behalf-of, impersonation) and any grant added later, without a
///             change in <c>TokenEndpointController</c>.</item>
///         <item>The claim is added to the access-token principal only: it never reaches the id token, the
///             userinfo response, or the principal stored in a refresh token / authorization code. A refresh grant
///             therefore reads the generation again at issuance instead of copying it.</item>
///         <item>No lifecycle record, or a record without <c>CreatedUtc</c> (legacy tenants, a system tenant
///             without a record): no claim, issuance succeeds.</item>
///         <item>The lifecycle read fails: the token request fails with <c>server_error</c> — never a token without
///             the claim for a tenant that may have a generation. The log names the tenant and the exception, never
///             a token or a secret.</item>
///         <item>One lifecycle read per issued access token; nothing on token validation.</item>
///     </list>
/// </summary>
public sealed class OctoTenantGenerationClaimHandler(
    ITenantLifecycleStore lifecycleStore,
    ILogger<OctoTenantGenerationClaimHandler> logger) : IOpenIddictServerHandler<ProcessSignInContext>
{
    /// <summary>
    ///     Runs right after <see cref="OpenIddictServerHandlers.PrepareAccessTokenPrincipal" /> (which applies the
    ///     claim destinations) and before the access token is generated.
    /// </summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .AddFilter<OpenIddictServerHandlerFilters.RequireAccessTokenGenerated>()
            .UseSingletonHandler<OctoTenantGenerationClaimHandler>()
            .SetOrder(OpenIddictServerHandlers.PrepareAccessTokenPrincipal.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var principal = context.AccessTokenPrincipal;
        if (principal?.Identity is not ClaimsIdentity identity)
        {
            return;
        }

        // A principal built by this service never carries tenant_gen; drop anything that might have been copied in,
        // so the value on the token is always the one read below.
        foreach (var stale in identity.FindAll(OctoClaimTypes.TenantGeneration).ToList())
        {
            identity.TryRemoveClaim(stale);
        }

        var tenantId = identity.FindFirst(OctoClaimTypes.TenantId)?.Value;
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            return;
        }

        TenantLifecycleRecord? record;
        try
        {
            record = await lifecycleStore.GetAsync(NormalizeTenantId(tenantId), context.CancellationToken);
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && context.CancellationToken.IsCancellationRequested))
        {
            logger.LogError(ex,
                "Access token for tenant '{TenantId}' refused: the tenant generation could not be read ({ExceptionType})",
                tenantId, ex.GetType().Name);
            context.Reject(
                error: Errors.ServerError,
                description: "The tenant generation could not be read. Try again later.");
            return;
        }

        var value = record is null ? null : FormatGeneration(record.CreatedUtc);
        if (value is null)
        {
            return;
        }

        var claim = new Claim(OctoClaimTypes.TenantGeneration, value, ClaimValueTypes.String);
        claim.SetDestinations(Destinations.AccessToken);
        identity.AddClaim(claim);
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
