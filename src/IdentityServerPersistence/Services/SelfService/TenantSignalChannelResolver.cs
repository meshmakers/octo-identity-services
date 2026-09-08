using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     CK-backed implementation of <see cref="ITenantSignalChannelResolver" /> (AB#5154). Reads the
///     tenant's <c>System.Communication/SignalChannel</c> entity through
///     <see cref="ISystemContext.TryFindTenantRepositoryAsync" /> — the same explicit-tenant
///     persistence access <c>ClientMirrorProvisioningService</c> uses — because the OTP delivery
///     channel is a singleton with no HTTP-scoped tenant: the tenant id travels in the
///     <see cref="OtpDeliveryContext" />.
/// </summary>
/// <remarks>
///     The SignalChannel type belongs to the System.Communication CK model (owned by the
///     Communication Controller), so this repo has no generated entity type for it; the read is a
///     generic <see cref="RtEntity" /> query by CK type id with attribute-name access. Mirrors the
///     controller's own projection guards (<c>AdapterService.AddSignalChannelConfigurationAsync</c>):
///     a read failure (e.g. a tenant whose System.Communication model predates 3.34.0 and has no
///     SignalChannel type) is logged and treated as "no channel" — never fatal — and a hand-crafted
///     multi-channel tie is broken deterministically by lowest rtId with a warning.
/// </remarks>
public sealed class TenantSignalChannelResolver(
    ISystemContext systemContext,
    ILogger<TenantSignalChannelResolver> logger) : ITenantSignalChannelResolver
{
    /// <summary>CK type id of the tenant-owned Signal channel entity (AB#5143).</summary>
    public const string SignalChannelCkTypeId = "System.Communication/SignalChannel";

    /// <summary>
    ///     <c>System.Communication/SignalRegistrationState.Registered</c>. The enum lives in the
    ///     Communication Controller's CK model; only its numeric value crosses this repo boundary.
    /// </summary>
    private const int RegisteredState = 2;

    public async Task<TenantSignalBridgeEndpoint?> ResolveRegisteredChannelAsync(
        string tenantId, CancellationToken cancellationToken = default)
    {
        try
        {
            var repository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
            if (repository == null)
            {
                logger.LogDebug(
                    "[{TenantId}] AB#5154 no tenant repository resolvable; no tenant SignalChannel",
                    tenantId);
                return null;
            }

            var session = await repository.GetSessionAsync();
            session.StartTransaction();
            var result = await repository.GetRtEntitiesByTypeAsync(
                session, SignalChannelCkTypeId, RtEntityQueryOptions.Create());
            await session.CommitTransactionAsync();

            var registered = result.Items
                .Where(e => e.GetAttributeValueOrStandard(
                    "RegistrationState", -1) == RegisteredState)
                // Multiple channels should not exist (singleton by design, service-enforced) — a
                // hand-crafted tie is broken deterministically, same ordering as the controller's
                // pipeline-configuration projection.
                .OrderBy(e => e.RtId.ToString(), StringComparer.Ordinal)
                .ToList();

            if (registered.Count == 0)
            {
                return null;
            }

            var channel = registered[0];
            if (registered.Count > 1)
            {
                logger.LogWarning(
                    "[{TenantId}] AB#5154 tenant carries {Count} Registered SignalChannel definitions; using '{RtId}'. The channel is a singleton — remove the others.",
                    tenantId, registered.Count, channel.RtId);
            }

            var apiUrl = channel.GetAttributeStringValueOrDefault("ApiUrl");
            var number = channel.GetAttributeStringValueOrDefault("Number");
            if (string.IsNullOrWhiteSpace(apiUrl) || string.IsNullOrWhiteSpace(number))
            {
                // Both attributes are mandatory on the CK type; an entity missing them is
                // hand-crafted. Treat as unusable rather than sending from a half-configured
                // channel — the caller falls back to SignalBridgeOptions.
                logger.LogWarning(
                    "[{TenantId}] AB#5154 Registered SignalChannel '{RtId}' misses Number/ApiUrl; ignoring it",
                    tenantId, channel.RtId);
                return null;
            }

            return new TenantSignalBridgeEndpoint(apiUrl, number);
        }
        catch (Exception e)
        {
            // Same rationale as the controller's projection: the tenant channel is an enrichment
            // over the env-bound fallback. A tenant whose CK model has no SignalChannel type (or a
            // transient read failure) must not break OTP delivery where SignalBridgeOptions or the
            // dev stub would still serve it.
            logger.LogWarning(e,
                "[{TenantId}] AB#5154 could not read the tenant's SignalChannel; falling back to SignalBridgeOptions",
                tenantId);
            return null;
        }
    }
}
