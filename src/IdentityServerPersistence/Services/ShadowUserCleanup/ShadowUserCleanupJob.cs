using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.ShadowUserCleanup;

/// <summary>Runs the cleanup of rights-less cross-tenant shadow users once over all tenants (AB#8305).</summary>
public interface IShadowUserCleanupJob
{
    /// <summary>
    ///     Runs the cleanup in <paramref name="mode" /> over the system tenant and every registered tenant. Off returns
    ///     at once without reading anything. A failing tenant is logged and does not stop the others.
    /// </summary>
    Task RunOnceAsync(ShadowUserCleanupMode mode, CancellationToken cancellationToken = default);
}

/// <inheritdoc />
/// <remarks>
///     First every tenant's external tenant user mappings are read, because the chain-source rule looks across tenants.
///     If one of those reads fails, an Apply run is downgraded to DryRun for all tenants: without every mapping it cannot
///     be ruled out that a user is the source of a mapping elsewhere. Several identity replicas each run the job; the
///     plan is re-checked per user before the delete and a second Apply finds nothing, so the result is the same.
/// </remarks>
public sealed class ShadowUserCleanupJob(
    ITenantRegistry tenantRegistry,
    ISystemContext systemContext,
    IGroupRoleResolver groupRoleResolver,
    ILogger<ShadowUserCleanupJob> logger,
    IEventRepository? eventRepository = null) : IShadowUserCleanupJob
{
    public async Task RunOnceAsync(ShadowUserCleanupMode mode, CancellationToken cancellationToken = default)
    {
        if (mode == ShadowUserCleanupMode.Off)
        {
            return;
        }

        var tenants = new List<(string TenantId, ITenantRepository Repository)>();
        var tenantIds = new List<string> { systemContext.TenantId };
        tenantIds.AddRange((await tenantRegistry.GetRegisteredTenantsAsync()).Select(t => t.TenantId));
        foreach (var tenantId in tenantIds.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var repository = await tenantRegistry.TryGetRepositoryAsync(tenantId);
            if (repository == null)
            {
                logger.LogWarning("ShadowUserCleanup {Mode}: tenant '{TenantId}' has no repository, skipped", mode, tenantId);
                continue;
            }

            tenants.Add((tenantId, repository));
        }

        Func<string, string, Task>? audit = eventRepository == null
            ? null
            : (tenantId, message) => eventRepository.StoreInformationEvent(tenantId, RtEventSourcesEnum.IdentityService, message);

        await RunAsync(tenants, mode,
            repository => new OctoUserStore(new FixedTenantResolver(repository), groupRoleResolver, null),
            audit, logger, cancellationToken);
    }

    /// <summary>The run over a given tenant list; separated from tenant discovery for tests.</summary>
    internal static async Task<IReadOnlyList<ShadowUserCleanupTenantResult>> RunAsync(
        IReadOnlyList<(string TenantId, ITenantRepository Repository)> tenants,
        ShadowUserCleanupMode mode,
        Func<ITenantRepository, IUserStore<RtUser>> userStoreFactory,
        Func<string, string, Task>? audit,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        if (mode == ShadowUserCleanupMode.Off)
        {
            return [];
        }

        var effectiveMode = mode;
        var allMappings = new List<ShadowUserMappingSource>();
        foreach (var (tenantId, repository) in tenants)
        {
            try
            {
                allMappings.AddRange(await TenantShadowUserCleanup.ReadMappingSourcesAsync(repository));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex,
                    "ShadowUserCleanup {Mode}: reading the mappings of tenant '{TenantId}' failed; the chain-source rule " +
                    "cannot be decided, so this run deletes nothing", mode, tenantId);
                effectiveMode = ShadowUserCleanupMode.DryRun;
            }
        }

        if (effectiveMode != mode)
        {
            logger.LogWarning("ShadowUserCleanup: Apply downgraded to DryRun for this run");
        }

        var results = new List<ShadowUserCleanupTenantResult>();
        var failed = 0;
        foreach (var (tenantId, repository) in tenants)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var userStore = userStoreFactory(repository);
                results.Add(await TenantShadowUserCleanup.RunAsync(
                    tenantId, repository, effectiveMode, allMappings, userStore, audit, logger, cancellationToken));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failed++;
                logger.LogError(ex, "ShadowUserCleanup {Mode}: tenant '{TenantId}' failed; the other tenants continue",
                    effectiveMode, tenantId);
            }
        }

        logger.LogInformation(
            "ShadowUserCleanup {Mode} finished: {TenantCount} tenants ({FailedCount} failed), {ShadowUserCount} xt_ users, " +
            "{CandidateCount} candidates, {DeletedCount} deleted",
            effectiveMode, tenants.Count, failed, results.Sum(r => r.Decisions.Count), results.Sum(r => r.CandidateCount),
            results.Sum(r => r.Deleted.Count));
        return results;
    }

    /// <summary>Binds a store to one tenant repository, independent of any request's tenant.</summary>
    private sealed class FixedTenantResolver(ITenantRepository repository) : IMultiTenancyResolverService
    {
        public ITenantRepository GetTenantRepository() => repository;
        public string GetTenantId() => repository.TenantId;
    }
}
