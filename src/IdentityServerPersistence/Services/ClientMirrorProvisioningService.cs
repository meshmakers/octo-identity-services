using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.Extensions.Logging;
using IdentityServerPersistence.Services.ScratchTenants;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <inheritdoc cref="IClientMirrorProvisioningService"/>
public class ClientMirrorProvisioningService(
    ILogger<ClientMirrorProvisioningService> logger,
    ISystemContext systemContext,
    ITenantDiscoveryService tenantDiscoveryService,
    IDistributionEventHubService? distributionEventHubService = null,
    IScratchTenantGrantService? scratchTenantGrantService = null)
    : IClientMirrorProvisioningService
{
    /// <summary>
    ///     AB#5487: tells every Identity pod that the client (and with it the CORS origins) of a tenant changed, so
    ///     the cached CORS policy is rebuilt. Without it a tenant that gets its app client mirrored in after the
    ///     first request stays blind to the SPA until the cache expires. A failing publish is logged and never
    ///     fails the provisioning: the policy cache has a TTL and heals anyway.
    /// </summary>
    private static readonly TimeSpan PublishTimeout = TimeSpan.FromSeconds(5);

    private async Task PublishCorsClientsUpdateAsync(string tenantId)
    {
        if (distributionEventHubService == null)
        {
            return;
        }

        try
        {
            // The publish goes through the message broker, and a MassTransit send endpoint waits for the broker to be
            // reachable without a bound of its own. A provisioning (a tenant setup, a test host without a broker) must
            // never wait for that: the wait is bounded, and a late answer is only observed, never awaited.
            var publish = distributionEventHubService.PublishAsync(
                new CorsClientsUpdate(tenantId, Guid.NewGuid(), DateTime.Now));
            _ = publish.ContinueWith(static t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            await publish.WaitAsync(PublishTimeout).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to publish CorsClientsUpdate for tenant '{TenantId}'; the CORS policy cache heals on its TTL",
                tenantId);
        }
    }

    /// <summary>
    ///     AB#6758: a mirror is only ever created, rotated or removed in a tenant of the parent's own subtree; the
    ///     system tenant as parent reaches every tenant. The controller filter checks the same rule at the door —
    ///     this check keeps the service safe for every other caller as well.
    /// </summary>
    private async Task EnsureChildInParentSubtreeAsync(string parentTenantId, string childTenantId)
    {
        var parent = parentTenantId.Trim();
        var child = childTenantId.Trim();

        if (string.Equals(parent, systemContext.TenantId?.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var descendants = await tenantDiscoveryService.GetScopeDescendantsAsync(parent);
        if (descendants != null && descendants.Any(d => string.Equals(d, child, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        logger.LogWarning(
            "Client mirror operation denied, child tenant {ChildTenantId} is outside the subtree of {ParentTenantId} (AB#6758)",
            childTenantId, parentTenantId);
        throw new ClientMirrorScopeException(parentTenantId, childTenantId);
    }

    public async Task<ClientMirrorProvisioningResult> ProvisionForChildTenantAsync(
        string parentTenantId, string childTenantId)
    {
        ValidateTenantIds(parentTenantId, childTenantId);
        if (!string.Equals(parentTenantId, childTenantId, StringComparison.OrdinalIgnoreCase))
        {
            await EnsureChildInParentSubtreeAsync(parentTenantId, childTenantId);
        }

        return await ProvisionForChildTenantCoreAsync(parentTenantId, childTenantId);
    }

    private static void ValidateTenantIds(string parentTenantId, string childTenantId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(childTenantId))
        {
            throw new ArgumentException("Child tenant id is required.", nameof(childTenantId));
        }
    }

    private async Task<ClientMirrorProvisioningResult> ProvisionForChildTenantCoreAsync(
        string parentTenantId, string childTenantId)
    {
        var result = await ProvisionForChildTenantMirrorsAsync(parentTenantId, childTenantId);

        // AB#7192: a mirror that was just (re)created has none of the edges the old record had, so the creator grant of
        // a scratch tenant is re-applied after every provisioning pass. A no-op for every tenant without a marker.
        await EnsureScratchCreatorGrantAsync(childTenantId);
        return result;
    }

    private async Task EnsureScratchCreatorGrantAsync(string childTenantId)
    {
        if (scratchTenantGrantService == null)
        {
            return;
        }

        try
        {
            await scratchTenantGrantService.EnsureGrantAsync(childTenantId);
        }
        catch (Exception ex)
        {
            // A failing grant must not fail the provisioning of the mirrors; the next setup retries it.
            logger.LogError(ex, "Re-applying the scratch creator grant failed for child tenant '{ChildTenantId}'",
                childTenantId);
        }
    }

    private async Task<ClientMirrorProvisioningResult> ProvisionForChildTenantMirrorsAsync(
        string parentTenantId, string childTenantId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(childTenantId))
        {
            throw new ArgumentException("Child tenant id is required.", nameof(childTenantId));
        }

        if (string.Equals(parentTenantId, childTenantId, StringComparison.OrdinalIgnoreCase))
        {
            // Provisioning a tenant into itself is meaningless and would create a self-mirror.
            logger.LogDebug(
                "Skipping client mirror provisioning: parent and child tenant are the same ('{TenantId}')",
                parentTenantId);
            return new ClientMirrorProvisioningResult(0, 0, 0);
        }

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            logger.LogWarning(
                "Skipping client mirror provisioning: parent tenant '{ParentTenantId}' not found",
                parentTenantId);
            return new ClientMirrorProvisioningResult(0, 0, 0);
        }

        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null)
        {
            logger.LogWarning(
                "Skipping client mirror provisioning: child tenant '{ChildTenantId}' not found",
                childTenantId);
            return new ClientMirrorProvisioningResult(0, 0, 0);
        }

        using var parentSession = await parentRepo.GetSessionAsync();
        using var childSession = await childRepo.GetSessionAsync();

        // 1. Enumerate flagged clients in the parent.
        var flaggedClientsResult = await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(
            parentSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(
                    nameof(RtClient.AutoProvisionInChildTenants),
                    FieldFilterOperator.Equals,
                    true));
        var flaggedClients = flaggedClientsResult.Items.ToList();

        if (flaggedClients.Count == 0)
        {
            logger.LogDebug(
                "No clients flagged for auto-provisioning in parent '{ParentTenantId}'",
                parentTenantId);
            return new ClientMirrorProvisioningResult(0, 0, 0);
        }

        var newlyProvisioned = 0;
        var alreadyPresent = 0;

        // 2. For each flagged client: ensure mirror in child + tracking row in parent.
        foreach (var parentClient in flaggedClients)
        {
            // Idempotency: a tracking row in the parent says "we already provisioned this".
            var existingMirrorResult = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
                parentSession,
                RtEntityQueryOptions.Create()
                    .FieldFilter(
                        nameof(RtClientMirror.ParentClientId),
                        FieldFilterOperator.Equals,
                        parentClient.ClientId)
                    .FieldFilter(
                        nameof(RtClientMirror.ChildTenantId),
                        FieldFilterOperator.Equals,
                        childTenantId));

            if (existingMirrorResult.Items.Any())
            {
                // Tracker says this client has been provisioned into this child before. Re-run the
                // upsert anyway so the child-side entity converges on the parent's current state
                // every startup. Two reasons this is load-bearing rather than wasteful:
                //
                //   * Duplicate-clientId healing: when a child tenant was restored from an older
                //     backup or had a manually-edited copy of the same OAuth ClientId, the
                //     dedup branch inside ConvergeChildMirrorAsync erases the stale row. Without
                //     this re-call the tracker would forever say "already present" and the
                //     duplicate would survive every restart (begdemo 2026-06-19 incident).
                //   * Drift repair: secret rotation / scope changes on the parent that fell
                //     behind on this child (e.g. a transient repo failure during SyncMirrorsForClient
                //     post-commit hook) get re-applied on the next service restart, matching the
                //     intent that the parent is the single source of truth for mirror state.
                // AB#8019: the parent is read again after the child (the list above may be older than an
                // immediate sync that already wrote this mirror); the listed client is only the fallback.
                var verifyClientId = parentClient.ClientId;
                var trackedWrite = await ConvergeChildMirrorAsync(childRepo, childSession, parentTenantId,
                    verifyClientId,
                    async () => await FindParentClientAsync(parentRepo, parentSession, verifyClientId) ?? parentClient,
                    skipWhenInSync: false);
                // AB#8054: a mirror this pass had to insert again is claimed by a versioned write of its tracking row,
                // like the reconciliation does; a row that changed or vanished meanwhile withdraws the insert.
                await ClaimTrackingRowAsync(parentRepo, parentSession, existingMirrorResult.Items.First(), trackedWrite,
                    childRepo, childSession);
                alreadyPresent++;
                continue;
            }

            // 2a. Materialize the mirror client in the child tenant's DB. Same idempotent
            //     query-or-insert pattern used by DefaultConfigurationCreatorService for
            //     the built-in OctoTool/Studio/Swagger clients.
            var newClientId = parentClient.ClientId;
            await ConvergeChildMirrorAsync(childRepo, childSession, parentTenantId, newClientId,
                async () => await FindParentClientAsync(parentRepo, parentSession, newClientId) ?? parentClient,
                skipWhenInSync: false);

            // 2b. Record the tracking row in the parent's DB.
            var mirrorRecord = new RtClientMirror
            {
                RtId = OctoObjectId.GenerateNewId(),
                ParentClientId = parentClient.ClientId,
                ParentTenantId = parentTenantId,
                ChildTenantId = childTenantId,
                ProvisionedAt = DateTime.UtcNow,
                SecretHashVersion = 0
            };
            await parentRepo.InsertOneRtEntityAsync(parentSession, mirrorRecord);

            newlyProvisioned++;
            logger.LogInformation(
                "Provisioned client mirror: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}'",
                parentClient.ClientId, parentTenantId, childTenantId);
        }

        if (newlyProvisioned > 0)
        {
            await PublishCorsClientsUpdateAsync(childTenantId);
        }

        return new ClientMirrorProvisioningResult(
            FlaggedClientsConsidered: flaggedClients.Count,
            NewlyProvisioned: newlyProvisioned,
            AlreadyPresent: alreadyPresent);
    }

    public async Task<ClientMirrorSyncResult> SyncMirrorsForClientAsync(
        string parentTenantId, RtClient parentClient)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        ArgumentNullException.ThrowIfNull(parentClient);

        if (string.IsNullOrWhiteSpace(parentClient.ClientId))
        {
            throw new ArgumentException("Parent client must have a ClientId.", nameof(parentClient));
        }

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            logger.LogWarning(
                "Skipping mirror sync: parent tenant '{ParentTenantId}' not found",
                parentTenantId);
            return new ClientMirrorSyncResult(0, 0);
        }

        using var parentSession = await parentRepo.GetSessionAsync();
        var mirrors = await GetMirrorsForClientAsync(parentRepo, parentSession, parentClient.ClientId);

        if (mirrors.Count == 0)
        {
            return new ClientMirrorSyncResult(0, 0);
        }

        var synced = 0;
        var failed = 0;

        foreach (var mirror in mirrors)
        {
            try
            {
                var childRepo = await systemContext.TryFindTenantRepositoryAsync(mirror.ChildTenantId);
                if (childRepo == null)
                {
                    logger.LogWarning(
                        "Mirror sync: child tenant '{ChildTenantId}' not found, leaving stale tracking row",
                        mirror.ChildTenantId);
                    failed++;
                    continue;
                }

                using var childSession = await childRepo.GetSessionAsync();
                var clientId = parentClient.ClientId;

                // AB#8054: the row is read again right before the write (the list above may be older than a removal or
                // another writer); a row that is gone means "not mirrored there any more".
                var row = await FindTrackingRowAsync(parentRepo, parentSession, clientId, mirror.ChildTenantId);
                if (row == null || !row.RtId.Equals(mirror.RtId))
                {
                    logger.LogDebug(
                        "Mirror sync skipped clientId='{ClientId}' child='{ChildTenantId}': tracking row removed concurrently",
                        clientId, mirror.ChildTenantId);
                    continue;
                }

                // AB#8019: version-checked like every mirror writer, and the parent is read again after the child, so a
                // delayed sync never writes an older parent state over a newer one (the passed snapshot is the fallback
                // when the read finds nothing).
                var write = await ConvergeChildMirrorAsync(childRepo, childSession, parentTenantId, clientId,
                    async () => await FindParentClientAsync(parentRepo, parentSession, clientId) ?? parentClient,
                    skipWhenInSync: false);

                // AB#8054: the counter bump is version-checked (a plain replace would neither advance rtVersion nor notice
                // a concurrent writer), and an insert is claimed by it.
                if (!await ClaimTrackingRowAsync(parentRepo, parentSession, row, write, childRepo, childSession))
                {
                    continue;
                }

                synced++;
                await PublishCorsClientsUpdateAsync(mirror.ChildTenantId);
                logger.LogInformation(
                    "Synced client mirror: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}' version={Version}",
                    parentClient.ClientId, parentTenantId, mirror.ChildTenantId, row.SecretHashVersion);
            }
            catch (Exception ex)
            {
                failed++;
                logger.LogError(ex,
                    "Failed to sync mirror clientId='{ClientId}' into child '{ChildTenantId}'",
                    parentClient.ClientId, mirror.ChildTenantId);
            }
        }

        return new ClientMirrorSyncResult(synced, failed);
    }

    public async Task<ClientMirrorReconciliationResult> ReconcileMirrorsAsync(string parentTenantId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            return ClientMirrorReconciliationResult.Empty;
        }

        using var parentSession = await parentRepo.GetSessionAsync();
        var rows = (await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(parentSession,
            RtEntityQueryOptions.Create())).Items.ToList();
        if (rows.Count == 0)
        {
            return ClientMirrorReconciliationResult.Empty;
        }

        // One repository lookup per child tenant and pass, not per row.
        var childRepos = new Dictionary<string, ITenantRepository?>(StringComparer.OrdinalIgnoreCase);
        int inSync = 0, repaired = 0, removed = 0, skipped = 0, failed = 0;
        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                switch (await ReconcileMirrorAsync(parentRepo, parentSession, parentTenantId, row, childRepos))
                {
                    case MirrorReconcileOutcome.InSync:
                        inSync++;
                        break;
                    case MirrorReconcileOutcome.Repaired:
                        repaired++;
                        break;
                    case MirrorReconcileOutcome.Removed:
                        removed++;
                        break;
                    default:
                        skipped++;
                        break;
                }
            }
            catch (RtVersionConflictException)
            {
                // Other writers kept changing the mirror during every attempt; nothing stale was written. Next pass.
                skipped++;
                logger.LogDebug(
                    "Mirror reconciliation skipped clientId='{ClientId}' child='{ChildTenantId}': changed concurrently",
                    row.ParentClientId, row.ChildTenantId);
            }
            catch (EntityNotFoundException)
            {
                // The mirror or its row was removed while we worked on it (RemoveMirrorAsync, client delete cleanup).
                skipped++;
                logger.LogDebug(
                    "Mirror reconciliation skipped clientId='{ClientId}' child='{ChildTenantId}': removed concurrently",
                    row.ParentClientId, row.ChildTenantId);
            }
            catch (Exception ex)
            {
                // Warning, not Error: a half-provisioned or unreachable tenant would otherwise raise an error every pass.
                failed++;
                logger.LogWarning(ex,
                    "Mirror reconciliation failed for clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}'",
                    row.ParentClientId, parentTenantId, row.ChildTenantId);
            }
        }

        return new ClientMirrorReconciliationResult(rows.Count, inSync, repaired, removed, skipped, failed);
    }

    private enum MirrorReconcileOutcome
    {
        InSync,
        Repaired,
        Removed,
        Skipped
    }

    /// <summary>
    ///     Tracked mirrors whose parent client was not found, with the number of consecutive passes that saw it missing
    ///     (per process). A mirror is removed only on the second consecutive miss, so a parent client that is briefly
    ///     absent (erase and re-create) does not lose its mirrors.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> MissingParentPasses =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Consecutive passes a parent client must be missing before its tracked mirror is removed.</summary>
    internal const int MissingParentPassesBeforeRemoval = 2;

    /// <summary>
    ///     Test seam (AB#8019): runs after the parent client was read and before the mirror is written (arguments: client
    ///     id, child tenant id).
    /// </summary>
    internal Func<string, string, Task>? BeforeMirrorWriteForTests { get; set; }

    /// <summary>Test seam (AB#8019): runs in the missing-mirror path after the row was re-read and before the insert.</summary>
    internal Func<string, Task>? BeforeMirrorInsertForTests { get; set; }

    /// <summary>
    ///     Test seam (AB#8054): runs in the missing-mirror path after the child was read (found empty) and before the
    ///     insert, i.e. where another writer can insert the same mirror concurrently.
    /// </summary>
    internal Func<string, string, Task>? BeforeMissingMirrorWriteForTests { get; set; }

    /// <summary>
    ///     Brings one tracked mirror to the state the parent client dictates (AB#8019). Writes only on a difference.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         🔴 <b>Every writer of a mirror takes part in the version check.</b> A plain replace writes the entity as
    ///         given and does not advance <c>rtVersion</c>, so a check is only worth something when every other writer
    ///         (immediate sync, start-up provisioning, mirror secret rotation, this job on another replica) also writes
    ///         with the version it read. All of them go through <see cref="ConvergeChildMirrorAsync" /> or the versioned
    ///         rotation. The child mirror is read <i>before</i> the parent client; a write after our child read makes our
    ///         replace fail (we re-read both and try again), a write before it is visible to the comparison while the
    ///         parent was read after it. A slow pass can never put a removed secret or an old own secret back.
    ///     </para>
    ///     <para>
    ///         <b>Missing mirror.</b> The tracking row is read again right before the insert and written with its version
    ///         afterwards; when that fails (row removed by <c>RemoveMirrorAsync</c> / the client delete cleanup, or another
    ///         replica inserted first), the inserted client is deleted again, so no untracked mirror and no duplicate
    ///         stays behind.
    ///     </para>
    ///     <para>
    ///         The tracking row is the authority on "this client is mirrored there": a tracked mirror follows its parent
    ///         client even when the parent's <c>AutoProvisionInChildTenants</c> flag was switched off later. A tracked
    ///         mirror whose parent client is missing in two consecutive passes is removed, but only a child client that
    ///         carries this parent's mirror marker.
    ///     </para>
    /// </remarks>
    private async Task<MirrorReconcileOutcome> ReconcileMirrorAsync(ITenantRepository parentRepo,
        IOctoSession parentSession, string parentTenantId, RtClientMirror row,
        Dictionary<string, ITenantRepository?> childRepos)
    {
        if (string.IsNullOrWhiteSpace(row.ParentClientId) || string.IsNullOrWhiteSpace(row.ChildTenantId))
        {
            return MirrorReconcileOutcome.Skipped;
        }

        if (!childRepos.TryGetValue(row.ChildTenantId, out var childRepo))
        {
            childRepo = await systemContext.TryFindTenantRepositoryAsync(row.ChildTenantId);
            childRepos[row.ChildTenantId] = childRepo;
        }

        if (childRepo == null)
        {
            // The PreDeleteTenant consumer drops rows of deleted tenants; a tenant that is only unreachable right now
            // must not lose its tracking row.
            logger.LogDebug("Mirror reconciliation: child tenant '{ChildTenantId}' not found, skipped",
                row.ChildTenantId);
            return MirrorReconcileOutcome.Skipped;
        }

        using var childSession = await childRepo.GetSessionAsync();
        var missingKey = $"{parentTenantId}|{row.ParentClientId}|{row.ChildTenantId}";

        // The missing-mirror path inserts; everything else is a version-checked replace.
        var childClients = await GetChildClientsAsync(childRepo, childSession, row.ParentClientId);
        if (childClients.Count == 0)
        {
            return await ReconcileMissingMirrorAsync(parentRepo, parentSession, parentTenantId, row, childRepo,
                childSession, missingKey);
        }

        var write = await ConvergeChildMirrorAsync(childRepo, childSession, parentTenantId, row.ParentClientId,
            async () =>
            {
                var parent = await FindParentClientAsync(parentRepo, parentSession, row.ParentClientId);
                if (parent != null && BeforeMirrorWriteForTests != null)
                {
                    await BeforeMirrorWriteForTests(row.ParentClientId, row.ChildTenantId);
                }

                return parent;
            },
            skipWhenInSync: true, childClientsJustRead: childClients);

        if (write == MirrorWriteResult.ParentMissing)
        {
            return await RemoveOrphanedMirrorAsync(parentRepo, parentSession, parentTenantId, row, childRepo,
                childSession, missingKey);
        }

        MissingParentPasses.TryRemove(missingKey, out _);
        if (write == MirrorWriteResult.InSync)
        {
            return MirrorReconcileOutcome.InSync;
        }

        await BumpTrackingRowAsync(parentRepo, parentSession, row);
        await PublishCorsClientsUpdateAsync(row.ChildTenantId);

        // Names only: never a secret value or hash.
        logger.LogInformation(
            "Reconciled client mirror: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}' version={Version}",
            row.ParentClientId, parentTenantId, row.ChildTenantId, row.SecretHashVersion);
        return MirrorReconcileOutcome.Repaired;
    }

    private async Task<MirrorReconcileOutcome> ReconcileMissingMirrorAsync(ITenantRepository parentRepo,
        IOctoSession parentSession, string parentTenantId, RtClientMirror row, ITenantRepository childRepo,
        IOctoSession childSession, string missingKey)
    {
        var parent = await FindParentClientAsync(parentRepo, parentSession, row.ParentClientId);
        if (parent == null)
        {
            return await RemoveOrphanedMirrorAsync(parentRepo, parentSession, parentTenantId, row, childRepo,
                childSession, missingKey);
        }

        MissingParentPasses.TryRemove(missingKey, out _);

        // Re-read the row right before the insert: a row removed in the meantime means "not mirrored any more".
        var currentRow = await FindTrackingRowAsync(parentRepo, parentSession, row.ParentClientId, row.ChildTenantId);
        if (currentRow == null || !currentRow.RtId.Equals(row.RtId))
        {
            return MirrorReconcileOutcome.Skipped;
        }

        if (BeforeMirrorInsertForTests != null)
        {
            await BeforeMirrorInsertForTests(row.ParentClientId);
        }

        var write = await ConvergeChildMirrorAsync(childRepo, childSession, parentTenantId, row.ParentClientId,
            async () =>
            {
                if (BeforeMissingMirrorWriteForTests != null)
                {
                    await BeforeMissingMirrorWriteForTests(row.ParentClientId, row.ChildTenantId);
                }

                return parent;
            }, skipWhenInSync: true);
        if (write == MirrorWriteResult.InSync)
        {
            return MirrorReconcileOutcome.InSync;
        }

        try
        {
            // The versioned row write claims the insert: it fails when the row was removed or another replica
            // repaired the same mirror first.
            currentRow.SecretHashVersion += 1;
            await parentRepo.ReplaceOneRtEntityByIdAsync(parentSession, currentRow.RtId, currentRow,
                currentRow.RtVersion);
        }
        catch (Exception ex) when (ex is RtVersionConflictException or EntityNotFoundException &&
                                   write.InsertedRtId != null)
        {
            await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(childSession, write.InsertedRtId.Value,
                DeleteOptions.Erase);
            logger.LogDebug(
                "Mirror reconciliation withdrew its insert of clientId='{ClientId}' in child '{ChildTenantId}': the tracking row changed",
                row.ParentClientId, row.ChildTenantId);
            return MirrorReconcileOutcome.Skipped;
        }

        await PublishCorsClientsUpdateAsync(row.ChildTenantId);
        logger.LogInformation(
            "Reconciled client mirror (re-created): clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}' version={Version}",
            row.ParentClientId, parentTenantId, row.ChildTenantId, currentRow.SecretHashVersion);
        return MirrorReconcileOutcome.Repaired;
    }

    private async Task<MirrorReconcileOutcome> RemoveOrphanedMirrorAsync(ITenantRepository parentRepo,
        IOctoSession parentSession, string parentTenantId, RtClientMirror row, ITenantRepository childRepo,
        IOctoSession childSession, string missingKey)
    {
        var passes = MissingParentPasses.AddOrUpdate(missingKey, 1, (_, n) => n + 1);
        if (passes < MissingParentPassesBeforeRemoval)
        {
            logger.LogInformation(
                "Mirror reconciliation: parent client '{ClientId}' of the mirror in '{ChildTenantId}' not found; removing it if still missing on the next pass",
                row.ParentClientId, row.ChildTenantId);
            return MirrorReconcileOutcome.Skipped;
        }

        foreach (var orphan in (await GetChildClientsAsync(childRepo, childSession, row.ParentClientId)).Where(c =>
                     string.Equals(c.ProvisionedByParentTenantId, parentTenantId, StringComparison.OrdinalIgnoreCase)))
        {
            await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(childSession, orphan.RtId, DeleteOptions.Erase);
        }

        await parentRepo.DeleteOneRtEntityByRtIdAsync<RtClientMirror>(parentSession, row.RtId, DeleteOptions.Erase);
        MissingParentPasses.TryRemove(missingKey, out _);
        await PublishCorsClientsUpdateAsync(row.ChildTenantId);
        logger.LogWarning(
            "Mirror reconciliation removed the mirror of deleted client '{ClientId}' (parent '{ParentTenantId}', child '{ChildTenantId}')",
            row.ParentClientId, parentTenantId, row.ChildTenantId);
        return MirrorReconcileOutcome.Removed;
    }

    /// <summary>The counter is informational; a concurrent bump wins and is not retried.</summary>
    private async Task BumpTrackingRowAsync(ITenantRepository parentRepo, IOctoSession parentSession, RtClientMirror row)
    {
        try
        {
            row.SecretHashVersion += 1;
            await parentRepo.ReplaceOneRtEntityByIdAsync(parentSession, row.RtId, row, row.RtVersion);
        }
        catch (RtVersionConflictException)
        {
            logger.LogDebug("Tracking row of clientId='{ClientId}' child='{ChildTenantId}' changed concurrently",
                row.ParentClientId, row.ChildTenantId);
        }
    }

    /// <summary>
    ///     Records a mirror write of the immediate sync or the start-up provisioning on its tracking row (AB#8054). The row
    ///     is written with the version it was read with, so the write advances <c>rtVersion</c> and the reconciliation's
    ///     claim of a re-created mirror sees it. When this writer had to <b>insert</b> the mirror, the row write claims the
    ///     insert: a row that changed (another writer re-created the same mirror) or vanished (<c>RemoveMirrorAsync</c>, the
    ///     client delete cleanup) withdraws the inserted client again, so no duplicate and no untracked mirror stays behind.
    ///     For a replaced or unchanged mirror a concurrent bump wins (the counter is informational).
    /// </summary>
    /// <returns><c>false</c> when the insert was withdrawn.</returns>
    private async Task<bool> ClaimTrackingRowAsync(ITenantRepository parentRepo, IOctoSession parentSession,
        RtClientMirror row, MirrorWriteResult write, ITenantRepository childRepo, IOctoSession childSession)
    {
        if (write.InsertedRtId == null)
        {
            if (write == MirrorWriteResult.Replaced)
            {
                await BumpTrackingRowAsync(parentRepo, parentSession, row);
            }

            return true;
        }

        try
        {
            row.SecretHashVersion += 1;
            await parentRepo.ReplaceOneRtEntityByIdAsync(parentSession, row.RtId, row, row.RtVersion);
            return true;
        }
        catch (Exception ex) when (ex is RtVersionConflictException or EntityNotFoundException)
        {
            await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(childSession, write.InsertedRtId.Value,
                DeleteOptions.Erase);
            logger.LogDebug(
                "Withdrew the insert of the mirror of clientId='{ClientId}' in child '{ChildTenantId}': the tracking row changed",
                row.ParentClientId, row.ChildTenantId);
            return false;
        }
    }

    private static async Task<RtClient?> FindParentClientAsync(ITenantRepository parentRepo,
        IOctoSession parentSession, string clientId) =>
        (await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(parentSession, ByClientId(clientId)))
        .Items.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));

    private static async Task<RtClientMirror?> FindTrackingRowAsync(ITenantRepository parentRepo,
        IOctoSession parentSession, string parentClientId, string childTenantId) =>
        (await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(parentSession, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, parentClientId)
            .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId)))
        .Items.FirstOrDefault(r => string.Equals(r.ParentClientId, parentClientId, StringComparison.Ordinal) &&
                                   string.Equals(r.ChildTenantId, childTenantId, StringComparison.OrdinalIgnoreCase));

    private static async Task<List<RtClient>> GetChildClientsAsync(ITenantRepository childRepo,
        IOctoSession childSession, string clientId) =>
        (await childRepo.GetRtEntitiesByTypeAsync<RtClient>(childSession, ByClientId(clientId)))
        .Items.Where(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal)).ToList();

    private static RtEntityQueryOptions ByClientId(string clientId) => RtEntityQueryOptions.Create()
        .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

    /// <summary>
    ///     <c>true</c> when the stored mirror differs from the desired one in any attribute of the client (secrets incl.
    ///     expiry and own secret, claims, flags, lifetimes, URIs, …). Compared: every property <see cref="RtClient" />
    ///     declares, i.e. every CK attribute; not compared: the entity's id, version, timestamps and other base fields.
    ///     The mirror marker is compared case-insensitively (tenant ids are case-insensitive), lists as multisets,
    ///     records by their attributes, an absent list like an empty one.
    /// </summary>
    internal static bool MirrorDiffers(RtClient desired, RtClient current)
    {
        foreach (var property in ComparedClientProperties)
        {
            var left = property.GetValue(desired);
            var right = property.GetValue(current);
            if (property.Name == nameof(RtClient.ProvisionedByParentTenantId))
            {
                if (!string.Equals(left as string, right as string, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                continue;
            }

            if (!string.Equals(Normalize(left), Normalize(right), StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static readonly System.Reflection.PropertyInfo[] ComparedClientProperties = typeof(RtClient)
        .GetProperties(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public |
                       System.Reflection.BindingFlags.DeclaredOnly)
        .Where(p => p.CanRead && p.GetIndexParameters().Length == 0)
        .ToArray();

    /// <summary>Canonical text of an attribute value: lists sorted, records by their declared attributes, dates in UTC.</summary>
    internal static string Normalize(object? value)
    {
        switch (value)
        {
            case null:
                return string.Empty;
            case string s:
                return "s:" + s;
            case DateTime dt:
                return "d:" + dt.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture);
            case DateTimeOffset dto:
                return "o:" + dto.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture);
            case IFormattable f when value.GetType().IsPrimitive || value is decimal or TimeSpan || value.GetType().IsEnum:
                return value.GetType().Name + ":" + f.ToString(null, System.Globalization.CultureInfo.InvariantCulture);
            case bool b:
                return b ? "b:1" : "b:0";
            case System.Collections.IEnumerable items:
                var parts = items.Cast<object?>().Select(Normalize).Order(StringComparer.Ordinal).ToList();
                return parts.Count == 0 ? string.Empty : "[" + string.Join("\u001e", parts) + "]";
            default:
                var props = value.GetType()
                    .GetProperties(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public |
                                   System.Reflection.BindingFlags.DeclaredOnly)
                    .Where(p => p.CanRead && p.GetIndexParameters().Length == 0)
                    .OrderBy(p => p.Name, StringComparer.Ordinal)
                    .Select(p => p.Name + "=" + Normalize(p.GetValue(value)));
                return "{" + string.Join("\u001f", props) + "}";
        }
    }

    public async Task<ClientMirrorCleanupResult> RemoveMirrorsForClientAsync(
        string parentTenantId, string parentClientId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(parentClientId))
        {
            throw new ArgumentException("Parent client id is required.", nameof(parentClientId));
        }

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            logger.LogWarning(
                "Skipping mirror removal: parent tenant '{ParentTenantId}' not found",
                parentTenantId);
            return new ClientMirrorCleanupResult(0, 0);
        }

        using var parentSession = await parentRepo.GetSessionAsync();
        var mirrors = await GetMirrorsForClientAsync(parentRepo, parentSession, parentClientId);

        if (mirrors.Count == 0)
        {
            return new ClientMirrorCleanupResult(0, 0);
        }

        var removed = 0;
        var failed = 0;

        foreach (var mirror in mirrors)
        {
            try
            {
                var childRepo = await systemContext.TryFindTenantRepositoryAsync(mirror.ChildTenantId);
                if (childRepo != null)
                {
                    using var childSession = await childRepo.GetSessionAsync();
                    await DeleteClientFromChildAsync(childRepo, childSession, parentClientId);
                }
                // If the child tenant is gone, the client is gone too — just drop the
                // tracking row. RemoveMirrorsForChildTenantAsync would otherwise need to
                // run; doing it here keeps the parent-side state consistent regardless.

                await parentRepo.DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
                    parentSession, mirror.RtId, DeleteOptions.Erase);

                removed++;
                await PublishCorsClientsUpdateAsync(mirror.ChildTenantId);
                logger.LogInformation(
                    "Removed client mirror: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}'",
                    parentClientId, parentTenantId, mirror.ChildTenantId);
            }
            catch (Exception ex)
            {
                failed++;
                logger.LogError(ex,
                    "Failed to remove mirror clientId='{ClientId}' in child '{ChildTenantId}'",
                    parentClientId, mirror.ChildTenantId);
            }
        }

        return new ClientMirrorCleanupResult(removed, failed);
    }

    public async Task<int> RemoveMirrorsForChildTenantAsync(
        string parentTenantId, string childTenantId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(childTenantId))
        {
            throw new ArgumentException("Child tenant id is required.", nameof(childTenantId));
        }

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            logger.LogWarning(
                "Skipping mirror-by-tenant cleanup: parent tenant '{ParentTenantId}' not found",
                parentTenantId);
            return 0;
        }

        using var parentSession = await parentRepo.GetSessionAsync();
        var result = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            parentSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(
                    nameof(RtClientMirror.ChildTenantId),
                    FieldFilterOperator.Equals,
                    childTenantId));

        var mirrors = result.Items.ToList();
        var removed = 0;
        foreach (var mirror in mirrors)
        {
            try
            {
                await parentRepo.DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
                    parentSession, mirror.RtId, DeleteOptions.Erase);
                removed++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex,
                    "Failed to drop mirror tracking row {RtId} for child '{ChildTenantId}'",
                    mirror.RtId, childTenantId);
            }
        }

        if (removed > 0)
        {
            logger.LogInformation(
                "Dropped {Count} mirror tracking row(s) for deleted child tenant '{ChildTenantId}' (parent '{ParentTenantId}')",
                removed, childTenantId, parentTenantId);
        }

        return removed;
    }

    public async Task<ClientMirrorBackfillResult?> ProvisionForAllChildTenantsAsync(
        string parentTenantId, string parentClientId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(parentClientId))
        {
            throw new ArgumentException("Parent client id is required.", nameof(parentClientId));
        }

        var parentContext = await systemContext.TryFindTenantContextAsync(parentTenantId);
        if (parentContext == null)
        {
            logger.LogWarning(
                "Backfill: parent tenant '{ParentTenantId}' not found", parentTenantId);
            return null;
        }

        // Guard: only flagged clients can be backfilled. Caller (controller) should have
        // validated this already and returned 400 — this is a defence in depth.
        var parentRepo = parentContext.GetTenantRepositoryAsAdmin();
        using var parentSession = await parentRepo.GetSessionAsync();
        var clientResult = await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(
            parentSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, parentClientId));
        var parentClient = clientResult.Items.FirstOrDefault();
        if (parentClient == null || !parentClient.AutoProvisionInChildTenants)
        {
            return null;
        }

        using var adminSession = await parentContext.GetAdminSessionAsync();

        // AB#5076: which set "every tenant this client should reach" is depends on the parent.
        //
        // Since AB#5025 GetChildTenantsAsync filters by ParentTenantId and returns DIRECT children
        // only. For an ordinary parent tenant that is exactly right — mirroring is one level, and a
        // grandchild is its own parent's business. For the SYSTEM tenant it is not: the caller that
        // matters here (DynamicClientRegistrationService, and the operator's "Provision in existing
        // tenants" button when run there) means every tenant on the instance, and nested tenants
        // from level two down would silently never receive the mirror. That failure surfaces far
        // from its cause — not here, but as an "unknown client" at login in the sub-tenant, and it
        // self-heals only on the next identity restart, when SetupTenantAsync provisions each tenant
        // against the system parent again.
        var isSystemParent = string.Equals(parentTenantId, systemContext.TenantId,
            StringComparison.OrdinalIgnoreCase);
        var childTenants = isSystemParent
            ? await systemContext.GetAllTenantsAsync(adminSession)
            : await parentContext.GetChildTenantsAsync(adminSession);

        var considered = 0;
        var newly = 0;
        var present = 0;

        foreach (var child in childTenants.Items)
        {
            considered++;
            try
            {
                // Reuse ProvisionForChildTenantAsync: it iterates every flagged client in
                // the parent, not just this one. That is intentional — the operator's
                // expectation when clicking "Provision in existing tenants" is "make every
                // flagged client present everywhere it should be", and this avoids
                // duplicating the provisioning logic for the single-client case.
                var perChildResult = await ProvisionForChildTenantCoreAsync(parentTenantId, child.TenantId);
                newly += perChildResult.NewlyProvisioned;
                present += perChildResult.AlreadyPresent;
            }
            catch (Exception ex)
            {
                logger.LogError(ex,
                    "Backfill into child '{ChildTenantId}' failed", child.TenantId);
            }
        }

        return new ClientMirrorBackfillResult(considered, newly, present);
    }

    public async Task<IReadOnlyList<RtClientMirror>> GetMirrorsAsync(
        string parentTenantId, string parentClientId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(parentClientId))
        {
            throw new ArgumentException("Parent client id is required.", nameof(parentClientId));
        }

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            return Array.Empty<RtClientMirror>();
        }

        using var parentSession = await parentRepo.GetSessionAsync();
        return await GetMirrorsForClientAsync(parentRepo, parentSession, parentClientId);
    }

    public Task<ClientMirrorProvisioningResult> ProvisionInTenantAsync(
        string parentTenantId, string parentClientId, string childTenantId)
    {
        // The per-child provisioning already filters by flagged clients in the parent,
        // so passing the clientId here is informational only. We could short-circuit if
        // the named client either doesn't exist or isn't flagged, but ProvisionForChildTenantAsync
        // already returns "0 considered" in that case — keep it simple.
        _ = parentClientId;
        return ProvisionForChildTenantAsync(parentTenantId, childTenantId);
    }

    public async Task<bool> RemoveMirrorAsync(
        string parentTenantId, string parentClientId, string childTenantId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(parentClientId))
        {
            throw new ArgumentException("Parent client id is required.", nameof(parentClientId));
        }

        if (string.IsNullOrWhiteSpace(childTenantId))
        {
            throw new ArgumentException("Child tenant id is required.", nameof(childTenantId));
        }

        await EnsureChildInParentSubtreeAsync(parentTenantId, childTenantId);

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            return false;
        }

        using var parentSession = await parentRepo.GetSessionAsync();
        var lookup = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            parentSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(
                    nameof(RtClientMirror.ParentClientId),
                    FieldFilterOperator.Equals,
                    parentClientId)
                .FieldFilter(
                    nameof(RtClientMirror.ChildTenantId),
                    FieldFilterOperator.Equals,
                    childTenantId));
        var mirror = lookup.Items.FirstOrDefault();
        if (mirror == null)
        {
            return false;
        }

        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo != null)
        {
            using var childSession = await childRepo.GetSessionAsync();
            await DeleteClientFromChildAsync(childRepo, childSession, parentClientId);
        }

        await parentRepo.DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
            parentSession, mirror.RtId, DeleteOptions.Erase);

        await PublishCorsClientsUpdateAsync(childTenantId);

        logger.LogInformation(
            "Removed client mirror manually: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}'",
            parentClientId, parentTenantId, childTenantId);
        return true;
    }

    public async Task<MirrorSecretRotationResult?> RotateMirrorSecretAsync(
        string parentTenantId, string parentClientId, string childTenantId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            throw new ArgumentException("Parent tenant id is required.", nameof(parentTenantId));
        }

        if (string.IsNullOrWhiteSpace(parentClientId))
        {
            throw new ArgumentException("Parent client id is required.", nameof(parentClientId));
        }

        if (string.IsNullOrWhiteSpace(childTenantId))
        {
            throw new ArgumentException("Child tenant id is required.", nameof(childTenantId));
        }

        await EnsureChildInParentSubtreeAsync(parentTenantId, childTenantId);

        var parentRepo = await systemContext.TryFindTenantRepositoryAsync(parentTenantId);
        if (parentRepo == null)
        {
            return null;
        }

        using var parentSession = await parentRepo.GetSessionAsync();

        // The tracking row is the authority on "this client is mirrored into that tenant". Rotating
        // against an untracked pair would mint a secret on some unrelated client that happens to
        // share the id in the child tenant.
        var lookup = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            parentSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(
                    nameof(RtClientMirror.ParentClientId),
                    FieldFilterOperator.Equals,
                    parentClientId)
                .FieldFilter(
                    nameof(RtClientMirror.ChildTenantId),
                    FieldFilterOperator.Equals,
                    childTenantId));
        var mirrorRow = lookup.Items.FirstOrDefault();
        if (mirrorRow == null)
        {
            return null;
        }

        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null)
        {
            logger.LogWarning(
                "Mirror secret rotation: child tenant '{ChildTenantId}' not found", childTenantId);
            return null;
        }

        using var childSession = await childRepo.GetSessionAsync();
        var plaintext = ClientMirrorSecrets.GenerateSecret();
        for (var attempt = 1;; attempt++)
        {
            var childClient = (await GetChildClientsAsync(childRepo, childSession, parentClientId)).FirstOrDefault();
            if (childClient == null)
            {
                logger.LogWarning(
                    "Mirror secret rotation: client '{ClientId}' not present in child tenant '{ChildTenantId}' "
                    + "although a tracking row exists", parentClientId, childTenantId);
                return null;
            }

            if (!ClientMirrorSecrets.IsConfidential(childClient))
            {
                return MirrorSecretRotationResult.PublicClient();
            }

            var replacement = ClientMirrorSecrets.CreateOwnSecretRecord(plaintext);
            var secrets = childClient.ClientSecrets ?? new AttributeRecordValueList<RtSecretRecord>();
            var retained = secrets.Where(s => !ClientMirrorSecrets.IsOwnSecret(s)).ToList();
            var rebuilt = new AttributeRecordValueList<RtSecretRecord>();
            foreach (var secret in retained)
            {
                rebuilt.Add(secret);
            }

            rebuilt.Add(replacement);
            childClient.ClientSecrets = rebuilt;
            childClient.RequireClientSecret = true;

            try
            {
                // AB#8019: version-checked, so the mirror reconciliation (which reads the mirror before it writes)
                // can never write the previous own secret back over this one.
                await childRepo.ReplaceOneRtEntityByIdAsync(childSession, childClient.RtId, childClient,
                    childClient.RtVersion);
                break;
            }
            catch (RtVersionConflictException) when (attempt < MaxMirrorWriteAttempts)
            {
                // Another writer changed the mirror: read it again and apply the new own secret on top.
            }
        }

        // Bump the same counter the parent-side rotation uses, so an operator reading the mirror
        // list can see that this pair moved.
        // AB#8054: version-checked like every tracking-row write; a concurrent bump wins (the counter is informational).
        await BumpTrackingRowAsync(parentRepo, parentSession, mirrorRow);

        // 🔴 The plaintext is deliberately absent from this line and from every other log statement.
        logger.LogInformation(
            "Rotated the own secret of the mirror of client '{ClientId}' in tenant '{ChildTenantId}' "
            + "(parent '{ParentTenantId}', version {Version})",
            parentClientId, childTenantId, parentTenantId, mirrorRow.SecretHashVersion);

        return MirrorSecretRotationResult.Issued(plaintext);
    }

    private static async Task<List<RtClientMirror>> GetMirrorsForClientAsync(
        ITenantRepository parentRepo, IOctoSession parentSession, string parentClientId)
    {
        var result = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            parentSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(
                    nameof(RtClientMirror.ParentClientId),
                    FieldFilterOperator.Equals,
                    parentClientId));
        return result.Items.ToList();
    }

    private static async Task DeleteClientFromChildAsync(
        ITenantRepository childRepo, IOctoSession childSession, string clientId)
    {
        var existing = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(
            childSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        var found = existing.Items.FirstOrDefault();
        if (found != null)
        {
            await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(
                childSession, found.RtId, DeleteOptions.Erase);
        }
    }

    /// <summary>
    /// Returns a copy of the parent client suitable for insertion into the child tenant's DB:
    /// fresh <c>RtId</c>, identical <c>ClientId</c> + secrets + scopes + everything else.
    /// <c>AutoProvisionInChildTenants</c> is intentionally NOT propagated — only the parent
    /// owns the flag; a mirror is never itself a source of further mirroring.
    /// </summary>
    /// <remarks>
    ///     The mirror's <b>own</b> secret (AB#5061) is not decided here — it depends on what the
    ///     child tenant already holds, which only <see cref="ConvergeChildMirrorAsync" /> knows.
    ///     This method produces the inherited state; that one reconciles the own secret on top.
    /// </remarks>
    private static RtClient CreateMirrorClient(string parentTenantId, RtClient parentClient)
    {
        return new RtClient
        {
            RtId = OctoObjectId.GenerateNewId(),
            Enabled = parentClient.Enabled,
            ClientId = parentClient.ClientId,
            ProtocolType = parentClient.ProtocolType,
            // 🔴 Defensive copy. Assigning the parent's list by reference would make the own-secret
            // reconciliation below mutate the *parent* client's in-memory secret list — and
            // SyncMirrorsForClientAsync hands the same parent instance to every child in the loop,
            // so each child would accumulate the previous children's secrets and write them back.
            ClientSecrets = CopySecrets(parentClient.ClientSecrets),
            RequireClientSecret = parentClient.RequireClientSecret,
            ClientName = parentClient.ClientName,
            Description = parentClient.Description,
            ClientUri = parentClient.ClientUri,
            LogoUri = parentClient.LogoUri,
            RequireConsent = parentClient.RequireConsent,
            AllowRememberConsent = parentClient.AllowRememberConsent,
            AllowedGrantTypes = parentClient.AllowedGrantTypes,
            RequirePkce = parentClient.RequirePkce,
            AllowPlainTextPkce = parentClient.AllowPlainTextPkce,
            RequireRequestObject = parentClient.RequireRequestObject,
            AllowAccessTokensViaBrowser = parentClient.AllowAccessTokensViaBrowser,
            RequireDPoP = parentClient.RequireDPoP,
            DPoPValidationMode = parentClient.DPoPValidationMode,
            DPoPClockSkew = parentClient.DPoPClockSkew,
            RedirectUris = parentClient.RedirectUris,
            PostLogoutRedirectUris = parentClient.PostLogoutRedirectUris,
            FrontChannelLogoutUri = parentClient.FrontChannelLogoutUri,
            FrontChannelLogoutSessionRequired = parentClient.FrontChannelLogoutSessionRequired,
            BackChannelLogoutUri = parentClient.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = parentClient.BackChannelLogoutSessionRequired,
            AllowOfflineAccess = parentClient.AllowOfflineAccess,
            AllowedScopes = parentClient.AllowedScopes,
            AlwaysIncludeUserClaimsInIdToken = parentClient.AlwaysIncludeUserClaimsInIdToken,
            IdentityTokenLifetime = parentClient.IdentityTokenLifetime,
            AllowedIdentityTokenSigningAlgorithms = parentClient.AllowedIdentityTokenSigningAlgorithms,
            AccessTokenLifetime = parentClient.AccessTokenLifetime,
            AuthorizationCodeLifetime = parentClient.AuthorizationCodeLifetime,
            AbsoluteRefreshTokenLifetime = parentClient.AbsoluteRefreshTokenLifetime,
            SlidingRefreshTokenLifetime = parentClient.SlidingRefreshTokenLifetime,
            ConsentLifetime = parentClient.ConsentLifetime,
            UpdateAccessTokenClaimsOnRefresh = parentClient.UpdateAccessTokenClaimsOnRefresh,
            RefreshTokenExpiration = parentClient.RefreshTokenExpiration,
            AccessTokenType = parentClient.AccessTokenType,
            EnableLocalLogin = parentClient.EnableLocalLogin,
            IdentityProviderRestrictions = parentClient.IdentityProviderRestrictions,
            IncludeJwtId = parentClient.IncludeJwtId,
            ClientClaims = parentClient.ClientClaims,
            AlwaysSendClientClaims = parentClient.AlwaysSendClientClaims,
            ClientClaimsPrefix = parentClient.ClientClaimsPrefix,
            PairWiseSubjectSalt = parentClient.PairWiseSubjectSalt,
            UserSsoLifetime = parentClient.UserSsoLifetime,
            UserCodeType = parentClient.UserCodeType,
            DeviceCodeLifetime = parentClient.DeviceCodeLifetime,
            CibaLifetime = parentClient.CibaLifetime,
            PollingInterval = parentClient.PollingInterval,
            CoordinateLifetimeWithUserSession = parentClient.CoordinateLifetimeWithUserSession,
            AllowedCorsOrigins = parentClient.AllowedCorsOrigins,
            InitiateLoginUri = parentClient.InitiateLoginUri,
            AutoProvisionInChildTenants = false,
            ProvisionedByParentTenantId = parentTenantId
        };
    }

    /// <summary>
    ///     Inclusive lower bound of the stable rtId range used by
    ///     <c>System.Identity.Bootstrap-1.x.x</c> seed entities. Mirrors the same constant on
    ///     <see cref="Services.Migrations.PreBlueprintCleanupMigration"/>; kept duplicated here to
    ///     avoid a one-way dependency from the mirror service onto the migration class.
    /// </summary>
    private static readonly OctoObjectId StableRtIdRangeStart =
        new("660000000000000000000000");

    /// <summary>
    ///     Exclusive upper bound. Anything &gt;= this is outside the blueprint range.
    /// </summary>
    private static readonly OctoObjectId StableRtIdRangeEndExclusive =
        new("670000000000000000000000");

    /// <summary>Attempts of a version-checked mirror write before the conflict is reported to the caller.</summary>
    internal const int MaxMirrorWriteAttempts = 5;

    /// <summary>Outcome of <see cref="ConvergeChildMirrorAsync" />.</summary>
    private sealed record MirrorWriteResult(string Kind, OctoObjectId? InsertedRtId = null)
    {
        public static readonly MirrorWriteResult InSync = new("InSync");
        public static readonly MirrorWriteResult ParentMissing = new("ParentMissing");
        public static readonly MirrorWriteResult Replaced = new("Replaced");
        public static MirrorWriteResult Inserted(OctoObjectId rtId) => new("Inserted", rtId);
    }

    /// <summary>
    ///     The one write path of a child-tenant mirror (sync, start-up provisioning, reconciliation; AB#8019): read the
    ///     child's clients of that id, then the parent client (<paramref name="readParent" />), derive the mirror
    ///     (<see cref="CreateMirrorClient" /> + <see cref="ReconcileOwnSecret" />) and write it. No client yet: insert.
    ///     Otherwise the canonical record (blueprint rtId range, else the first) is kept, duplicates are erased and the
    ///     canonical one is replaced <b>with the version that was read</b>; a concurrent writer makes the replace fail,
    ///     and the read-derive-write runs again (at most <see cref="MaxMirrorWriteAttempts" /> times, then the
    ///     <see cref="RtVersionConflictException" /> reaches the caller). Every writer must use this path or another
    ///     version-checked write: a plain replace does not advance <c>rtVersion</c> and would defeat the check.
    /// </summary>
    private async Task<MirrorWriteResult> ConvergeChildMirrorAsync(ITenantRepository childRepo,
        IOctoSession childSession, string parentTenantId, string clientId, Func<Task<RtClient?>> readParent,
        bool skipWhenInSync, List<RtClient>? childClientsJustRead = null)
    {
        for (var attempt = 1;; attempt++)
        {
            // The caller may hand over the child read it just made (first attempt only; a retry always reads again).
            var existingItems = attempt == 1 && childClientsJustRead != null
                ? childClientsJustRead
                : await GetChildClientsAsync(childRepo, childSession, clientId);
            var parentClient = await readParent();
            if (parentClient == null)
            {
                return MirrorWriteResult.ParentMissing;
            }

            var mirror = CreateMirrorClient(parentTenantId, parentClient);
            if (existingItems.Count == 0)
            {
                ReconcileOwnSecret(mirror, existingChild: null, childRepo.TenantId);
                await childRepo.InsertOneRtEntityAsync(childSession, mirror);
                return MirrorWriteResult.Inserted(mirror.RtId);
            }

            // Multiple entries with the same OAuth ClientId are an inconsistent state — the
            // protocol client lookup returns the first match and the other(s) become ghosts
            // that fight back at every login attempt. Begdemo's 2026-06-19 stale staging/prod-URI
            // copy alongside the freshly-applied blueprint client at 660…30 was the trigger to
            // harden this path. The blueprint-managed entity (stable rtId 660…xx) is the canonical
            // one — keep it and erase the rest. When no stable-rtId entry is found, fall back to
            // the first match (preserves the original upsert semantics).
            var canonical = existingItems.FirstOrDefault(IsBlueprintRtId) ?? existingItems[0];
            foreach (var duplicate in existingItems.Where(d => !d.RtId.Equals(canonical.RtId)))
            {
                logger.LogWarning(
                    "Removing duplicate RtClient with clientId='{ClientId}' rtId='{RtId}' from tenant '{TenantId}': "
                    + "keeping canonical rtId='{CanonicalRtId}' (blueprint-stable={IsBlueprintStable}).",
                    mirror.ClientId, duplicate.RtId, childRepo.TenantId, canonical.RtId, IsBlueprintRtId(canonical));
                await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(childSession, duplicate.RtId,
                    DeleteOptions.Erase);
            }

            // Reuse the canonical RtId on the child side; secret/scope changes still propagate.
            mirror.RtId = canonical.RtId;
            ReconcileOwnSecret(mirror, canonical, childRepo.TenantId);
            if (skipWhenInSync && existingItems.Count == 1 && !MirrorDiffers(mirror, canonical))
            {
                return MirrorWriteResult.InSync;
            }

            try
            {
                await childRepo.ReplaceOneRtEntityByIdAsync(childSession, canonical.RtId, mirror, canonical.RtVersion);
                return MirrorWriteResult.Replaced;
            }
            catch (RtVersionConflictException) when (attempt < MaxMirrorWriteAttempts)
            {
                // Another writer changed the mirror after our read: read child and parent again and re-derive.
            }
        }
    }

    /// <summary>
    ///     Gives the mirror of a confidential parent its <b>own</b> secret (AB#5061), so that
    ///     possession of a child tenant's credentials proves that tenant and nothing more.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         🔴 <b>Preservation is the load-bearing half.</b> This runs on every provisioning pass
    ///         and on every parent-side secret rotation, and the mirror written back is built from
    ///         the <i>parent's</i> state — so without carrying the existing own secret across, each
    ///         service restart would silently invalidate every per-tenant credential handed out so
    ///         far. Exactly the trap already documented for the AB#5027 bus consumer, in the one
    ///         other place a client is replaced wholesale.
    ///     </para>
    ///     <para>
    ///         A public parent gets nothing: it has no secret to shadow, and inventing one would
    ///         turn a public client into a confidential one in the child tenant only.
    ///     </para>
    ///     <para>
    ///         ⚠️ The inherited copy of the parent's secret stays alongside it — see
    ///         <see cref="ClientMirrorSecrets" /> for why, and for when it goes away.
    ///     </para>
    /// </remarks>
    private void ReconcileOwnSecret(RtClient mirror, RtClient? existingChild, string childTenantId)
    {
        if (!ClientMirrorSecrets.IsConfidential(mirror))
        {
            return;
        }

        // An own secret already handed out for this tenant must survive. Never re-generate:
        // the plaintext is unrecoverable, so a fresh hash would lock the holder out.
        var carriedOver = existingChild is null ? null : ClientMirrorSecrets.FindOwnSecret(existingChild);
        if (carriedOver != null)
        {
            mirror.ClientSecrets.Add(new RtSecretRecord
            {
                Type = carriedOver.Type,
                Value = carriedOver.Value,
                Description = carriedOver.Description,
                ExpirationDateTime = carriedOver.ExpirationDateTime
            });
            return;
        }

        // First materialization of this mirror. The generated plaintext is deliberately dropped
        // here and never persisted or logged; the holder obtains a usable value by rotating
        // (POST .../mirrors/{childTenantId}/secret), which is the only path that ever reveals one.
        mirror.ClientSecrets.Add(ClientMirrorSecrets.CreateOwnSecretRecord(
            ClientMirrorSecrets.GenerateSecret()));

        logger.LogInformation(
            "Provisioned an own secret for the mirror of client '{ClientId}' in tenant '{ChildTenantId}'. "
            + "The inherited parent secret is still accepted there (AB#5061) — rotate the mirror secret "
            + "and migrate the caller to close the instance-wide credential.",
            mirror.ClientId, childTenantId);
    }

    /// <summary>
    ///     Defensive copy of a secret list, so a mirror never shares the parent's list instance.
    /// </summary>
    private static AttributeRecordValueList<RtSecretRecord> CopySecrets(
        IAttributeValueList<RtSecretRecord>? source)
    {
        var copy = new AttributeRecordValueList<RtSecretRecord>();
        if (source == null)
        {
            return copy;
        }

        foreach (var secret in source)
        {
            // The expiry travels too (AB#8019): without it a parent secret that expired kept authenticating in every
            // child tenant, because the token endpoint skips expired records only.
            copy.Add(new RtSecretRecord
            {
                Type = secret.Type,
                Value = secret.Value,
                Description = secret.Description,
                ExpirationDateTime = secret.ExpirationDateTime
            });
        }

        return copy;
    }

    private static bool IsBlueprintRtId(RtClient entity)
    {
        return IsBlueprintRtId(entity.RtId);
    }

    private static bool IsBlueprintRtId(OctoObjectId rtId)
    {
        return rtId.CompareTo(StableRtIdRangeStart) >= 0
               && rtId.CompareTo(StableRtIdRangeEndExclusive) < 0;
    }
}
