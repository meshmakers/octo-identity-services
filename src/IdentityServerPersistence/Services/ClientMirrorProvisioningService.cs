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
                //     dedup branch inside UpsertClientInChildAsync erases the stale row. Without
                //     this re-call the tracker would forever say "already present" and the
                //     duplicate would survive every restart (begdemo 2026-06-19 incident).
                //   * Drift repair: secret rotation / scope changes on the parent that fell
                //     behind on this child (e.g. a transient repo failure during SyncMirrorsForClient
                //     post-commit hook) get re-applied on the next service restart, matching the
                //     intent that the parent is the single source of truth for mirror state.
                var mirrorForVerify = CreateMirrorClient(parentTenantId, parentClient);
                await UpsertClientInChildAsync(childRepo, childSession, mirrorForVerify);
                alreadyPresent++;
                continue;
            }

            // 2a. Materialize the mirror client in the child tenant's DB. Same idempotent
            //     query-or-insert pattern used by DefaultConfigurationCreatorService for
            //     the built-in OctoTool/Studio/Swagger clients.
            var mirror = CreateMirrorClient(parentTenantId, parentClient);
            await UpsertClientInChildAsync(childRepo, childSession, mirror);

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
                var updatedMirror = CreateMirrorClient(parentTenantId, parentClient);
                await UpsertClientInChildAsync(childRepo, childSession, updatedMirror);

                mirror.SecretHashVersion += 1;
                await parentRepo.ReplaceOneRtEntityByIdAsync(parentSession, mirror.RtId, mirror);

                synced++;
                await PublishCorsClientsUpdateAsync(mirror.ChildTenantId);
                logger.LogInformation(
                    "Synced client mirror: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}' version={Version}",
                    parentClient.ClientId, parentTenantId, mirror.ChildTenantId, mirror.SecretHashVersion);
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

        int inSync = 0, repaired = 0, removed = 0, skipped = 0, failed = 0;
        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                switch (await ReconcileMirrorAsync(parentRepo, parentSession, parentTenantId, row))
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
                // Another writer (the immediate sync of a newer change, or the job on another replica) changed the
                // mirror between our read and our write; nothing was written. The next pass compares again.
                skipped++;
                logger.LogDebug(
                    "Mirror reconciliation skipped clientId='{ClientId}' child='{ChildTenantId}': changed concurrently",
                    row.ParentClientId, row.ChildTenantId);
            }
            catch (Exception ex)
            {
                failed++;
                logger.LogError(ex,
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
    ///     Brings one tracked mirror to the state the parent client dictates (AB#8019). Writes only on a difference.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         🔴 <b>Read order is load-bearing.</b> The child mirror is read <i>before</i> the parent client, and the
    ///         repair is a version-checked replace with the version that was read. Every write of the mirror (the
    ///         immediate sync after a parent change, this job on another replica) increments its version. So a write
    ///         that happened after our child read makes our replace fail (nothing written, next pass), and a write
    ///         before it is visible to the comparison — while the parent state we compare against was read after that
    ///         write and is therefore at least as new as the one it carried. A slow pass can never put a removed
    ///         secret back.
    ///     </para>
    ///     <para>
    ///         The tracking row is the authority on "this client is mirrored there": a tracked mirror follows its
    ///         parent client even when the parent's <c>AutoProvisionInChildTenants</c> flag was switched off later.
    ///         A tracked mirror whose parent client no longer exists (the cleanup after the delete failed) is removed,
    ///         but only a child client that carries this parent's mirror marker.
    ///     </para>
    /// </remarks>
    private async Task<MirrorReconcileOutcome> ReconcileMirrorAsync(ITenantRepository parentRepo,
        IOctoSession parentSession, string parentTenantId, RtClientMirror row)
    {
        if (string.IsNullOrWhiteSpace(row.ParentClientId) || string.IsNullOrWhiteSpace(row.ChildTenantId))
        {
            return MirrorReconcileOutcome.Skipped;
        }

        var childRepo = await systemContext.TryFindTenantRepositoryAsync(row.ChildTenantId);
        if (childRepo == null)
        {
            // The PreDeleteTenant consumer drops rows of deleted tenants; a tenant that is only unreachable right now
            // must not lose its tracking row.
            logger.LogDebug("Mirror reconciliation: child tenant '{ChildTenantId}' not found, skipped",
                row.ChildTenantId);
            return MirrorReconcileOutcome.Skipped;
        }

        using var childSession = await childRepo.GetSessionAsync();

        // 1. Child first (see remarks).
        var childClients = (await childRepo.GetRtEntitiesByTypeAsync<RtClient>(childSession,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, row.ParentClientId)))
            .Items.ToList();

        // 2. Then the parent client.
        var parentClient = (await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(parentSession,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, row.ParentClientId)))
            .Items.FirstOrDefault();

        if (parentClient == null)
        {
            foreach (var orphan in childClients.Where(c =>
                         string.Equals(c.ProvisionedByParentTenantId, parentTenantId, StringComparison.OrdinalIgnoreCase)))
            {
                await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(childSession, orphan.RtId, DeleteOptions.Erase);
            }

            await parentRepo.DeleteOneRtEntityByRtIdAsync<RtClientMirror>(parentSession, row.RtId, DeleteOptions.Erase);
            await PublishCorsClientsUpdateAsync(row.ChildTenantId);
            logger.LogWarning(
                "Mirror reconciliation removed the mirror of deleted client '{ClientId}' (parent '{ParentTenantId}', child '{ChildTenantId}')",
                row.ParentClientId, parentTenantId, row.ChildTenantId);
            return MirrorReconcileOutcome.Removed;
        }

        var desired = CreateMirrorClient(parentTenantId, parentClient);
        if (childClients.Count != 1)
        {
            // Missing mirror (re-create) or duplicate client ids (keep the canonical one): the provisioning upsert
            // already handles both.
            await UpsertClientInChildAsync(childRepo, childSession, desired);
        }
        else
        {
            var current = childClients[0];
            desired.RtId = current.RtId;
            ReconcileOwnSecret(desired, current, childRepo.TenantId);
            if (!MirrorDiffers(desired, current))
            {
                return MirrorReconcileOutcome.InSync;
            }

            await childRepo.ReplaceOneRtEntityByIdAsync(childSession, current.RtId, desired, current.RtVersion);
        }

        row.SecretHashVersion += 1;
        await parentRepo.ReplaceOneRtEntityByIdAsync(parentSession, row.RtId, row);
        await PublishCorsClientsUpdateAsync(row.ChildTenantId);

        // Names only: never a secret value or hash.
        logger.LogInformation(
            "Reconciled client mirror: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}' version={Version}",
            row.ParentClientId, parentTenantId, row.ChildTenantId, row.SecretHashVersion);
        return MirrorReconcileOutcome.Repaired;
    }

    /// <summary>
    ///     <c>true</c> when the stored mirror differs from the desired one in a field that decides who may authenticate
    ///     or what the client may do: the secrets (inherited and own, with expiry), enabled state, secret requirement,
    ///     grant types, scopes, redirect and CORS URIs, the mirror marker. Other fields (names, lifetimes, …) follow
    ///     with the next write of the mirror (immediate sync, start-up provisioning) or with any repair of these.
    /// </summary>
    internal static bool MirrorDiffers(RtClient desired, RtClient current)
    {
        return desired.Enabled != current.Enabled ||
               desired.RequireClientSecret != current.RequireClientSecret ||
               desired.AutoProvisionInChildTenants != current.AutoProvisionInChildTenants ||
               !string.Equals(desired.ProvisionedByParentTenantId, current.ProvisionedByParentTenantId,
                   StringComparison.Ordinal) ||
               !SameSecrets(desired.ClientSecrets, current.ClientSecrets) ||
               !SameStrings(desired.AllowedGrantTypes, current.AllowedGrantTypes) ||
               !SameStrings(desired.AllowedScopes, current.AllowedScopes) ||
               !SameStrings(Uris(desired.RedirectUris), Uris(current.RedirectUris)) ||
               !SameStrings(Uris(desired.PostLogoutRedirectUris), Uris(current.PostLogoutRedirectUris)) ||
               !SameStrings(Uris(desired.AllowedCorsOrigins), Uris(current.AllowedCorsOrigins));
    }

    private static IEnumerable<string>? Uris(IEnumerable<RtClientUriEntryRecord>? entries) =>
        entries?.Select(e => string.Join('\u001f', e.Uri, e.Source));

    private static bool SameStrings(IEnumerable<string>? left, IEnumerable<string>? right) =>
        (left ?? []).Order(StringComparer.Ordinal).SequenceEqual((right ?? []).Order(StringComparer.Ordinal),
            StringComparer.Ordinal);

    private static bool SameSecrets(IEnumerable<RtSecretRecord>? left, IEnumerable<RtSecretRecord>? right)
    {
        static string Key(RtSecretRecord s) =>
            string.Join('\u001f', s.Type, s.Value, s.Description,
                s.ExpirationDateTime?.ToUniversalTime().Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture));

        return (left ?? []).Select(Key).Order(StringComparer.Ordinal)
            .SequenceEqual((right ?? []).Select(Key).Order(StringComparer.Ordinal), StringComparer.Ordinal);
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
        var existing = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(
            childSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, parentClientId));
        var childClient = existing.Items.FirstOrDefault();
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

        var plaintext = ClientMirrorSecrets.GenerateSecret();
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

        await childRepo.ReplaceOneRtEntityByIdAsync(childSession, childClient.RtId, childClient);

        // Bump the same counter the parent-side rotation uses, so an operator reading the mirror
        // list can see that this pair moved.
        mirrorRow.SecretHashVersion += 1;
        await parentRepo.ReplaceOneRtEntityByIdAsync(parentSession, mirrorRow.RtId, mirrorRow);

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
    ///     child tenant already holds, which only <see cref="UpsertClientInChildAsync" /> knows.
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

    private async Task UpsertClientInChildAsync(
        ITenantRepository childRepo, IOctoSession childSession, RtClient mirror)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, mirror.ClientId);
        var existing = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(childSession, queryOptions);
        var existingItems = existing.Items.ToList();

        if (existingItems.Count == 0)
        {
            ReconcileOwnSecret(mirror, existingChild: null, childRepo.TenantId);
            await childRepo.InsertOneRtEntityAsync(childSession, mirror);
            return;
        }

        // Multiple entries with the same OAuth ClientId are an inconsistent state — the
        // protocol client lookup returns the first match and the other(s) become ghosts
        // that fight back at every login attempt. Begdemo's 2026-06-19 stale staging/prod-URI
        // copy alongside the freshly-applied blueprint client at 660…30 was the trigger to
        // harden this path. The blueprint-managed entity (stable rtId 660…xx) is the canonical
        // one — keep it and erase the rest. When no stable-rtId entry is found, fall back to
        // the first match (preserves the original upsert semantics).
        var canonical = existingItems.FirstOrDefault(IsBlueprintRtId)
                        ?? existingItems[0];

        if (existingItems.Count > 1)
        {
            foreach (var duplicate in existingItems)
            {
                if (duplicate.RtId.Equals(canonical.RtId))
                {
                    continue;
                }

                logger.LogWarning(
                    "Removing duplicate RtClient with clientId='{ClientId}' rtId='{RtId}' from tenant '{TenantId}': "
                    + "keeping canonical rtId='{CanonicalRtId}' (blueprint-stable={IsBlueprintStable}).",
                    mirror.ClientId, duplicate.RtId, childRepo.TenantId, canonical.RtId,
                    IsBlueprintRtId(canonical));

                await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(
                    childSession, duplicate.RtId, DeleteOptions.Erase);
            }
        }

        // Reuse the canonical RtId on the child side; secret/scope changes still propagate.
        mirror.RtId = canonical.RtId;
        ReconcileOwnSecret(mirror, canonical, childRepo.TenantId);
        await childRepo.ReplaceOneRtEntityByIdAsync(childSession, mirror.RtId, mirror);
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
