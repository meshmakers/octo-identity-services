using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services.Migrations;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.BlueprintCatalogs;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Blueprints;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.ConstructionKit.Models.System.Generated.System.v2;
using Meshmakers.Octo.Runtime.Contracts.CkModelMigrations;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

// ReSharper disable once ClassNeverInstantiated.Global
internal class DefaultConfigurationCreatorService(
    ILogger<DefaultConfigurationCreatorService> logger,
    ISystemContext systemContext,
    IDiagnosticsService diagnosticsService,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    MigrationService? migrationService,
    IClientMirrorProvisioningService? clientMirrorProvisioningService = null,
    ICkModelUpgradeService? ckModelUpgradeService = null,
    IRuntimeRepositoryProvider? runtimeRepositoryProvider = null,
    IBlueprintService? blueprintService = null,
    IEnumerable<IBlueprintEmbeddedSource>? embeddedBlueprintSources = null)
    : DefaultConfigurationCreatorServiceBase(logger, blueprintService, embeddedBlueprintSources),
      IConfigurationService
{
    /// <summary>
    ///     Identity owns two blueprint namespaces: <c>System.Identity.</c> (its own bootstrap)
    ///     and <c>System.Notification.</c> (the Notification bootstrap, which Identity drives
    ///     because the templates are an Identity-side concern even though the CK types belong
    ///     to <c>System.Notification</c>). The base class's single <see cref="ServiceManagedBlueprintPrefix"/>
    ///     can only carry one prefix, so we override <see cref="IsServiceManagedBlueprint"/>
    ///     instead and short-circuit to the two-prefix match. Auto-applied by
    ///     <see cref="SetupTenantAsync"/> on cold init and by <see cref="RefreshTenantStateAsync"/>
    ///     on every tenant lifecycle event.
    /// </summary>
    protected override bool IsServiceManagedBlueprint(BlueprintId blueprintId)
    {
        return blueprintId.Name.StartsWith("System.Identity.", StringComparison.Ordinal)
               || blueprintId.Name.StartsWith("System.Notification.", StringComparison.Ordinal);
    }

    /// <summary>
    ///     Re-applies the <c>System.Identity.Bootstrap-1.0.0</c> blueprint on every tenant
    ///     lifecycle event (Enable / Restore / DeferTenantStart=false). Together with the
    ///     unconditional apply in <see cref="SetupTenantAsync"/> this guarantees the seed
    ///     entities stay aligned with the embedded blueprint version. Operators still drive
    ///     blueprint version bumps via image deploys; the engine then picks up the new
    ///     version on the next pod restart or lifecycle event without further intervention.
    /// </summary>
    /// <remarks>
    ///     <c>throwOnFailure: false</c> so a transient blueprint failure (e.g. catalog lookup
    ///     hiccup) does not knock a tenant offline. Failures are logged + surfaced via
    ///     <see cref="DefaultConfigurationCreatorServiceBase.OnServiceManagedBlueprintApplyFailedAsync"/>.
    /// </remarks>
    protected override async Task RefreshTenantStateAsync(string tenantId)
    {
        await ApplyServiceManagedBlueprintsAsync(tenantId, throwOnFailure: false).ConfigureAwait(false);
    }

    public override async Task InitializeAsync()
    {
        // Reconfigure the log level based on the configuration
        await diagnosticsService.ReconfigureLogLevelAsync(octoIdentityOptions.Value.MinLogLevel);

        await base.InitializeAsync();
    }

    protected override async Task SetupTenantAsync(string tenantId)
    {
        // Capture schema versions BEFORE any CK model updates
        // This must happen FIRST so we can detect version changes for migration
        IReadOnlyDictionary<string, string>? previousSchemaVersions = null;
        if (runtimeRepositoryProvider != null && ckModelUpgradeService != null)
        {
            previousSchemaVersions = await runtimeRepositoryProvider
                .GetSchemaVersionsAsync(tenantId, CancellationToken.None);

            if (previousSchemaVersions.Count > 0)
            {
                logger.LogDebug(
                    "Captured {Count} schema versions before import for tenant '{TenantId}'",
                    previousSchemaVersions.Count, tenantId);
            }
        }

        // 1st, we ensure that the system tenant and its ck model exists
        if (tenantId == systemContext.TenantId)
        {
            // Ensure that the system ck model is available with the current version,
            // This method ensures that the system repository database is already existing, but not
            // up-to-date.
            await systemContext.EnsureSystemCkModelAsync();

            // So upgrades are done now. If it still does not exist -> create it from scratch.
            if (!await systemContext.IsSystemTenantExistingAsync())
            {
                await systemContext.CreateSystemTenantAsync();
            }
        }

        var tenantContext = tenantId == systemContext.TenantId
            ? systemContext
            : await systemContext.GetChildTenantContextAsync(tenantId);

        // Ensure that the identity ck model and notification ck model is imported
        await ImportCkModel(tenantContext);

        // Run CK model data migrations (transforms existing runtime entities)
        await RunCkModelMigrationsAsync(tenantContext, previousSchemaVersions);

        // we run the infrastructure migrations for each tenant context
        if (migrationService != null)
        {
            using var adminSession = await tenantContext.GetAdminSessionAsync();
            await migrationService.ExecuteMigrationsAsync(adminSession, tenantContext);
        }

        // Phase 3 PR #4: declarative seed via System.Identity.Bootstrap-1.0.0 blueprint —
        // replaces the previous ~800 LOC of CreateUsersAndRoles / CreateDefaultGroupsAsync /
        // CreateApiScopes / CreateApiResources / CreateIdentityResources / CreateIdentityProvider /
        // CreateClients / EnsureRefineryStudioClientAsync and the per-child
        // EnsureIdentityDataInChildTenantAsync write-through. The blueprint upserts every
        // seed entity by stable rtId (660…01..40 range), so the same call services system tenant
        // and child tenants identically. The Phase 2 isRuntimeState contract protects volatile
        // attributes; static attributes (DisplayName, Claims, redirect URIs) are overwritten on
        // every version bump — which is exactly how operator-driven drift recovery works after
        // Phase 3 ships. RefineryStudioUrl / AuthorityUrl flow through IdentityBlueprintVariableProvider
        // (PR #3) so URL changes propagate without code edits.
        //
        // throwOnFailure: true — a failed Identity seed cannot leave a tenant in a half-provisioned
        // state. Treat as a fatal startup error; the tenant fails to come up and the failure surfaces
        // in pod logs immediately instead of silently breaking OIDC.
        //
        // AB#4209 Step 2 — source-aware URI preservation across the blueprint re-apply. Capture
        // every Source != "base" entry on the 5 blueprint-managed clients (rtId 660…30..34) BEFORE
        // the apply wipes the URI lists with the seed values, then merge the captured entries back
        // in afterwards. Without this wrap any URI entry that the operator added through the REST
        // API (Source = "api") or the future overlay cmdlet (Source = "overlay:<name>") would be
        // destroyed on every Identity restart — silently regressing the operator's configuration.
        // The capture / merge are idempotent: if the seed re-asserts a URI that previously held a
        // non-base source, the seed value wins and the captured copy is dropped (Uri-keyed dedup
        // in BlueprintClientUriPreservation.Merge).
        var capturedNonBaseUris = await CaptureBlueprintClientNonBaseUrisAsync(tenantContext);
        await ApplyServiceManagedBlueprintsAsync(tenantId, throwOnFailure: true);
        await RestoreBlueprintClientNonBaseUrisAsync(tenantContext, capturedNonBaseUris);

        // Phase 3 PR #4 post-blueprint restore: PreBlueprintCleanupMigration captures every
        // User → Role and ExternalTenantUserMapping → Role assignment by role NAME into
        // SystemConfiguration[PendingPostBlueprintRoleAssignmentsKey] before deleting the OLD
        // entities. Now that the blueprint has installed the NEW roles with stable rtIds
        // (660…01..0E), look the names up and re-attach the assignments via fresh AssignedRole
        // edges. The pending row is deleted on success — if Identity crashes mid-restore the
        // next startup retries with the same data.
        await RestorePendingRoleAssignmentsAsync(tenantContext);

        // Child-tenant client mirror provisioning runs AFTER the blueprint apply has guaranteed
        // the parent tenant's RtClient entities exist. Idempotent — runs on every startup so
        // backfill happens naturally for tenants that pre-date the AutoProvisionInChildTenants
        // flag being set on a parent-tenant client. Hard-wired parent = system tenant; nested
        // customer sub-tenants tracked in
        // octo-communication-controller-services/docs/concepts/cicd-workload-deployment.md.
        if (tenantId != systemContext.TenantId && clientMirrorProvisioningService != null)
        {
            try
            {
                var result = await clientMirrorProvisioningService
                    .ProvisionForChildTenantAsync(systemContext.TenantId, tenantId);
                if (result.NewlyProvisioned > 0 || result.AlreadyPresent > 0)
                {
                    logger.LogInformation(
                        "Client mirror provisioning for '{TenantId}': considered={Considered}, " +
                        "newly provisioned={New}, already present={Existing}",
                        tenantId,
                        result.FlaggedClientsConsidered,
                        result.NewlyProvisioned,
                        result.AlreadyPresent);
                }
            }
            catch (Exception ex)
            {
                // Provisioning failure must not break tenant setup. Surface it loudly,
                // operator can re-trigger via the backfill endpoint (#4045).
                logger.LogError(ex,
                    "Client mirror provisioning failed for child tenant '{TenantId}'", tenantId);
            }
        }
    }

    /// <summary>
    ///     AB#4209 Step 2 pre-blueprint pass: snapshot every <c>Source != "base"</c> URI entry
    ///     on each blueprint-managed <see cref="RtClient"/> so the subsequent
    ///     <see cref="DefaultConfigurationCreatorServiceBase.ApplyServiceManagedBlueprintsAsync"/>
    ///     call can rewrite the URI lists from the seed without destroying operator-added URIs
    ///     (REST-API <c>"api"</c> source) and overlay-cmdlet URIs (<c>"overlay:&lt;name&gt;"</c>
    ///     source). The capture is restricted to the blueprint-stable rtId range (660…00..FF) —
    ///     operator-created clients outside that range are left alone because the blueprint apply
    ///     doesn't touch them anyway.
    /// </summary>
    /// <returns>
    ///     A dictionary of per-client captures (empty when no preservation is needed). The caller
    ///     hands this verbatim to <see cref="RestoreBlueprintClientNonBaseUrisAsync"/> after the
    ///     apply.
    /// </returns>
    private async Task<IReadOnlyDictionary<OctoObjectId, NonBaseUriCapture>>
        CaptureBlueprintClientNonBaseUrisAsync(ITenantContext tenantContext)
    {
        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        // Push the blueprint-stable-rtId filter down to the query so we don't transfer every
        // operator-created client only to discard it in BlueprintClientUriPreservation.Capture.
        // BlueprintClientUriPreservation.IsBlueprintStableRtId still gates the in-memory side as
        // defense-in-depth so the helper stays correct if a future caller hands it pre-loaded
        // entities that include operator-created clients.
        var clients = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(
            session,
            RtEntityQueryOptions.Create()
                .FieldGreaterEqualThan("rtId", BlueprintClientUriPreservation.StableRtIdRangeStart)
                .FieldLessThan("rtId", BlueprintClientUriPreservation.StableRtIdRangeEndExclusive));

        await session.CommitTransactionAsync();

        var captures = BlueprintClientUriPreservation.Capture(clients.Items);

        if (captures.Count > 0)
        {
            logger.LogDebug(
                "Captured non-base URI entries on {Count} blueprint-managed client(s) " +
                "for tenant '{TenantId}' before blueprint apply",
                captures.Count, tenantContext.TenantId);
        }

        return captures;
    }

    /// <summary>
    ///     AB#4209 Step 2 post-blueprint pass: re-applies captured non-base URI entries on each
    ///     blueprint-managed <see cref="RtClient"/> that the apply just rewrote. Each captured
    ///     entry is appended only when its URI is not already present in the post-apply list — the
    ///     seed wins on URI collisions, the captured copy wins on novel entries. Clients whose
    ///     merge yields no append are not written back.
    /// </summary>
    private async Task RestoreBlueprintClientNonBaseUrisAsync(
        ITenantContext tenantContext,
        IReadOnlyDictionary<OctoObjectId, NonBaseUriCapture> captured)
    {
        if (captured.Count == 0)
        {
            return;
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var restoredClients = 0;
        var restoredEntries = 0;
        foreach (var (clientRtId, capture) in captured)
        {
            var postApplyClient = await tenantRepository
                .GetRtEntityByRtIdAsync<RtClient>(session, clientRtId);
            if (postApplyClient == null)
            {
                // The apply removed the client entirely (e.g. blueprint version dropped one of the
                // 660…30..34 entries). Don't recreate it from a stale mirror — that would resurrect
                // a client the seed deliberately retired. Just drop the captured non-base entries.
                logger.LogWarning(
                    "Skipping non-base URI restore for clientId='{ClientId}' rtId='{RtId}' on " +
                    "tenant '{TenantId}': client no longer exists after blueprint apply",
                    capture.ClientId, clientRtId, tenantContext.TenantId);
                continue;
            }

            var mutated = BlueprintClientUriPreservation.Merge(postApplyClient, capture);
            if (!mutated)
            {
                // Every captured non-base entry collided with a seed URI — the merge is a no-op.
                continue;
            }

            await tenantRepository.ReplaceOneRtEntityByIdAsync(session, clientRtId, postApplyClient);
            restoredClients++;
            restoredEntries += capture.RedirectUris.Count
                               + capture.PostLogoutRedirectUris.Count
                               + capture.AllowedCorsOrigins.Count;
        }

        await session.CommitTransactionAsync();

        if (restoredClients > 0)
        {
            logger.LogInformation(
                "Restored non-base URI entries on {Clients} blueprint-managed client(s) for " +
                "tenant '{TenantId}' (up to {Entries} entries merged, post-apply seed collisions skipped)",
                restoredClients, tenantContext.TenantId, restoredEntries);
        }
    }

    /// <summary>
    /// Reads the PendingPostBlueprintRoleAssignments TenantConfiguration row written by
    /// <c>PreBlueprintCleanupMigration</c>, looks up each captured role name against the blueprint's
    /// stable-rtId Role entities, and replays an AssignedRole edge from every captured origin to
    /// the matching new Role. Idempotent: a successful run deletes the row so the next startup
    /// is a fast read-and-skip. If Identity crashes mid-restore the row stays and the next
    /// startup retries with the same data — the restore is safe to run twice because the engine
    /// silently no-ops when the same association already exists.
    /// </summary>
    private async Task RestorePendingRoleAssignmentsAsync(ITenantContext tenantContext)
    {
        using var session = await tenantContext.GetAdminSessionAsync();
        var pending = await tenantContext.GetConfigurationAsync<PendingPostBlueprintRoleAssignments>(
            session, IdentityServiceConstants.PendingPostBlueprintRoleAssignmentsKey,
            defaultValue: null);
        if (pending == null
            || (pending.UserRoles.Count == 0 && pending.ExternalMappingRoles.Count == 0))
        {
            return;
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        using var writeSession = await tenantRepository.GetSessionAsync();
        writeSession.StartTransaction();

        // Build a name → new-Role-rtId index once from the blueprint-seeded entities. This used
        // to be a straight `.ToDictionary(r => r.Name)` which crashed Identity startup on test-2
        // 2026-06-15 when the broken pre-blueprint cleanup migration left a pair of
        // <name="AdminPanelManagement", rtId=686a…> + <name="AdminPanelManagement", rtId=660…05>
        // for every imperative-seed role. `An item with the same key has already been added`
        // took the host down.
        //
        // Defensive build: tolerate duplicates by preferring the blueprint-range entity (660…
        // first byte = 0x66, see PreBlueprintCleanupMigration.IsBlueprintRtId), log a structured
        // warning so the duplicates are still visible and chasable, and continue. The companion
        // PR #94 fix to the cleanup migration prevents the duplicates from forming in the first
        // place; this safety net catches any future variant of the same trap (e.g. an operator
        // who manually creates a duplicate Role.Name, or a blueprint-version bump that lands a
        // new well-known name colliding with an operator role).
        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(
            writeSession, RtEntityQueryOptions.Create());
        var rolesByName = BuildRoleNameIndex(roles.Items, tenantContext.TenantId, logger);

        var restored = 0;
        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        // Users: re-emit AssignedRole associations (the schema-defined edge type for User → Role).
        restored += await ReattachAsync(pending.UserRoles, userCkTypeId);

        // ExternalTenantUserMapping: roles live in the MappedRoleIds attribute (per the
        // System.Identity CK schema; no AssignedRole edges are allowed). Resolve each captured
        // role name to the new stable rtId and rewrite the attribute in place.
        restored += await RewriteMappedRoleIdsAsync(pending.ExternalMappingRoles);

        await writeSession.CommitTransactionAsync();

        // Pending row is cleared in a separate session so we don't tangle the configuration
        // collection write with the AssignedRole edge writes above.
        using (var clearSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                clearSession,
                IdentityServiceConstants.PendingPostBlueprintRoleAssignmentsKey,
                new PendingPostBlueprintRoleAssignments());
        }

        logger.LogInformation(
            "Post-blueprint role restore for tenant '{TenantId}': re-attached {Count} AssignedRole edges " +
            "across {UserCount} users and {MappingCount} external mappings",
            tenantContext.TenantId, restored,
            pending.UserRoles.Count, pending.ExternalMappingRoles.Count);

        return;

        async Task<int> ReattachAsync(
            Dictionary<string, List<string>> originGroup,
            RtCkId<CkTypeId> originCkTypeId)
        {
            var count = 0;
            foreach (var (originRtIdHex, roleNames) in originGroup)
            {
                var originRtId = new OctoObjectId(originRtIdHex);
                foreach (var roleName in roleNames)
                {
                    if (!rolesByName.TryGetValue(roleName, out var newRoleRtId))
                    {
                        logger.LogWarning(
                            "Post-blueprint role restore: role '{RoleName}' captured for origin " +
                            "{OriginRtId} not found among the blueprint-seeded roles in tenant " +
                            "'{TenantId}'. Edge skipped.",
                            roleName, originRtIdHex, tenantContext.TenantId);
                        continue;
                    }

                    var update = AssociationUpdateInfo.CreateInsert(
                        new RtEntityId(originCkTypeId, originRtId),
                        new RtEntityId(roleCkTypeId, newRoleRtId),
                        IdentityAssociationConstants.AssignedRoleId);
                    var opResult = new OperationResult();
                    await tenantRepository.ApplyChangesAsync(writeSession, new[] { update }, opResult);
                    count++;
                }
            }

            return count;
        }

        async Task<int> RewriteMappedRoleIdsAsync(Dictionary<string, List<string>> mappingRoles)
        {
            var count = 0;
            foreach (var (mappingRtIdHex, roleNames) in mappingRoles)
            {
                var mappingRtId = new OctoObjectId(mappingRtIdHex);
                var mapping = await tenantRepository
                    .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(writeSession, mappingRtId);
                if (mapping == null)
                {
                    continue;
                }

                var resolved = new List<string>();
                foreach (var roleName in roleNames)
                {
                    if (rolesByName.TryGetValue(roleName, out var newRoleRtId))
                    {
                        resolved.Add(newRoleRtId.ToString());
                    }
                    else
                    {
                        logger.LogWarning(
                            "Post-blueprint role restore: role '{RoleName}' captured for mapping " +
                            "{MappingRtId} not found among the blueprint-seeded roles in tenant " +
                            "'{TenantId}'. Entry dropped from MappedRoleIds.",
                            roleName, mappingRtIdHex, tenantContext.TenantId);
                    }
                }

                mapping.MappedRoleIds = new AttributeStringValueList(resolved);
                var update = EntityUpdateInfo<RtExternalTenantUserMapping>.CreateUpdate(
                    mapping.ToRtEntityId(), mapping);
                var opResult = new OperationResult();
                await tenantRepository.ApplyChangesAsync(
                    writeSession, new[] { update }, opResult);
                count += resolved.Count;
            }

            return count;
        }
    }

    private async Task ImportCkModel(ITenantContext tenantContext)
    {
        if (!await tenantContext.IsCkModelExistingAsync(SystemIdentityCkIds.CkModelId))
        {
            // Install the Identity CK model in all tenants (needed for cross-tenant authentication
            // and role mapping). The model is required for ExternalTenantUserMapping and
            // OctoTenantIdentityProvider entities.
            OperationResult operationResult = new();
            await tenantContext.ImportCkModelAsync(SystemIdentityCkIds.CkModelId, operationResult);
            if (operationResult.HasErrors || operationResult.HasFatalErrors)
            {
                throw InitializationException.ImportCkModelFailed(tenantContext.TenantId,
                    operationResult.GetMessages());
            }
        }

        if (!await tenantContext.IsCkModelExistingAsync(SystemNotificationCkIds.CkModelId))
        {
            // We ensure that at least the system tenant contains a valid ck model.Other tenants
            // need to be enabled manually by an admin.
            OperationResult operationResult = new();
            await tenantContext.ImportCkModelAsync(SystemNotificationCkIds.CkModelId, operationResult);
            if (operationResult.HasErrors || operationResult.HasFatalErrors)
            {
                throw InitializationException.ImportCkModelFailed(tenantContext.TenantId,
                    operationResult.GetMessages());
            }
        }
    }


    public Task EnableAsync(string tenantId)
    {
        return Task.CompletedTask;
    }

    public Task DisableAsync(string tenantId)
    {
        return Task.CompletedTask;
    }

    public Task<bool> IsEnabledAsync(string tenantId)
    {
        return Task.FromResult(true);
    }

    public bool CanBeEnabled()
    {
        return false;
    }


    private async Task RunCkModelMigrationsAsync(
        ITenantContext tenantContext,
        IReadOnlyDictionary<string, string>? previousSchemaVersions = null)
    {
        if (ckModelUpgradeService == null)
        {
            return;
        }

        var ckModelIds = new List<CkModelIdVersionRange>
        {
            // System CK model (base model, updated via EnsureSystemCkModelAsync)
            SystemCkIds.CkModelId.ToVersionRange(),
            // Identity and Notification CK models
            SystemIdentityCkIds.CkModelId.ToVersionRange(),
            SystemNotificationCkIds.CkModelId.ToVersionRange()
        };

        logger.LogInformation(
            "Running CK model data migrations for tenant '{TenantId}' with {ModelCount} models",
            tenantContext.TenantId, ckModelIds.Count);

        var result = await ckModelUpgradeService.UpgradeModelsAsync(
            tenantContext.TenantId,
            ckModelIds,
            new CkMigrationOptions { ContinueOnError = false },
            previousSchemaVersions,
            CancellationToken.None);

        if (!result.Success)
        {
            var errorMessage = $"CK model migration failed for tenant '{tenantContext.TenantId}': {string.Join("; ", result.Errors)}";
            logger.LogError("{ErrorMessage}", errorMessage);
            throw new InvalidOperationException(errorMessage);
        }

        if (result.TotalEntitiesAffected > 0)
        {
            logger.LogInformation(
                "CK model data migrations completed for tenant '{TenantId}': {EntitiesAffected} entities affected",
                tenantContext.TenantId, result.TotalEntitiesAffected);
        }
    }

    /// <summary>
    ///     Inclusive lower bound of the blueprint stable-rtId range
    ///     (<c>System.Identity.Bootstrap-1.0.0</c> seed). First byte 0x66. Mirrors the constant
    ///     in <c>PreBlueprintCleanupMigration</c>; duplicated here so the defensive role-index
    ///     build does not take a dependency on the migration class purely for one comparison.
    /// </summary>
    internal static readonly OctoObjectId BlueprintRangeStart =
        new("660000000000000000000000");

    /// <summary>
    ///     Exclusive upper bound of the blueprint stable-rtId range. ObjectId comparison is
    ///     byte-by-byte.
    /// </summary>
    internal static readonly OctoObjectId BlueprintRangeEndExclusive =
        new("670000000000000000000000");

    internal static bool IsBlueprintRtId(OctoObjectId rtId)
        => rtId.CompareTo(BlueprintRangeStart) >= 0
           && rtId.CompareTo(BlueprintRangeEndExclusive) < 0;

    /// <summary>
    ///     Build a <c>name → rtId</c> dictionary that is tolerant of duplicate Role names.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The unguarded <c>.ToDictionary(r =&gt; r.Name)</c> this replaces would crash with
    ///         <see cref="ArgumentException"/> on any duplicate, taking the entire host down
    ///         (test-2 2026-06-15 — pre-blueprint cleanup left <c>686a…cd</c> and
    ///         <c>660…05</c> both named <c>AdminPanelManagement</c>). Identity refused to start
    ///         and recovery required a backup restore.
    ///     </para>
    ///     <para>
    ///         Defensive build: group by name, prefer the blueprint-range rtId (the only one the
    ///         seed authored), and log a warning carrying every conflicting rtId so the data
    ///         drift stays visible. PR #94 fixes the upstream migration so duplicates don't form
    ///         in the first place; this safety net catches any future variant — operator-created
    ///         duplicates, blueprint-version bumps that collide with operator names, half-applied
    ///         restores.
    ///     </para>
    /// </remarks>
    internal static Dictionary<string, OctoObjectId> BuildRoleNameIndex(
        IEnumerable<RtRole> roles, string tenantId, ILogger logger)
    {
        var grouped = roles
            .Where(r => r.Name is { Length: > 0 })
            .GroupBy(r => r.Name!, StringComparer.Ordinal);

        var index = new Dictionary<string, OctoObjectId>(StringComparer.Ordinal);
        foreach (var group in grouped)
        {
            var entries = group.ToList();
            // Prefer the blueprint-range entry; fall back to the first by rtId for stable
            // selection across restarts when no blueprint entry exists yet.
            var blueprintEntries = entries.Where(r => IsBlueprintRtId(r.RtId)).ToList();
            var winner = blueprintEntries.Count > 0
                ? blueprintEntries.OrderBy(r => r.RtId).First()
                : entries.OrderBy(r => r.RtId).First();

            if (entries.Count > 1)
            {
                logger.LogWarning(
                    "Duplicate Role name '{RoleName}' in tenant '{TenantId}' — {Count} entries " +
                    "(rtIds: {RtIds}). Using rtId '{WinnerRtId}' for post-blueprint role restore; " +
                    "review whether the pre-blueprint cleanup left orphans.",
                    group.Key, tenantId, entries.Count,
                    string.Join(", ", entries.Select(r => r.RtId.ToString())),
                    winner.RtId);
            }

            index[group.Key] = winner.RtId;
        }

        return index;
    }
}