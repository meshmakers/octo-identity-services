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
    ///     Phase 3 PR #3: declares the namespace prefix the Base class uses to recognise
    ///     embedded blueprints this service owns. Today the only such blueprint is
    ///     <c>System.Identity.Bootstrap-1.0.0</c> (shipped by PR #2). PR #4 cuts
    ///     <see cref="SetupTenantAsync"/> over to apply the blueprint unconditionally; the
    ///     <see cref="RefreshTenantStateAsync"/> path is still flag-gated until PR #5 ships
    ///     and removes the flag.
    /// </summary>
    protected override string? ServiceManagedBlueprintPrefix => "System.Identity.";

    /// <summary>
    ///     Phase 3 PR #3: feature-flagged blueprint apply on the lifecycle path
    ///     (Enable / Restore / DeferTenantStart=false). The imperative seed in
    ///     <see cref="SetupTenantAsync"/> still runs unchanged — when the flag is on, the
    ///     blueprint apply runs <strong>alongside</strong> it so we can observe
    ///     <c>BlueprintInstallation</c> rows appear without disturbing the existing seed.
    ///     PR #4 cuts <c>SetupTenantAsync</c> over to the blueprint and this hook becomes
    ///     unconditional; PR #5 removes the feature flag.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <c>throwOnFailure: false</c> so a transient blueprint failure (e.g. catalog
    ///         lookup hiccup) does not knock a tenant offline during the burn-in phase.
    ///         Failures are logged + surfaced via
    ///         <see cref="DefaultConfigurationCreatorServiceBase.OnServiceManagedBlueprintApplyFailedAsync"/>.
    ///     </para>
    ///     <para>
    ///         When <see cref="OctoIdentityServicesOptions.UseBlueprintBootstrap"/> is false
    ///         (the default), this override is a no-op — the base's empty implementation is
    ///         effectively still in play and the imperative seed remains the sole source of
    ///         truth for the tenant's identity entities.
    ///     </para>
    /// </remarks>
    protected override async Task RefreshTenantStateAsync(string tenantId)
    {
        if (!octoIdentityOptions.Value.UseBlueprintBootstrap)
        {
            return;
        }

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
        await ApplyServiceManagedBlueprintsAsync(tenantId, throwOnFailure: true);

        // Phase 3 PR #4 post-blueprint restore: PreBlueprintCleanupMigration captures every
        // User → Role and ExternalTenantUserMapping → Role assignment by role NAME into
        // SystemConfiguration[PendingPostBlueprintRoleAssignmentsKey] before deleting the OLD
        // entities. Now that the blueprint has installed the NEW roles with stable rtIds
        // (660…01..0E), look the names up and re-attach the assignments via fresh AssignedRole
        // edges. The pending row is deleted on success — if Identity crashes mid-restore the
        // next startup retries with the same data.
        await RestorePendingRoleAssignmentsAsync(tenantContext);

        // Mail templates + RtMailNotificationConfiguration stay in code. They belong to the
        // System.Notification CK model, not System.Identity, and are a candidate for a separate
        // System.Notification.Bootstrap blueprint in a follow-up (concept doc §6).
        var configRepo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : tenantContext.GetTenantRepositoryAsAdmin();
        using (var configSession = await tenantContext.GetAdminSessionAsync())
        {
            configSession.StartTransaction();
            await CreateTenantConfiguration(configSession, configRepo);
            await configSession.CommitTransactionAsync();
        }

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

        // Build a name → new-Role-rtId index once from the blueprint-seeded entities.
        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(
            writeSession, RtEntityQueryOptions.Create());
        var rolesByName = roles.Items
            .Where(r => r.Name is { Length: > 0 })
            .ToDictionary(r => r.Name!, r => r.RtId, StringComparer.Ordinal);

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


    private async Task CreateTenantConfiguration(IOctoSession session, ITenantRepository tenantRepository)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.MailNotificationConfigurationName);
        var r = await tenantRepository.GetRtEntitiesByTypeAsync<RtMailNotificationConfiguration>(session,
            queryOptions);
        if (r.TotalCount == 0)
        {
            var rtMailNotificationConfiguration = new RtMailNotificationConfiguration
            {
                RtWellKnownName = IdentityServiceConstants.MailNotificationConfigurationName,
                EnableEmailNotifications = false
            };
            await tenantRepository.InsertOneRtEntityAsync(session, rtMailNotificationConfiguration);
        }

        queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.WelcomeEmailTemplateName);
        var mailTemplateResultSet = await tenantRepository.GetRtEntitiesByTypeAsync<RtNotificationTemplate>(session,
            queryOptions);
        if (mailTemplateResultSet.TotalCount == 0)
        {
            var welcomeMailTemplate = new RtNotificationTemplate
            {
                RtWellKnownName = IdentityServiceConstants.WelcomeEmailTemplateName,
                Type = RtNotificationTypesEnum.EMail,
                RenderingType = RtRenderingTypesEnum.Plain,
                SubjectTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailSubject,
                BodyTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailBody
            };
            await tenantRepository.InsertOneRtEntityAsync(session, welcomeMailTemplate);
        }

        queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.WelcomeEmailWithNoPasswordTemplateName);
        mailTemplateResultSet = await tenantRepository.GetRtEntitiesByTypeAsync<RtNotificationTemplate>(session,
            queryOptions);
        if (mailTemplateResultSet.TotalCount == 0)
        {
            var welcomeMailWithNoPasswordTemplate = new RtNotificationTemplate
            {
                RtWellKnownName = IdentityServiceConstants.WelcomeEmailWithNoPasswordTemplateName,
                Type = RtNotificationTypesEnum.EMail,
                RenderingType = RtRenderingTypesEnum.Plain,
                SubjectTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailWithNoPasswordSubject,
                BodyTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailWithNoPasswordBody
            };
            await tenantRepository.InsertOneRtEntityAsync(session, welcomeMailWithNoPasswordTemplate);
        }

        queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.ResetPasswordEmailTemplateName);
        mailTemplateResultSet = await tenantRepository.GetRtEntitiesByTypeAsync<RtNotificationTemplate>(session,
            queryOptions);
        if (mailTemplateResultSet.TotalCount == 0)
        {
            var resetPasswordMailTemplate = new RtNotificationTemplate
            {
                RtWellKnownName = IdentityServiceConstants.ResetPasswordEmailTemplateName,
                Type = RtNotificationTypesEnum.EMail,
                RenderingType = RtRenderingTypesEnum.Plain,
                SubjectTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_ResetPasswordMailSubject,
                BodyTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_ResetPasswordMailBody
            };
            await tenantRepository.InsertOneRtEntityAsync(session, resetPasswordMailTemplate);
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
}