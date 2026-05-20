using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <inheritdoc cref="IClientMirrorProvisioningService"/>
public class ClientMirrorProvisioningService(
    ILogger<ClientMirrorProvisioningService> logger,
    ISystemContext systemContext)
    : IClientMirrorProvisioningService
{
    public async Task<ClientMirrorProvisioningResult> ProvisionForChildTenantAsync(
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
        var childTenants = await parentContext.GetChildTenantsAsync(adminSession);

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
                var perChildResult = await ProvisionForChildTenantAsync(parentTenantId, child.TenantId);
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

        logger.LogInformation(
            "Removed client mirror manually: clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}'",
            parentClientId, parentTenantId, childTenantId);
        return true;
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
    private static RtClient CreateMirrorClient(string parentTenantId, RtClient parentClient)
    {
        return new RtClient
        {
            RtId = OctoObjectId.GenerateNewId(),
            Enabled = parentClient.Enabled,
            ClientId = parentClient.ClientId,
            ProtocolType = parentClient.ProtocolType,
            ClientSecrets = parentClient.ClientSecrets,
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

    private static async Task UpsertClientInChildAsync(
        ITenantRepository childRepo, IOctoSession childSession, RtClient mirror)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, mirror.ClientId);
        var existing = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(childSession, queryOptions);
        if (existing.Items.Any())
        {
            // Reuse the existing RtId on the child side; secret/scope changes still propagate.
            mirror.RtId = existing.Items.First().RtId;
            await childRepo.ReplaceOneRtEntityByIdAsync(childSession, mirror.RtId, mirror);
        }
        else
        {
            await childRepo.InsertOneRtEntityAsync(childSession, mirror);
        }
    }
}
