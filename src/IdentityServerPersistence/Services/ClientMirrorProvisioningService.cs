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
            var mirror = CreateMirrorClient(parentClient);
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

    /// <summary>
    /// Returns a copy of the parent client suitable for insertion into the child tenant's DB:
    /// fresh <c>RtId</c>, identical <c>ClientId</c> + secrets + scopes + everything else.
    /// <c>AutoProvisionInChildTenants</c> is intentionally NOT propagated — only the parent
    /// owns the flag; a mirror is never itself a source of further mirroring.
    /// </summary>
    private static RtClient CreateMirrorClient(RtClient parentClient)
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
            AutoProvisionInChildTenants = false
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
