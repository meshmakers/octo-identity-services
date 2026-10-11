using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.FileRoles;

/// <summary>Outcome of one <see cref="PipelineServiceAccountFileRoleGrant.EnsureAsync"/> call.</summary>
internal enum PipelineServiceAccountFileRoleGrantStatus
{
    /// <summary>The check ran; accounts that lacked the role received it (possibly none).</summary>
    Completed,

    /// <summary>The tenant has no System.Files model (or the probe says so); nothing was read or written.</summary>
    SkippedNoFilesModel,

    /// <summary>The FileManagement role does not exist (yet); nothing was written, the next setup retries.</summary>
    RoleMissing
}

internal sealed record PipelineServiceAccountFileRoleGrantResult(
    PipelineServiceAccountFileRoleGrantStatus Status,
    IReadOnlyList<string> GrantedClientRtIds,
    IReadOnlyList<string> AccountsWithoutRole);

/// <summary>
///     AB#6467 / AB#6457 (decision Gerald 2026-10-11): the pipeline service accounts
///     (<c>octo-pipeline-sa-{adapterRtId}</c>, created per adapter by the Communication Controller) hold
///     <c>FileManagement</c>. Their file nodes (<c>CreateFileSystemUpdate</c>, <c>GetFileSystemContent</c>) run in the
///     adapter's own engine, where the System.Files data policies of <c>System.Identity.Bootstrap</c> 1.6.0 apply to
///     the account's roles — without the role a node running as <c>ServiceAccount</c> (or as <c>Caller</c> with no
///     caller: cron and HTTP triggers) is refused, silently from the pipeline author's point of view.
/// </summary>
/// <remarks>
///     <para>
///         Unlike <see cref="FileRoleGrant"/> this is <b>not</b> a run-once step: it runs on every tenant setup
///         (identity start, tenant create, full tenant update, failed-tenant retry) so accounts created later are
///         picked up. Additive and idempotent — it only inserts an <c>AssignedRole</c> edge for accounts that do not
///         hold the role, so a repeated run writes nothing. Consequently an operator cannot remove the role from a
///         pipeline service account for good; revoking file access of pipelines is done per pipeline
///         (<c>Identity: Caller</c>) or by changing the policies.
///     </para>
///     <para>
///         The Communication Controller's identity-data command is covered separately and immediately
///         (<c>CreateIdentityDataCommandRequestConsumer</c> grants the role on every command for such a client and the
///         declarative role sync keeps it), so this pass is the catch-up for accounts that exist already and for the
///         case that the role seed was still pending when the account was created.
///     </para>
/// </remarks>
internal static class PipelineServiceAccountFileRoleGrant
{
    /// <summary>
    ///     Pure rule: the rtIds of the pipeline service accounts (client id with the
    ///     <see cref="IdentityServiceConstants.PipelineServiceAccountClientIdPrefix"/> prefix) that do not hold the
    ///     role. Other clients are never listed.
    /// </summary>
    public static IReadOnlyList<string> Plan(
        IReadOnlyDictionary<string, (string ClientId, IReadOnlySet<string> RoleIds)> clients, string fileManagementRoleId)
    {
        return clients
            .Where(c => c.Value.ClientId.StartsWith(IdentityServiceConstants.PipelineServiceAccountClientIdPrefix,
                StringComparison.Ordinal))
            .Where(c => !c.Value.RoleIds.Any(r => string.Equals(r, fileManagementRoleId, StringComparison.OrdinalIgnoreCase)))
            .Select(c => c.Key)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();
    }

    public static async Task<PipelineServiceAccountFileRoleGrantResult> EnsureAsync(ITenantContext tenantContext,
        Func<bool> tenantHasFilesModel, ILogger logger)
    {
        if (!tenantHasFilesModel())
        {
            logger.LogDebug(
                "Tenant '{TenantId}' has no System.Files model; the pipeline service accounts are not granted {Role}",
                tenantContext.TenantId, IdentityServiceConstants.FileManagementRole);
            return new(PipelineServiceAccountFileRoleGrantStatus.SkippedNoFilesModel, [], []);
        }

        using var _ = await PipelineServiceAccountFileRoleLock.AcquireAsync(tenantContext.TenantId);
        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        using var session = await tenantRepository.GetSessionAsync();

        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(roles.Items, tenantContext.TenantId, logger);
        if (!roleIndex.TryGetValue(IdentityServiceConstants.FileManagementRole, out var fileManagementRoleId))
        {
            logger.LogWarning(
                "Role {Role} not found in tenant '{TenantId}'; the pipeline service accounts are granted it on the next setup",
                IdentityServiceConstants.FileManagementRole, tenantContext.TenantId);
            return new(PipelineServiceAccountFileRoleGrantStatus.RoleMissing, [], []);
        }

        // TODO(AB#6457): one association query per pipeline account at every tenant setup (N+1). Fine for the
        // handful of accounts per tenant (one per adapter); batch it (GetRtAssociationsAsync takes many origins) if a
        // tenant ever has hundreds.
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
        var clients = new Dictionary<string, (string ClientId, IReadOnlySet<string> RoleIds)>(StringComparer.Ordinal);
        var allClients = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create());
        foreach (var client in allClients.Items.Where(c => c.ClientId != null &&
                     c.ClientId.StartsWith(IdentityServiceConstants.PipelineServiceAccountClientIdPrefix,
                         StringComparison.Ordinal)))
        {
            var edges = await tenantRepository.GetRtAssociationsAsync(session, client.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                    roleId: IdentityAssociationConstants.AssignedRoleId));
            clients[client.RtId.ToString()] = (client.ClientId!, edges.Items
                .Where(e => e.TargetCkTypeId == roleCkTypeId)
                .Select(e => e.TargetRtId.ToString())
                .ToHashSet(StringComparer.Ordinal));
        }

        var missing = Plan(clients, fileManagementRoleId.ToString());
        if (missing.Count == 0)
        {
            return new(PipelineServiceAccountFileRoleGrantStatus.Completed, [], []);
        }

        using var writeSession = await tenantRepository.GetSessionAsync();
        writeSession.StartTransaction();
        var updates = missing.Select(id => AssociationUpdateInfo.CreateInsert(
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), new OctoObjectId(id)),
                new RtEntityId(roleCkTypeId, fileManagementRoleId),
                IdentityAssociationConstants.AssignedRoleId))
            .ToList();
        var operationResult = new OperationResult();
        await tenantRepository.ApplyChangesAsync(writeSession, updates, operationResult);
        if (operationResult.HasErrors || operationResult.HasFatalErrors)
        {
            throw new InvalidOperationException(
                $"Failed to grant {IdentityServiceConstants.FileManagementRole} to the pipeline service accounts of tenant " +
                $"'{tenantContext.TenantId}': {string.Join("; ", operationResult.GetMessages())}");
        }

        await writeSession.CommitTransactionAsync();

        logger.LogInformation(
            "Granted {Role} to {Count} pipeline service account(s) of tenant '{TenantId}': {Accounts}",
            IdentityServiceConstants.FileManagementRole, missing.Count, tenantContext.TenantId,
            string.Join(", ", missing.Select(id => clients[id].ClientId)));
        return new(PipelineServiceAccountFileRoleGrantStatus.Completed, missing, []);
    }

    /// <summary>
    ///     Read-only detection: the client ids of the pipeline service accounts that do not hold the role. Empty when
    ///     the tenant is fine, has no System.Files or the role does not exist. For a health check or a log line.
    /// </summary>
    public static async Task<IReadOnlyList<string>> FindAccountsWithoutRoleAsync(ITenantContext tenantContext,
        Func<bool> tenantHasFilesModel)
    {
        if (!tenantHasFilesModel())
        {
            return [];
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        using var session = await tenantRepository.GetSessionAsync();
        var roleQuery = RtEntityQueryOptions.Create().FieldFilter(nameof(RtRole.NormalizedName),
            FieldFilterOperator.Equals, IdentityServiceConstants.FileManagementRole.ToUpperInvariant());
        var role = (await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, roleQuery, take: 1)).Items
            .FirstOrDefault();
        if (role == null)
        {
            return [];
        }

        var result = new List<string>();
        var allClients = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create());
        foreach (var client in allClients.Items.Where(c => c.ClientId != null &&
                     c.ClientId.StartsWith(IdentityServiceConstants.PipelineServiceAccountClientIdPrefix,
                         StringComparison.Ordinal)))
        {
            var edges = await tenantRepository.GetRtAssociationsAsync(session, client.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                    roleId: IdentityAssociationConstants.AssignedRoleId));
            if (!edges.Items.Any(e => e.TargetRtId == role.RtId))
            {
                result.Add(client.ClientId!);
            }
        }

        return result;
    }
}
