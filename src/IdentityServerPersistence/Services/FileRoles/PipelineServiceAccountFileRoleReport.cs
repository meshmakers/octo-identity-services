using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.FileRoles;

/// <summary>Overall verdict of <see cref="PipelineServiceAccountFileRoleReport"/> for one tenant.</summary>
public enum PipelineServiceAccountFileRoleReportStatus
{
    /// <summary>At least one pipeline service account exists and all of them hold FileManagement.</summary>
    AllCovered,

    /// <summary>At least one pipeline service account does not hold FileManagement.</summary>
    MissingGrants,

    /// <summary>The tenant has no pipeline service account (<c>octo-pipeline-sa-*</c>); nothing to grant.</summary>
    NoAccounts,

    /// <summary>The tenant has no System.Files model; file nodes cannot run, so the check does not apply.</summary>
    NotApplicable,

    /// <summary>The FileManagement role does not exist in the tenant (yet); the next tenant setup retries the grant.</summary>
    RoleMissing
}

/// <summary>One pipeline service account of the report (no secrets).</summary>
/// <param name="ClientId">The client id, <c>octo-pipeline-sa-{adapterRtId}</c>.</param>
/// <param name="RtId">The runtime id of the client entity.</param>
/// <param name="HasFileManagement">True when the account holds FileManagement through an AssignedRole edge.</param>
public sealed record PipelineServiceAccountFileRoleEntry(string ClientId, string RtId, bool HasFileManagement);

/// <summary>Read-only report which pipeline service accounts of a tenant hold FileManagement (AB#6542).</summary>
/// <param name="TenantId">The tenant the report was built for.</param>
/// <param name="Status">The overall verdict; <c>MissingGrants</c> is the only value an operator has to act on.</param>
/// <param name="MissingCount">Number of accounts without FileManagement.</param>
/// <param name="Accounts">All pipeline service accounts of the tenant, ordered by client id.</param>
public sealed record PipelineServiceAccountFileRoleReportResult(
    string TenantId,
    PipelineServiceAccountFileRoleReportStatus Status,
    int MissingCount,
    IReadOnlyList<PipelineServiceAccountFileRoleEntry> Accounts);

/// <summary>
///     AB#6542: proof report for <see cref="PipelineServiceAccountFileRoleGrant"/>. Lists the pipeline service
///     accounts of a tenant and whether each holds FileManagement. Strictly read-only; "holds the role" is decided by
///     the grant's own pure rule (<see cref="PipelineServiceAccountFileRoleGrant.Plan"/>), not redefined here.
/// </summary>
public static class PipelineServiceAccountFileRoleReport
{
    /// <summary>Pure assembly of the report from already read data.</summary>
    /// <param name="tenantId">The tenant id.</param>
    /// <param name="hasFilesModel">Whether the tenant has the System.Files model.</param>
    /// <param name="fileManagementRoleId">The rtId of the FileManagement role, or null when it does not exist.</param>
    /// <param name="clients">Pipeline-account candidates: client rtId → (client id, rtIds of held roles).</param>
    public static PipelineServiceAccountFileRoleReportResult Build(string tenantId, bool hasFilesModel,
        string? fileManagementRoleId,
        IReadOnlyDictionary<string, (string ClientId, IReadOnlySet<string> RoleIds)> clients)
    {
        if (!hasFilesModel)
        {
            return new(tenantId, PipelineServiceAccountFileRoleReportStatus.NotApplicable, 0, []);
        }

        var accounts = clients
            .Where(c => c.Value.ClientId.StartsWith(IdentityServiceConstants.PipelineServiceAccountClientIdPrefix,
                StringComparison.Ordinal))
            .ToList();
        if (fileManagementRoleId == null)
        {
            return new(tenantId, PipelineServiceAccountFileRoleReportStatus.RoleMissing, 0, []);
        }

        var missing = PipelineServiceAccountFileRoleGrant.Plan(clients, fileManagementRoleId).ToHashSet(StringComparer.Ordinal);
        var entries = accounts
            .Select(c => new PipelineServiceAccountFileRoleEntry(c.Value.ClientId, c.Key, !missing.Contains(c.Key)))
            .OrderBy(e => e.ClientId, StringComparer.Ordinal)
            .ToList();
        var status = entries.Count == 0 ? PipelineServiceAccountFileRoleReportStatus.NoAccounts
            : missing.Count > 0 ? PipelineServiceAccountFileRoleReportStatus.MissingGrants
            : PipelineServiceAccountFileRoleReportStatus.AllCovered;
        return new(tenantId, status, missing.Count, entries);
    }

    /// <summary>Reads the tenant and builds the report. Nothing is written.</summary>
    public static async Task<PipelineServiceAccountFileRoleReportResult> ReadAsync(
        ITenantRepository tenantRepository, string tenantId, ICkCacheService ckCacheService)
    {
        var hasFilesModel = new CkCacheFilesModelProbe(ckCacheService).HasFilesModel(tenantId);
        if (!hasFilesModel)
        {
            return Build(tenantId, false, null, new Dictionary<string, (string, IReadOnlySet<string>)>());
        }

        using var session = await tenantRepository.GetSessionAsync();
        var roleQuery = RtEntityQueryOptions.Create().FieldFilter(nameof(RtRole.NormalizedName),
            FieldFilterOperator.Equals, IdentityServiceConstants.FileManagementRole.ToUpperInvariant());
        var role = (await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, roleQuery, take: 1)).Items
            .FirstOrDefault();

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

        return Build(tenantId, true, role?.RtId.ToString(), clients);
    }
}
