using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.PipelineServiceAccounts;

/// <summary>A missing <c>AssignedRole</c> edge from a pipeline service account to a baseline role.</summary>
internal sealed record PipelineServiceAccountRoleGrantEdge(string ClientRtId, string RoleId);

/// <summary>A pipeline service account that lacks a baseline role, by client id and role name.</summary>
internal sealed record PipelineServiceAccountMissingRole(string ClientId, string RoleName);

/// <summary>Outcome of one <see cref="PipelineServiceAccountRoleGrant.EnsureAsync"/> call.</summary>
/// <param name="Granted">The edges written (empty when every account was covered).</param>
/// <param name="NotApplicableRoles">Baseline roles not granted in this tenant (FileManagement without System.Files).</param>
/// <param name="MissingRoles">Baseline roles that are not seeded (yet); the next setup retries.</param>
internal sealed record PipelineServiceAccountRoleGrantResult(
    IReadOnlyList<PipelineServiceAccountMissingRole> Granted,
    IReadOnlyList<string> NotApplicableRoles,
    IReadOnlyList<string> MissingRoles);

/// <summary>
///     Tenant-setup pass that gives every pipeline service account (<c>octo-pipeline-sa-{adapterRtId}</c>, created per
///     adapter by the Communication Controller) the baseline roles of <see cref="PipelineServiceAccountBaselineRoles"/>:
///     <c>FileManagement</c> (AB#6467 / AB#6457, only in tenants with System.Files) and <c>StreamDataReader</c>
///     (AB#8581).
/// </summary>
/// <remarks>
///     <para>
///         Not a run-once step: it runs on every tenant setup (identity start, tenant create, full tenant update,
///         failed-tenant retry) so accounts created later are picked up. Additive and idempotent — it only inserts an
///         <c>AssignedRole</c> edge for accounts that do not hold the role, never removes one, so a legacy account
///         (no <c>AssignedRoleNames</c>) keeps every role it had and a repeated run writes nothing. Consequently an
///         operator cannot remove a baseline role from a pipeline service account for good.
///     </para>
///     <para>
///         The identity-data command is covered separately and immediately (<c>CreateIdentityDataCommandRequestConsumer</c>
///         grants the roles on every command for such a client and the declarative role sync keeps them), so this pass is
///         the catch-up for accounts that exist already and for the case that a role seed was still pending.
///     </para>
///     <para>
///         System grant, not a role change by a caller: it does not run through the role change guard. Two limits keep
///         it narrow — only clients under the exact, case-sensitive prefix, and only roles that are seeded in the
///         tenant (nothing is created).
///     </para>
/// </remarks>
internal static class PipelineServiceAccountRoleGrant
{
    /// <summary>
    ///     Pure rule: the missing edges from the pipeline service accounts (client id with the
    ///     <see cref="IdentityServiceConstants.PipelineServiceAccountClientIdPrefix"/> prefix) to the given roles. Other
    ///     clients are never listed. Ordered by client rtId, then role id.
    /// </summary>
    /// <param name="clients">Client rtId → (client id, rtIds of the roles it holds).</param>
    /// <param name="roleIds">The rtIds of the baseline roles to ensure.</param>
    public static IReadOnlyList<PipelineServiceAccountRoleGrantEdge> Plan(
        IReadOnlyDictionary<string, (string ClientId, IReadOnlySet<string> RoleIds)> clients,
        IReadOnlyCollection<string> roleIds)
    {
        return clients
            .Where(c => PipelineServiceAccountBaselineRoles.IsPipelineServiceAccount(c.Value.ClientId))
            .OrderBy(c => c.Key, StringComparer.Ordinal)
            .SelectMany(c => roleIds
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(roleId => !c.Value.RoleIds.Any(r => string.Equals(r, roleId, StringComparison.OrdinalIgnoreCase)))
                .Order(StringComparer.Ordinal)
                .Select(roleId => new PipelineServiceAccountRoleGrantEdge(c.Key, roleId)))
            .ToList();
    }

    public static async Task<PipelineServiceAccountRoleGrantResult> EnsureAsync(ITenantContext tenantContext,
        Func<bool> tenantHasFilesModel, ILogger logger)
    {
        var hasFilesModel = tenantHasFilesModel();
        var roleNames = PipelineServiceAccountBaselineRoles.ForTenantSetup(hasFilesModel);
        var notApplicable = PipelineServiceAccountBaselineRoles.All.Select(r => r.RoleName).Except(roleNames).ToList();
        if (notApplicable.Count > 0)
        {
            logger.LogDebug(
                "Tenant '{TenantId}' has no System.Files model; the pipeline service accounts are not granted {Roles}",
                tenantContext.TenantId, string.Join(", ", notApplicable));
        }

        // The identity-data consumer writes the same edges: serialise (a second identical edge is not rejected).
        using var _ = await PipelineServiceAccountRoleLock.AcquireAsync(tenantContext.TenantId);
        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        var snapshot = await ReadAsync(tenantRepository, tenantContext.TenantId, roleNames, logger);
        if (snapshot.MissingRoles.Count > 0)
        {
            logger.LogWarning(
                "Role(s) {Roles} not found in tenant '{TenantId}'; the pipeline service accounts are granted them on the next setup",
                string.Join(", ", snapshot.MissingRoles), tenantContext.TenantId);
        }

        var missing = Plan(snapshot.Clients, snapshot.RoleIdsByName.Values.ToList());
        if (missing.Count == 0)
        {
            return new([], notApplicable, snapshot.MissingRoles);
        }

        using var writeSession = await tenantRepository.GetSessionAsync();
        writeSession.StartTransaction();
        var clientCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtClient>();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
        var updates = missing.Select(e => AssociationUpdateInfo.CreateInsert(
                new RtEntityId(clientCkTypeId, new OctoObjectId(e.ClientRtId)),
                new RtEntityId(roleCkTypeId, new OctoObjectId(e.RoleId)),
                IdentityAssociationConstants.AssignedRoleId))
            .ToList();
        var operationResult = new OperationResult();
        await tenantRepository.ApplyChangesAsync(writeSession, updates, operationResult);
        if (operationResult.HasErrors || operationResult.HasFatalErrors)
        {
            throw new InvalidOperationException(
                $"Failed to grant the baseline roles to the pipeline service accounts of tenant " +
                $"'{tenantContext.TenantId}': {string.Join("; ", operationResult.GetMessages())}");
        }

        await writeSession.CommitTransactionAsync();

        var granted = snapshot.Describe(missing);
        logger.LogInformation(
            "Granted {Count} baseline role(s) to the pipeline service accounts of tenant '{TenantId}': {Grants}",
            granted.Count, tenantContext.TenantId,
            string.Join(", ", granted.Select(g => $"{g.ClientId} → {g.RoleName}")));
        return new(granted, notApplicable, snapshot.MissingRoles);
    }

    /// <summary>
    ///     Read-only detection: the pipeline service accounts that lack a baseline role this tenant's setup would grant.
    ///     Roles that are not seeded are not reported. For a health check or a log line.
    /// </summary>
    public static async Task<IReadOnlyList<PipelineServiceAccountMissingRole>> FindMissingRolesAsync(
        ITenantContext tenantContext, Func<bool> tenantHasFilesModel, ILogger logger)
    {
        var roleNames = PipelineServiceAccountBaselineRoles.ForTenantSetup(tenantHasFilesModel());
        var snapshot = await ReadAsync(tenantContext.GetTenantRepositoryAsAdmin(), tenantContext.TenantId, roleNames,
            logger);
        return snapshot.Describe(Plan(snapshot.Clients, snapshot.RoleIdsByName.Values.ToList()));
    }

    private static async Task<Snapshot> ReadAsync(ITenantRepository tenantRepository, string tenantId,
        IReadOnlyList<string> roleNames, ILogger logger)
    {
        using var session = await tenantRepository.GetSessionAsync();

        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(roles.Items, tenantId, logger);
        var roleIdsByName = new Dictionary<string, string>(StringComparer.Ordinal);
        var missingRoles = new List<string>();
        foreach (var roleName in roleNames)
        {
            if (roleIndex.TryGetValue(roleName, out var roleId))
            {
                roleIdsByName[roleName] = roleId.ToString();
            }
            else
            {
                missingRoles.Add(roleName);
            }
        }

        var clients = new Dictionary<string, (string ClientId, IReadOnlySet<string> RoleIds)>(StringComparer.Ordinal);
        if (roleIdsByName.Count == 0)
        {
            return new Snapshot(clients, roleIdsByName, missingRoles);
        }

        // TODO(AB#6457): one association query per pipeline account at every tenant setup (N+1). Fine for the
        // handful of accounts per tenant (one per adapter); batch it (GetRtAssociationsAsync takes many origins) if a
        // tenant ever has hundreds.
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
        var allClients = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create());
        foreach (var client in allClients.Items.Where(c =>
                     PipelineServiceAccountBaselineRoles.IsPipelineServiceAccount(c.ClientId)))
        {
            var edges = await tenantRepository.GetRtAssociationsAsync(session, client.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                    roleId: IdentityAssociationConstants.AssignedRoleId));
            clients[client.RtId.ToString()] = (client.ClientId!, edges.Items
                .Where(e => e.TargetCkTypeId == roleCkTypeId)
                .Select(e => e.TargetRtId.ToString())
                .ToHashSet(StringComparer.Ordinal));
        }

        return new Snapshot(clients, roleIdsByName, missingRoles);
    }

    private sealed record Snapshot(
        IReadOnlyDictionary<string, (string ClientId, IReadOnlySet<string> RoleIds)> Clients,
        IReadOnlyDictionary<string, string> RoleIdsByName,
        IReadOnlyList<string> MissingRoles)
    {
        public IReadOnlyList<PipelineServiceAccountMissingRole> Describe(
            IEnumerable<PipelineServiceAccountRoleGrantEdge> edges)
        {
            var namesById = RoleIdsByName.ToDictionary(kv => kv.Value, kv => kv.Key, StringComparer.OrdinalIgnoreCase);
            return edges.Select(e => new PipelineServiceAccountMissingRole(Clients[e.ClientRtId].ClientId,
                namesById[e.RoleId])).ToList();
        }
    }
}
