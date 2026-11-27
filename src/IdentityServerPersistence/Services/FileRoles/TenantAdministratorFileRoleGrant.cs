using System.Collections.Concurrent;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.FileRoles;

/// <summary>
///     Marker persisted in the tenant configuration once <see cref="TenantAdministratorFileRoleGrant"/> has run for
///     a tenant. Its presence is the run-once gate: an operator who later removes the role from an administrator
///     must not see it come back on the next restart.
/// </summary>
public sealed class TenantAdministratorFileRoleGrantMarker
{
    /// <summary>Version of the grant rule that produced this marker (see <see cref="TenantAdministratorFileRoleGrant.Version"/>).</summary>
    public int Version { get; set; }

    public DateTime CompletedAtUtc { get; set; }

    public List<string> GrantedUserIds { get; set; } = [];
}

/// <summary>Outcome of one <see cref="TenantAdministratorFileRoleGrant.EnsureAsync"/> call.</summary>
internal enum TenantAdministratorFileRoleGrantStatus
{
    /// <summary>The grants were written (possibly none) and the marker recorded.</summary>
    Completed,

    /// <summary>The marker already existed; nothing was read or written.</summary>
    AlreadyDone,

    /// <summary>FileManagement does not exist (yet); nothing written, no marker — retried next setup.</summary>
    RoleMissing
}

internal sealed record TenantAdministratorFileRoleGrantResult(
    TenantAdministratorFileRoleGrantStatus Status,
    IReadOnlyList<string> GrantedUserIds);

/// <summary>
///     AB#6578: one-time, additive grant of <c>FileManagement</c> to the HUMAN administrators of a tenant — every
///     local user that holds both <c>AdminPanelManagement</c> and <c>TenantManagement</c>. No group, client,
///     cross-tenant shadow user or external mapping receives it. See <see cref="TenantAdministratorRoleGrantPlanner"/>.
/// </summary>
/// <remarks>
///     <para>
///         Complements <see cref="FileRoleGrant"/> (Reporting role holders, kept untouched) and
///         <see cref="PipelineServiceAccountFileRoleGrant"/>. It has its OWN marker
///         (<see cref="IdentityServiceConstants.TenantAdministratorFileRoleGrantKey"/>), so tenants that already
///         carry the <see cref="IdentityServiceConstants.FileRoleGrantKey"/> marker from the Reporting-based grant
///         — the tenants this fix is for — still receive the administrator grant on the next identity start.
///         <see cref="Version"/> is part of the key name semantics: a future change of the rule bumps it and the key.
///     </para>
///     <para>
///         Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> right AFTER the
///         <c>System.Identity.Bootstrap</c> blueprint apply (the role has to exist). Only <c>AssignedRole</c> insert
///         edges are written, only for users that do not hold the role yet; the marker is written after the edges are
///         committed, so a crash in between re-runs the step, which then finds the edges and writes nothing new.
///     </para>
/// </remarks>
internal static class TenantAdministratorFileRoleGrant
{
    /// <summary>Rule version; v1 was the Reporting-based <see cref="FileRoleGrant"/>, v2 adds the administrators.</summary>
    public const int Version = 2;

    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    public static async Task<TenantAdministratorFileRoleGrantResult> EnsureAsync(
        ITenantContext tenantContext, ILogger logger)
    {
        // Serialises the runs inside this process. Several replicas starting at once can still race: every write
        // re-reads the user's edges first, and a duplicate that slips through is harmless (role reads treat the
        // edges as a set).
        var gate = Locks.GetOrAdd(tenantContext.TenantId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await EnsureCoreAsync(tenantContext, logger).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<TenantAdministratorFileRoleGrantResult> EnsureCoreAsync(
        ITenantContext tenantContext, ILogger logger)
    {
        using (var readSession = await tenantContext.GetAdminSessionAsync())
        {
            var marker = await tenantContext.GetConfigurationAsync<TenantAdministratorFileRoleGrantMarker>(
                readSession, IdentityServiceConstants.TenantAdministratorFileRoleGrantKey, defaultValue: null);
            if (marker != null)
            {
                return new TenantAdministratorFileRoleGrantResult(TenantAdministratorFileRoleGrantStatus.AlreadyDone, []);
            }
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        TenantAdministratorRoleGrantPlan plan;
        using (var session = await tenantRepository.GetSessionAsync())
        {
            var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
            var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(
                roles.Items, tenantContext.TenantId, logger);

            if (!roleIndex.TryGetValue(IdentityServiceConstants.FileManagementRole, out var fileManagementRoleId))
            {
                logger.LogWarning(
                    "{Role} role not found in tenant '{TenantId}'; the one-time administrator grant is retried on " +
                    "the next tenant setup",
                    IdentityServiceConstants.FileManagementRole, tenantContext.TenantId);
                return new TenantAdministratorFileRoleGrantResult(TenantAdministratorFileRoleGrantStatus.RoleMissing, []);
            }

            // A tenant without one of the admin roles can still have TenantOwners; an unknown role id simply never
            // matches.
            var adminPanelRoleId = roleIndex.TryGetValue(CommonConstants.AdminPanelManagementRole, out var apm)
                ? apm.ToString()
                : "-";
            var tenantManagementRoleId = roleIndex.TryGetValue(CommonConstants.TenantManagementRole, out var tm)
                ? tm.ToString()
                : "-";

            // The read is not wrapped in a transaction (one association query per subject can outlast MongoDB's
            // transaction lifetime on large tenants); the planner skips users that already hold the role.
            var input = await TenantAdministratorRoleGraphReader.ReadAsync(tenantRepository, session);
            plan = TenantAdministratorRoleGrantPlanner.Plan(
                input, adminPanelRoleId, tenantManagementRoleId, fileManagementRoleId.ToString());

            using var writeSession = await tenantRepository.GetSessionAsync();
            writeSession.StartTransaction();
            var roleEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), fileManagementRoleId);
            var updates = new List<AssociationUpdateInfo>();
            foreach (var userId in plan.UserIds)
            {
                var userEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtUser>(), new OctoObjectId(userId));
                // Re-read right before the insert: another replica may have written the edge since the plan.
                var existing = await tenantRepository.GetRtAssociationsAsync(writeSession, userEntityId,
                    RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                        roleId: IdentityAssociationConstants.AssignedRoleId));
                if (existing.Items.Any(e => e.TargetRtId == fileManagementRoleId))
                {
                    continue;
                }

                updates.Add(AssociationUpdateInfo.CreateInsert(
                    userEntityId, roleEntityId, IdentityAssociationConstants.AssignedRoleId));
            }

            if (updates.Count > 0)
            {
                var opResult = new OperationResult();
                await tenantRepository.ApplyChangesAsync(writeSession, updates, opResult);
                if (opResult.HasErrors || opResult.HasFatalErrors)
                {
                    // Throw before the commit and before the marker: the caller logs it and the next tenant setup
                    // retries (the marker would otherwise claim a grant that failed).
                    throw new InvalidOperationException(
                        $"Failed to grant {IdentityServiceConstants.FileManagementRole} to the administrators of " +
                        $"tenant '{tenantContext.TenantId}': {string.Join("; ", opResult.GetMessages())}");
                }
            }

            await writeSession.CommitTransactionAsync();
        }

        using (var markerSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                markerSession,
                IdentityServiceConstants.TenantAdministratorFileRoleGrantKey,
                new TenantAdministratorFileRoleGrantMarker
                {
                    Version = Version,
                    CompletedAtUtc = DateTime.UtcNow,
                    GrantedUserIds = plan.UserIds.ToList()
                });
        }

        logger.LogInformation(
            "{Role} granted to the human administrators of tenant '{TenantId}': {UserCount} users ({UserIds}); " +
            "recorded as done (rule v{Version})",
            IdentityServiceConstants.FileManagementRole, tenantContext.TenantId, plan.UserIds.Count,
            string.Join(", ", plan.UserIds), Version);

        return new TenantAdministratorFileRoleGrantResult(
            TenantAdministratorFileRoleGrantStatus.Completed, plan.UserIds);
    }
}
