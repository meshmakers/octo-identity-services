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
///     Marker persisted in the tenant configuration once <see cref="FileRoleGrant"/> has run for a tenant. Its
///     presence is the run-once gate: an operator who later removes a File role from somebody must not see it
///     come back on the next restart.
/// </summary>
public sealed class FileRoleGrantMarker
{
    public DateTime CompletedAtUtc { get; set; }

    /// <summary>Granted edges as <c>"{kind}:{subjectRtId}:{roleName}"</c>.</summary>
    public List<string> GrantedAssignments { get; set; } = [];

    /// <summary>Extended mappings as <c>"{mappingRtId}:{roleName}"</c>.</summary>
    public List<string> GrantedMappingRoles { get; set; } = [];
}

/// <summary>Outcome of one <see cref="FileRoleGrant.EnsureAsync"/> call.</summary>
internal enum FileRoleGrantStatus
{
    /// <summary>The grants were written (possibly none) and the marker recorded.</summary>
    Completed,

    /// <summary>The marker already existed; nothing was read or written.</summary>
    AlreadyDone,

    /// <summary>FileManagement or FileViewer does not exist (yet); nothing written, no marker — retried next setup.</summary>
    RoleMissing
}

internal sealed record FileRoleGrantResult(FileRoleGrantStatus Status, FileRoleGrantPlan Plan)
{
    public static readonly FileRoleGrantPlan EmptyPlan = new([], []);
}

/// <summary>
///     AB#6180 (epic AB#6171, decision D5): one-time, additive grant of the new File roles to everybody who holds
///     the Reporting roles today — <c>ReportingManagement</c> → <c>FileManagement</c>,
///     <c>ReportingViewer</c> → <c>FileViewer</c> — so nobody loses access to the file system when the Studio page
///     and the file APIs switch from the Reporting roles to the File roles. See <see cref="FileRoleGrantPlanner"/>
///     for the rule (direct holders: users, groups, clients via <c>AssignedRole</c>; external tenant user mappings
///     via <c>MappedRoleIds</c>).
/// </summary>
/// <remarks>
///     <para>
///         Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> right AFTER the
///         <c>System.Identity.Bootstrap</c> blueprint apply, because the File roles (660…61/62, blueprint 1.5.0)
///         have to exist first. That is why this is not an <c>IMigration</c>: the infrastructure migrations run
///         before the blueprint apply. Same shape as the AB#5544 SecretManagement administrator grant.
///     </para>
///     <para>
///         Never removes anything. Only <c>AssignedRole</c> insert edges and <c>MappedRoleIds</c> appends are
///         written, and only for subjects that do not hold the target role yet. The marker
///         (<see cref="IdentityServiceConstants.FileRoleGrantKey"/>) is written after the changes are committed; a
///         crash in between re-runs the step, which then finds the grants and writes nothing new.
///     </para>
/// </remarks>
internal static class FileRoleGrant
{
    public static async Task<FileRoleGrantResult> EnsureAsync(ITenantContext tenantContext, ILogger logger)
    {
        using (var readSession = await tenantContext.GetAdminSessionAsync())
        {
            var marker = await tenantContext.GetConfigurationAsync<FileRoleGrantMarker>(
                readSession, IdentityServiceConstants.FileRoleGrantKey, defaultValue: null);
            if (marker != null)
            {
                return new FileRoleGrantResult(FileRoleGrantStatus.AlreadyDone, FileRoleGrantResult.EmptyPlan);
            }
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        FileRoleGrantPlan plan;
        Dictionary<string, string> roleNamesById;
        using (var session = await tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
            var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(
                roles.Items, tenantContext.TenantId, logger);

            if (!roleIndex.TryGetValue(IdentityServiceConstants.FileManagementRole, out var fileManagementRoleId)
                || !roleIndex.TryGetValue(IdentityServiceConstants.FileViewerRole, out var fileViewerRoleId))
            {
                await session.CommitTransactionAsync();
                logger.LogWarning(
                    "File roles ({FileManagementRole}/{FileViewerRole}) not found in tenant '{TenantId}'; the one-time " +
                    "grant to the Reporting role holders is retried on the next tenant setup",
                    IdentityServiceConstants.FileManagementRole, IdentityServiceConstants.FileViewerRole,
                    tenantContext.TenantId);
                return new FileRoleGrantResult(FileRoleGrantStatus.RoleMissing, FileRoleGrantResult.EmptyPlan);
            }

            // A tenant without a Reporting role simply has nobody to mirror for that pair.
            var pairs = new List<FileRoleGrantPair>();
            if (roleIndex.TryGetValue(CommonConstants.ReportingManagementRole, out var reportingManagementRoleId))
            {
                pairs.Add(new FileRoleGrantPair(reportingManagementRoleId.ToString(), fileManagementRoleId.ToString()));
            }

            if (roleIndex.TryGetValue(CommonConstants.ReportingViewerRole, out var reportingViewerRoleId))
            {
                pairs.Add(new FileRoleGrantPair(reportingViewerRoleId.ToString(), fileViewerRoleId.ToString()));
            }

            roleNamesById = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [fileManagementRoleId.ToString()] = IdentityServiceConstants.FileManagementRole,
                [fileViewerRoleId.ToString()] = IdentityServiceConstants.FileViewerRole
            };

            var input = await ReadRoleHoldingsAsync(tenantRepository, session);
            await session.CommitTransactionAsync();

            plan = FileRoleGrantPlanner.Plan(input, pairs);

            if (!plan.IsEmpty)
            {
                using var writeSession = await tenantRepository.GetSessionAsync();
                writeSession.StartTransaction();

                var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
                var edgeUpdates = plan.Edges.Select(edge => AssociationUpdateInfo.CreateInsert(
                        new RtEntityId(SubjectCkTypeId(edge.Kind), new OctoObjectId(edge.SubjectId)),
                        new RtEntityId(roleCkTypeId, new OctoObjectId(edge.RoleId)),
                        IdentityAssociationConstants.AssignedRoleId))
                    .ToList();
                if (edgeUpdates.Count > 0)
                {
                    await tenantRepository.ApplyChangesAsync(writeSession, edgeUpdates, new OperationResult());
                }

                foreach (var (mappingId, additions) in plan.MappingAdditions)
                {
                    var mapping = await tenantRepository
                        .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(writeSession, new OctoObjectId(mappingId));
                    if (mapping == null)
                    {
                        continue;
                    }

                    var mappedRoleIds = mapping.MappedRoleIds?.ToList() ?? [];
                    mappedRoleIds.AddRange(additions);
                    mapping.MappedRoleIds = new AttributeStringValueList(mappedRoleIds);
                    await tenantRepository.ApplyChangesAsync(
                        writeSession,
                        new[] { EntityUpdateInfo<RtExternalTenantUserMapping>.CreateUpdate(mapping.ToRtEntityId(), mapping) },
                        new OperationResult());
                }

                await writeSession.CommitTransactionAsync();
            }
        }

        var grantedAssignments = plan.Edges
            .Select(e => $"{e.Kind}:{e.SubjectId}:{roleNamesById[e.RoleId]}")
            .ToList();
        var grantedMappingRoles = plan.MappingAdditions
            .SelectMany(m => m.Value.Select(roleId => $"{m.Key}:{roleNamesById[roleId]}"))
            .ToList();

        using (var markerSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                markerSession,
                IdentityServiceConstants.FileRoleGrantKey,
                new FileRoleGrantMarker
                {
                    CompletedAtUtc = DateTime.UtcNow,
                    GrantedAssignments = grantedAssignments,
                    GrantedMappingRoles = grantedMappingRoles
                });
        }

        logger.LogInformation(
            "File roles granted to the Reporting role holders of tenant '{TenantId}': {EdgeCount} AssignedRole edges " +
            "({Assignments}), {MappingCount} external mapping roles ({MappingRoles}); recorded as done",
            tenantContext.TenantId, grantedAssignments.Count, string.Join(", ", grantedAssignments),
            grantedMappingRoles.Count, string.Join(", ", grantedMappingRoles));

        return new FileRoleGrantResult(FileRoleGrantStatus.Completed, plan);
    }

    private static RtCkId<CkTypeId> SubjectCkTypeId(FileRoleGrantSubjectKind kind) => kind switch
    {
        FileRoleGrantSubjectKind.User => RtEntityExtensions.GetRtCkTypeId<RtUser>(),
        FileRoleGrantSubjectKind.Group => RtEntityExtensions.GetRtCkTypeId<RtGroup>(),
        FileRoleGrantSubjectKind.Client => RtEntityExtensions.GetRtCkTypeId<RtClient>(),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null)
    };

    private static async Task<FileRoleGrantInput> ReadRoleHoldingsAsync(
        ITenantRepository tenantRepository, IOctoSession session)
    {
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        var userRoles = await ReadAssignedRolesAsync<RtUser>();
        var groupRoles = await ReadAssignedRolesAsync<RtGroup>();
        var clientRoles = await ReadAssignedRolesAsync<RtClient>();

        var mappingRoles = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
        var mappings = await tenantRepository.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(
            session, RtEntityQueryOptions.Create());
        foreach (var mapping in mappings.Items)
        {
            mappingRoles[mapping.RtId.ToString()] =
                (mapping.MappedRoleIds ?? Enumerable.Empty<string>()).ToHashSet(StringComparer.Ordinal);
        }

        return new FileRoleGrantInput(userRoles, groupRoles, clientRoles, mappingRoles);

        async Task<Dictionary<string, IReadOnlySet<string>>> ReadAssignedRolesAsync<TSubject>()
            where TSubject : RtEntity, new()
        {
            var result = new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal);
            var subjects = await tenantRepository.GetRtEntitiesByTypeAsync<TSubject>(session, RtEntityQueryOptions.Create());
            foreach (var subject in subjects.Items)
            {
                var edges = await tenantRepository.GetRtAssociationsAsync(
                    session, subject.ToRtEntityId(),
                    RtAssociationExtendedQueryOptions.Create(
                        GraphDirections.Outbound, roleId: IdentityAssociationConstants.AssignedRoleId));
                result[subject.RtId.ToString()] = edges.Items
                    .Where(e => e.TargetCkTypeId == roleCkTypeId)
                    .Select(e => e.TargetRtId.ToString())
                    .ToHashSet(StringComparer.Ordinal);
            }

            return result;
        }
    }
}
