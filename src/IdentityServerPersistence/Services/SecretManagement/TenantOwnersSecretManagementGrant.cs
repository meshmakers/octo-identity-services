using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.SecretManagement;

/// <summary>Marker persisted once <see cref="TenantOwnersSecretManagementGrant"/> has run for a tenant.</summary>
public sealed class TenantOwnersSecretManagementGrantMarker
{
    public DateTime CompletedAtUtc { get; set; }

    public bool GroupEdgeAdded { get; set; }

    public List<string> ExtendedMappingIds { get; set; } = [];
}

/// <summary>Outcome of one <see cref="TenantOwnersSecretManagementGrant.EnsureAsync"/> call.</summary>
internal enum TenantOwnersSecretManagementGrantStatus
{
    /// <summary>The grants were written (possibly none) and the marker recorded.</summary>
    Completed,

    /// <summary>The marker already existed; nothing was read or written.</summary>
    AlreadyDone,

    /// <summary>The SecretManagement role does not exist (yet); nothing written, no marker — retried next setup.</summary>
    RoleMissing,

    /// <summary>
    ///     The tenant has no TenantOwners group. The octosystem mappings were still handled, but no marker is
    ///     recorded, so the group edge is retried on the next setup.
    /// </summary>
    GroupMissing
}

internal sealed record TenantOwnersSecretManagementGrantResult(
    TenantOwnersSecretManagementGrantStatus Status,
    bool GroupEdgeAdded,
    IReadOnlyList<string> ExtendedMappingIds);

/// <summary>
///     AB#8161 (decision Gerald 2026-11-02, supersedes the 2026-10-11 rule that kept SecretManagement away from
///     TenantOwners): before <c>SecretManagementRoleEnforcement</c> goes to <c>Enforce</c> the group
///     <c>TenantOwners</c> of every tenant holds <c>SecretManagement</c>, and so do the mappings that come from the
///     system tenant (octosystem) and carry <c>TenantManagement</c> without being TenantOwners members.
/// </summary>
/// <remarks>
///     <para>
///         Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> after the blueprint apply and next
///         to <see cref="SecretManagementAdminGrant"/>, once per tenant (marker
///         <see cref="IdentityServiceConstants.TenantOwnersSecretManagementGrantKey"/>): an operator who changes
///         the group on purpose afterwards is not overridden. Covers existing tenants (first start with this
///         version) and new tenants (their setup).
///     </para>
///     <para>
///         Additive only: one <c>AssignedRole</c> edge (TenantOwners → SecretManagement) and, for qualifying
///         mappings, <c>SecretManagement</c> appended to <c>MappedRoleIds</c>. Clients that are members of
///         TenantOwners inherit the role by design. No user, client or other group is touched.
///     </para>
/// </remarks>
internal static class TenantOwnersSecretManagementGrant
{
    public static async Task<TenantOwnersSecretManagementGrantResult> EnsureAsync(
        ITenantContext tenantContext, string systemTenantId, ILogger logger)
    {
        using (var readSession = await tenantContext.GetAdminSessionAsync())
        {
            var marker = await tenantContext.GetConfigurationAsync<TenantOwnersSecretManagementGrantMarker>(
                readSession, IdentityServiceConstants.TenantOwnersSecretManagementGrantKey, defaultValue: null);
            if (marker != null)
            {
                return new TenantOwnersSecretManagementGrantResult(
                    TenantOwnersSecretManagementGrantStatus.AlreadyDone, false, []);
            }
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        var groupEdgeAdded = false;
        IReadOnlyList<string> extendedMappings;
        bool groupExists;

        using (var session = await tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
            var roleIndex = DefaultConfigurationCreatorService.BuildRoleNameIndex(
                roles.Items, tenantContext.TenantId, logger);
            if (!roleIndex.TryGetValue(CommonConstants.SecretManagementRole, out var secretManagementRoleId))
            {
                await session.CommitTransactionAsync();
                logger.LogWarning(
                    "SecretManagement role not found in tenant '{TenantId}'; the TenantOwners grant is retried on " +
                    "the next tenant setup", tenantContext.TenantId);
                return new TenantOwnersSecretManagementGrantResult(
                    TenantOwnersSecretManagementGrantStatus.RoleMissing, false, []);
            }

            var groupQuery = RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtGroup.NormalizedGroupName), CommonConstants.TenantOwnersGroup.ToUpperInvariant());
            var group = (await tenantRepository.GetRtEntitiesByTypeAsync<RtGroup>(session, groupQuery))
                .Items.FirstOrDefault();
            groupExists = group != null;

            var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
            var ownerMemberIds = new HashSet<string>(StringComparer.Ordinal);
            var updates = new List<AssociationUpdateInfo>();
            if (group != null)
            {
                var roleEdges = await tenantRepository.GetRtAssociationsAsync(session, group.ToRtEntityId(),
                    RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                        roleId: IdentityAssociationConstants.AssignedRoleId));
                if (!roleEdges.Items.Any(e => e.TargetRtId == secretManagementRoleId))
                {
                    updates.Add(AssociationUpdateInfo.CreateInsert(
                        group.ToRtEntityId(),
                        new RtEntityId(roleCkTypeId, secretManagementRoleId),
                        IdentityAssociationConstants.AssignedRoleId));
                    groupEdgeAdded = true;
                }

                var memberEdges = await tenantRepository.GetRtAssociationsAsync(session, group.ToRtEntityId(),
                    RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                        roleId: IdentityAssociationConstants.GroupMemberId));
                foreach (var edge in memberEdges.Items)
                {
                    ownerMemberIds.Add(edge.TargetRtId.ToString());
                }
            }

            var mappings = await tenantRepository.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(
                session, RtEntityQueryOptions.Create());
            if (roleIndex.TryGetValue(CommonConstants.TenantManagementRole, out var tenantManagementRoleId))
            {
                extendedMappings = TenantOwnersSecretManagementGrantPlanner.PlanMappings(
                    mappings.Items.Select(m => new TenantOwnersGrantMapping(
                        m.RtId.ToString(),
                        m.SourceTenantId,
                        (m.MappedRoleIds ?? Enumerable.Empty<string>()).ToList(),
                        ownerMemberIds.Contains(m.RtId.ToString()))),
                    systemTenantId,
                    tenantManagementRoleId.ToString(),
                    secretManagementRoleId.ToString());
            }
            else
            {
                extendedMappings = [];
            }

            if (updates.Count > 0)
            {
                var opResult = new OperationResult();
                await tenantRepository.ApplyChangesAsync(session, updates, opResult);
                if (opResult.HasErrors || opResult.HasFatalErrors)
                {
                    throw new InvalidOperationException(
                        $"Failed to grant {CommonConstants.SecretManagementRole} to {CommonConstants.TenantOwnersGroup} " +
                        $"of tenant '{tenantContext.TenantId}': {string.Join("; ", opResult.GetMessages())}");
                }
            }

            foreach (var mappingId in extendedMappings)
            {
                var mapping = mappings.Items.First(m => m.RtId.ToString() == mappingId);
                var roleIds = mapping.MappedRoleIds?.ToList() ?? [];
                roleIds.Add(secretManagementRoleId.ToString());
                mapping.MappedRoleIds = new AttributeStringValueList(roleIds);
                await tenantRepository.ReplaceOneRtEntityByIdAsync(session, mapping.RtId, mapping);
            }

            await session.CommitTransactionAsync();
        }

        if (!groupExists)
        {
            logger.LogWarning(
                "Tenant '{TenantId}' has no {Group} group; SecretManagement added to {MappingCount} octosystem " +
                "mappings ({MappingIds}), the group grant is retried on the next tenant setup",
                tenantContext.TenantId, CommonConstants.TenantOwnersGroup, extendedMappings.Count,
                string.Join(", ", extendedMappings));
            return new TenantOwnersSecretManagementGrantResult(
                TenantOwnersSecretManagementGrantStatus.GroupMissing, false, extendedMappings);
        }

        using (var markerSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                markerSession,
                IdentityServiceConstants.TenantOwnersSecretManagementGrantKey,
                new TenantOwnersSecretManagementGrantMarker
                {
                    CompletedAtUtc = DateTime.UtcNow,
                    GroupEdgeAdded = groupEdgeAdded,
                    ExtendedMappingIds = extendedMappings.ToList()
                });
        }

        logger.LogInformation(
            "SecretManagement for tenant '{TenantId}': {Group} edge added={GroupEdgeAdded}, appended to " +
            "{MappingCount} octosystem mappings ({MappingIds}); recorded as done",
            tenantContext.TenantId, CommonConstants.TenantOwnersGroup, groupEdgeAdded, extendedMappings.Count,
            string.Join(", ", extendedMappings));

        return new TenantOwnersSecretManagementGrantResult(
            TenantOwnersSecretManagementGrantStatus.Completed, groupEdgeAdded, extendedMappings);
    }
}
