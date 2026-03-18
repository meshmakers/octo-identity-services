using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// Migration 9→10: Converts all StringArray-based relationships (RoleIds, MemberUserIds,
/// MemberExternalUserIds, MemberGroupIds) to CK associations and creates the TenantOwners group
/// for existing tenants.
/// </summary>
[Migration(9, 10, IdentityServiceConstants.IdentityMigrationVersionKey,
    "Convert identity relationships from StringArray attributes to CK associations")]
// ReSharper disable once UnusedType.Global
internal class IdentityAssociationMigration(
    ILogger<IdentityAssociationMigration> logger) : IMigration
{
    // Attribute names as stored in MongoDB documents (from the old CK model)
    private const string RoleIdsField = "RoleIds";
    private const string MemberUserIdsField = "MemberUserIds";
    private const string MemberExternalUserIdsField = "MemberExternalUserIds";
    private const string MemberGroupIdsField = "MemberGroupIds";

    public async Task<MigrationResult> MigrateAsync(IOctoAdminSession adminSession, ITenantContext tenantContext)
    {
        try
        {
            var childRepo = tenantContext.GetTenantRepositoryAsAdmin();

            // Migrate Group entities
            await MigrateGroupsAsync(adminSession, childRepo, tenantContext.TenantId);

            // Migrate User entities
            await MigrateUsersAsync(adminSession, childRepo, tenantContext.TenantId);

            // Ensure TenantOwners group exists with all default roles (via associations)
            await EnsureTenantOwnersGroupAsync(adminSession, childRepo, tenantContext.TenantId);

            return MigrationResult.Success();
        }
        catch (Exception e)
        {
            logger.LogError(e,
                "Failed to migrate identity associations for tenant '{TenantId}'",
                tenantContext.TenantId);
            return MigrationResult.Failure($"Failed to migrate identity associations: {e.Message}");
        }
    }

    private async Task MigrateGroupsAsync(
        IOctoAdminSession adminSession, ITenantRepository childRepo, string tenantId)
    {
        var groupResult = await childRepo.GetRtEntitiesByTypeAsync<RtGroup>(
            adminSession, RtEntityQueryOptions.Create());

        var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        var extUserCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtExternalTenantUserMapping>();

        foreach (var group in groupResult.Items)
        {
            var groupEntityId = new RtEntityId(groupCkTypeId, group.RtId);

            // Read old StringArray attributes from the entity's generic attribute store.
            // The CK model v2.3.0 removed these attributes from the type definition,
            // but existing MongoDB documents still contain them.
            var roleIds = GetStringArrayAttribute(group, RoleIdsField);
            var memberUserIds = GetStringArrayAttribute(group, MemberUserIdsField);
            var memberExternalUserIds = GetStringArrayAttribute(group, MemberExternalUserIdsField);
            var memberGroupIds = GetStringArrayAttribute(group, MemberGroupIdsField);

            // Get existing associations to avoid duplicates (some may have been created
            // by DefaultConfigurationCreatorService before the migration runs)
            var existingTargetIds = await GetExistingAssociationTargetIdsAsync(
                adminSession, childRepo, groupEntityId);

            var updates = new List<AssociationUpdateInfo>();

            // RoleIds → AssignedRole associations
            foreach (var roleId in roleIds)
            {
                var targetId = new RtEntityId(roleCkTypeId, new OctoObjectId(roleId));
                if (!existingTargetIds.Contains(targetId.ToString()))
                {
                    updates.Add(AssociationUpdateInfo.CreateInsert(
                        groupEntityId, targetId,
                        IdentityAssociationConstants.AssignedRoleId));
                }
            }

            // MemberUserIds → GroupMember associations (target: User)
            foreach (var userId in memberUserIds)
            {
                var targetId = new RtEntityId(userCkTypeId, new OctoObjectId(userId));
                if (!existingTargetIds.Contains(targetId.ToString()))
                {
                    updates.Add(AssociationUpdateInfo.CreateInsert(
                        groupEntityId, targetId,
                        IdentityAssociationConstants.GroupMemberId));
                }
            }

            // MemberExternalUserIds → GroupMember associations (target: ExternalTenantUserMapping)
            foreach (var extUserId in memberExternalUserIds)
            {
                var targetId = new RtEntityId(extUserCkTypeId, new OctoObjectId(extUserId));
                if (!existingTargetIds.Contains(targetId.ToString()))
                {
                    updates.Add(AssociationUpdateInfo.CreateInsert(
                        groupEntityId, targetId,
                        IdentityAssociationConstants.GroupMemberId));
                }
            }

            // MemberGroupIds → ChildGroup associations
            foreach (var childGroupId in memberGroupIds)
            {
                var targetId = new RtEntityId(groupCkTypeId, new OctoObjectId(childGroupId));
                if (!existingTargetIds.Contains(targetId.ToString()))
                {
                    updates.Add(AssociationUpdateInfo.CreateInsert(
                        groupEntityId, targetId,
                        IdentityAssociationConstants.ChildGroupId));
                }
            }

            if (updates.Count > 0)
            {
                var opResult = new OperationResult();
                await childRepo.ApplyChangesAsync(adminSession, updates, opResult);

                logger.LogInformation(
                    "Migrated group '{GroupName}' in tenant '{TenantId}': {Count} associations created",
                    group.GroupName, tenantId, updates.Count);
            }
        }
    }

    private async Task MigrateUsersAsync(
        IOctoAdminSession adminSession, ITenantRepository childRepo, string tenantId)
    {
        var userResult = await childRepo.GetRtEntitiesByTypeAsync<RtUser>(
            adminSession, RtEntityQueryOptions.Create());

        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        foreach (var user in userResult.Items)
        {
            var userEntityId = new RtEntityId(userCkTypeId, user.RtId);
            var roleIds = GetStringArrayAttribute(user, RoleIdsField);

            if (roleIds.Count == 0)
            {
                continue;
            }

            // Get existing associations to avoid duplicates
            var existingTargetIds = await GetExistingAssociationTargetIdsAsync(
                adminSession, childRepo, userEntityId);

            var updates = new List<AssociationUpdateInfo>();
            foreach (var roleId in roleIds)
            {
                var targetId = new RtEntityId(roleCkTypeId, new OctoObjectId(roleId));
                if (!existingTargetIds.Contains(targetId.ToString()))
                {
                    updates.Add(AssociationUpdateInfo.CreateInsert(
                        userEntityId, targetId,
                        IdentityAssociationConstants.AssignedRoleId));
                }
            }

            if (updates.Count == 0)
            {
                continue;
            }

            var opResult = new OperationResult();
            await childRepo.ApplyChangesAsync(adminSession, updates, opResult);

            logger.LogInformation(
                "Migrated user '{UserName}' in tenant '{TenantId}': {Count} role associations created",
                user.UserName, tenantId, updates.Count);
        }
    }

    private async Task EnsureTenantOwnersGroupAsync(
        IOctoAdminSession adminSession, ITenantRepository childRepo, string tenantId)
    {
        var normalizedName = CommonConstants.TenantOwnersGroup.ToUpperInvariant();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName), normalizedName);
        var groupResult = await childRepo.GetRtEntitiesByTypeAsync<RtGroup>(adminSession, queryOptions);

        RtGroup group;
        if (!groupResult.Items.Any())
        {
            group = new RtGroup
            {
                RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
                GroupName = CommonConstants.TenantOwnersGroup,
                NormalizedGroupName = normalizedName,
                GroupDescription =
                    "Default group with all roles assigned. Members inherit all tenant permissions."
            };
            await childRepo.InsertOneRtEntityAsync(adminSession, group);

            logger.LogInformation(
                "Migration created TenantOwners group in tenant '{TenantId}'", tenantId);
        }
        else
        {
            group = groupResult.Items.First();
        }

        // Collect all role RtIds and ensure associations
        var roleResult = await childRepo.GetRtEntitiesByTypeAsync<RtRole>(
            adminSession, RtEntityQueryOptions.Create());
        var roleIds = roleResult.Items.Select(r => r.RtId.ToString()).ToList();

        var groupEntityId = group.ToRtEntityId();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        // Get existing associations to avoid duplicates
        var currentAssociations = await childRepo.GetRtAssociationsAsync(
            adminSession,
            groupEntityId,
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        var existingRoleIds = currentAssociations.Items
            .Select(a => a.TargetRtId.ToString())
            .ToHashSet();

        var updates = new List<AssociationUpdateInfo>();
        foreach (var roleId in roleIds)
        {
            if (!existingRoleIds.Contains(roleId))
            {
                updates.Add(AssociationUpdateInfo.CreateInsert(
                    groupEntityId,
                    new RtEntityId(roleCkTypeId, new OctoObjectId(roleId)),
                    IdentityAssociationConstants.AssignedRoleId));
            }
        }

        if (updates.Count > 0)
        {
            var opResult = new OperationResult();
            await childRepo.ApplyChangesAsync(adminSession, updates, opResult);

            logger.LogInformation(
                "Migration ensured TenantOwners group in tenant '{TenantId}' has {RoleCount} role associations",
                tenantId, roleIds.Count);
        }
    }

    /// <summary>
    /// Queries all outbound associations of an entity and returns the set of target entity IDs
    /// (as strings) to allow duplicate detection before creating new associations.
    /// </summary>
    private static async Task<HashSet<string>> GetExistingAssociationTargetIdsAsync(
        IOctoAdminSession adminSession, ITenantRepository childRepo, RtEntityId entityId)
    {
        var existing = await childRepo.GetRtAssociationsAsync(
            adminSession, entityId,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound));

        return existing.Items
            .Select(a => new RtEntityId(a.TargetCkTypeId, a.TargetRtId).ToString())
            .ToHashSet();
    }

    /// <summary>
    /// Reads a StringArray attribute value from the entity's raw attribute storage.
    /// Since the CK model v2.3.0 removed these properties from the generated types,
    /// we access them through the base entity's generic attribute accessor.
    /// </summary>
    private static List<string> GetStringArrayAttribute(RtEntity entity, string attributeName)
    {
        var values = entity.GetAttributeStringValuesOrDefault(attributeName);
        if (values != null)
        {
            return values.Where(s => !string.IsNullOrEmpty(s)).ToList();
        }

        return [];
    }
}
