using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class GroupStore(
    IMultiTenancyResolverService multiTenancyResolverService) : IGroupStore
{
    // IMPORTANT: Do NOT capture the tenant repository in a field initializer.
    // This service may be constructed during authentication (via OctoUserStore → GroupRoleResolver),
    // before the inline middleware has resolved the tenant from the route. Resolving lazily ensures
    // each call uses the current tenant context from HttpContext.Items.
    private ITenantRepository GetRepository() => multiTenancyResolverService.GetTenantRepository();

    public async Task<RtGroup?> FindByIdAsync(OctoObjectId rtId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var result = await GetRepository()
            .GetRtEntityByRtIdAsync<RtGroup>(session, rtId);
        await session.CommitTransactionAsync();

        return result;
    }

    public async Task<RtGroup?> FindByNameAsync(string normalizedGroupName)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName), normalizedGroupName);

        var result = await GetRepository()
            .GetRtEntitiesByTypeAsync<RtGroup>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items.SingleOrDefault();
    }

    public async Task<IEnumerable<RtGroup>> GetAllAsync(int? skip = null, int? take = null)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();
        var result = await GetRepository()
            .GetRtEntitiesByTypeAsync<RtGroup>(session, queryOptions, skip, take);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task StoreAsync(RtGroup group)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var existing = await GetRepository()
            .GetRtEntityByRtIdAsync<RtGroup>(session, group.RtId);
        if (existing == null)
        {
            await GetRepository().InsertOneRtEntityAsync(session, group);
        }
        else
        {
            await GetRepository().ReplaceOneRtEntityByIdAsync(session, group.RtId, group);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAsync(OctoObjectId rtId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        await GetRepository()
            .DeleteOneRtEntityByRtIdAsync<RtGroup>(session, rtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    // ========================================
    // Role associations (AssignedRole)
    // ========================================

    public async Task<IReadOnlyList<string>> GetRoleIdsAsync(OctoObjectId groupRtId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var group = await GetRepository().GetRtEntityByRtIdAsync<RtGroup>(session, groupRtId);
        if (group == null)
        {
            await session.CommitTransactionAsync();
            return [];
        }

        var associations = await GetRepository().GetRtAssociationsAsync(
            session,
            group.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        await session.CommitTransactionAsync();

        return associations.Items.Select(a => a.TargetRtId.ToString()).ToList();
    }

    public async Task SetRoleIdsAsync(OctoObjectId groupRtId, IReadOnlyList<string> roleIds)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var group = await GetRepository().GetRtEntityByRtIdAsync<RtGroup>(session, groupRtId);
        if (group == null)
        {
            await session.CommitTransactionAsync();
            return;
        }

        var groupEntityId = group.ToRtEntityId();

        // Get current associations
        var currentAssociations = await GetRepository().GetRtAssociationsAsync(
            session,
            groupEntityId,
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        var currentRoleIds = currentAssociations.Items
            .Select(a => a.TargetRtId.ToString())
            .ToHashSet();
        var desiredRoleIds = roleIds.ToHashSet();

        var updates = new List<AssociationUpdateInfo>();

        // Delete removed
        foreach (var assoc in currentAssociations.Items)
        {
            if (!desiredRoleIds.Contains(assoc.TargetRtId.ToString()))
            {
                updates.Add(AssociationUpdateInfo.CreateDelete(
                    groupEntityId,
                    new RtEntityId(assoc.TargetCkTypeId, assoc.TargetRtId),
                    IdentityAssociationConstants.AssignedRoleId));
            }
        }

        // Add new
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();
        foreach (var roleId in desiredRoleIds)
        {
            if (!currentRoleIds.Contains(roleId))
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
            await GetRepository().ApplyChangesAsync(session, updates, opResult);
        }

        await session.CommitTransactionAsync();
    }

    // ========================================
    // User member associations (GroupMember → User)
    // ========================================

    public async Task<IReadOnlyList<string>> GetMemberUserIdsAsync(OctoObjectId groupRtId)
    {
        return await GetOutboundTargetIdsAsync<RtUser>(
            groupRtId, IdentityAssociationConstants.GroupMemberId);
    }

    public async Task AddMemberUserAsync(OctoObjectId groupRtId, string userId)
    {
        await AddOutboundAssociationAsync<RtUser>(
            groupRtId, userId, IdentityAssociationConstants.GroupMemberId);
    }

    public async Task RemoveMemberUserAsync(OctoObjectId groupRtId, string userId)
    {
        await RemoveOutboundAssociationAsync<RtUser>(
            groupRtId, userId, IdentityAssociationConstants.GroupMemberId);
    }

    // ========================================
    // External user member associations (GroupMember → ExternalTenantUserMapping)
    // ========================================

    public async Task<IReadOnlyList<string>> GetMemberExternalUserIdsAsync(OctoObjectId groupRtId)
    {
        return await GetOutboundTargetIdsAsync<RtExternalTenantUserMapping>(
            groupRtId, IdentityAssociationConstants.GroupMemberId);
    }

    // ========================================
    // Child group associations (ChildGroup)
    // ========================================

    public async Task<IReadOnlyList<string>> GetMemberGroupIdsAsync(OctoObjectId groupRtId)
    {
        return await GetOutboundTargetIdsAsync<RtGroup>(
            groupRtId, IdentityAssociationConstants.ChildGroupId);
    }

    public async Task AddMemberGroupAsync(OctoObjectId groupRtId, string childGroupId)
    {
        await AddOutboundAssociationAsync<RtGroup>(
            groupRtId, childGroupId, IdentityAssociationConstants.ChildGroupId);
    }

    public async Task RemoveMemberGroupAsync(OctoObjectId groupRtId, string childGroupId)
    {
        await RemoveOutboundAssociationAsync<RtGroup>(
            groupRtId, childGroupId, IdentityAssociationConstants.ChildGroupId);
    }

    // ========================================
    // Private helpers
    // ========================================

    private async Task<IReadOnlyList<string>> GetOutboundTargetIdsAsync<TTarget>(
        OctoObjectId originRtId,
        RtCkId<CkAssociationRoleId> roleId) where TTarget : RtEntity, new()
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var origin = await GetRepository().GetRtEntityByRtIdAsync<RtGroup>(session, originRtId);
        if (origin == null)
        {
            await session.CommitTransactionAsync();
            return [];
        }

        var targetCkTypeId = RtEntityExtensions.GetRtCkTypeId<TTarget>();
        var associations = await GetRepository().GetRtAssociationsAsync(
            session,
            origin.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: roleId));
        await session.CommitTransactionAsync();

        return associations.Items
            .Where(a => a.TargetCkTypeId == targetCkTypeId)
            .Select(a => a.TargetRtId.ToString())
            .ToList();
    }

    private async Task AddOutboundAssociationAsync<TTarget>(
        OctoObjectId originRtId,
        string targetRtIdString,
        RtCkId<CkAssociationRoleId> roleId) where TTarget : RtEntity, new()
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var origin = await GetRepository().GetRtEntityByRtIdAsync<RtGroup>(session, originRtId);
        if (origin == null)
        {
            await session.CommitTransactionAsync();
            return;
        }

        var targetCkTypeId = RtEntityExtensions.GetRtCkTypeId<TTarget>();
        var targetEntityId = new RtEntityId(targetCkTypeId, new OctoObjectId(targetRtIdString));

        // Check if association already exists
        var existing = await GetRepository().GetRtAssociationOrDefaultAsync(
            session, origin.ToRtEntityId(), targetEntityId, roleId);
        if (existing != null)
        {
            await session.CommitTransactionAsync();
            return;
        }

        var updates = new List<AssociationUpdateInfo>
        {
            AssociationUpdateInfo.CreateInsert(origin.ToRtEntityId(), targetEntityId, roleId)
        };

        var opResult = new OperationResult();
        await GetRepository().ApplyChangesAsync(session, updates, opResult);
        await session.CommitTransactionAsync();
    }

    private async Task RemoveOutboundAssociationAsync<TTarget>(
        OctoObjectId originRtId,
        string targetRtIdString,
        RtCkId<CkAssociationRoleId> roleId) where TTarget : RtEntity, new()
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var origin = await GetRepository().GetRtEntityByRtIdAsync<RtGroup>(session, originRtId);
        if (origin == null)
        {
            await session.CommitTransactionAsync();
            return;
        }

        var targetCkTypeId = RtEntityExtensions.GetRtCkTypeId<TTarget>();
        var targetEntityId = new RtEntityId(targetCkTypeId, new OctoObjectId(targetRtIdString));

        var updates = new List<AssociationUpdateInfo>
        {
            AssociationUpdateInfo.CreateDelete(origin.ToRtEntityId(), targetEntityId, roleId)
        };

        var opResult = new OperationResult();
        await GetRepository().ApplyChangesAsync(session, updates, opResult);
        await session.CommitTransactionAsync();
    }
}
