using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;

using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Implementation of <see cref="IDataPermissionStore" /> (AB#4972). Same lazy tenant-repository
///     resolution as the other identity stores.
/// </summary>
public class DataPermissionStore(
    IMultiTenancyResolverService multiTenancyResolverService) : IDataPermissionStore
{
    private ITenantRepository GetRepository() => multiTenancyResolverService.GetTenantRepository();

    /// <inheritdoc />
    public async Task<IReadOnlyList<RtDataPermission>> GetAllAsync()
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var result = await GetRepository()
            .GetRtEntitiesByTypeAsync<RtDataPermission>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();

        return result.Items.ToList();
    }

    /// <inheritdoc />
    public async Task<RtDataPermission?> FindByPermissionIdAsync(string permissionId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();
        var result = await FindByPermissionIdAsync(session, permissionId);
        await session.CommitTransactionAsync();
        return result;
    }

    /// <inheritdoc />
    public async Task<OctoObjectId> CreateAsync(string permissionId, string? description)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var existing = await FindByPermissionIdAsync(session, permissionId);
        if (existing != null)
        {
            await session.CommitTransactionAsync();
            throw new InvalidOperationException($"Data permission '{permissionId}' already exists.");
        }

        var entity = new RtDataPermission
        {
            RtId = OctoObjectId.GenerateNewId(),
            PermissionId = permissionId,
            Description = description
        };
        await GetRepository().InsertOneRtEntityAsync(session, entity);
        await session.CommitTransactionAsync();
        return entity.RtId;
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string permissionId)
    {
        var repository = GetRepository();
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var permission = await FindByPermissionIdAsync(session, permissionId)
                         ?? throw new InvalidOperationException($"Data permission '{permissionId}' not found.");

        // Policies go with their permission — a policy without a permission grants nobody anything
        // but still protects its targets (deny-all trap).
        var policyRtIds = await GetPolicyRtIdsAsync(session, permission.RtId);
        var updates = new List<IEntityUpdateInfo<RtEntity>>();
        foreach (var policyRtId in policyRtIds)
        {
            updates.Add(EntityUpdateInfo<RtEntity>.CreateDelete(
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPolicy>(), policyRtId)));
        }

        updates.Add(EntityUpdateInfo<RtEntity>.CreateDelete(
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPermission>(), permission.RtId)));

        var operationResult = new OperationResult();
        await repository.ApplyChangesAsync(session, updates, operationResult);
        await session.CommitTransactionAsync();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<RtDataPolicy>> GetPoliciesAsync(OctoObjectId permissionRtId)
    {
        var repository = GetRepository();
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var policyRtIds = await GetPolicyRtIdsAsync(session, permissionRtId);
        var policies = policyRtIds.Count == 0
            ? []
            : (await repository.GetRtEntitiesByIdAsync<RtDataPolicy>(session, policyRtIds,
                RtEntityQueryOptions.Create())).Items.ToList();
        await session.CommitTransactionAsync();
        return policies;
    }

    /// <inheritdoc />
    public async Task<OctoObjectId> CreatePolicyAsync(string permissionId, IReadOnlyList<string> targetCkTypeIds,
        IReadOnlyList<string> actions, RtDataPolicyScopeEnum scope,
        RtDataPolicyEnforcementModeEnum enforcementMode)
    {
        var repository = GetRepository();
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var permission = await FindByPermissionIdAsync(session, permissionId)
                         ?? throw new InvalidOperationException($"Data permission '{permissionId}' not found.");

        var policy = new RtDataPolicy
        {
            RtId = OctoObjectId.GenerateNewId(),
            TargetCkTypeIds = new AttributeStringValueList(targetCkTypeIds.ToList()),
            Actions = new AttributeStringValueList(actions.ToList()),
            Scope = scope,
            EnforcementMode = enforcementMode
        };
        // The PolicyPermission association is mandatory (multiplicity One) — the graph rule engine
        // requires entity and edge in the same change set.
        var operationResult = new OperationResult();
        await repository.ApplyChangesAsync(session,
            new List<IEntityUpdateInfo<RtEntity>> { EntityUpdateInfo<RtEntity>.CreateInsert(policy) },
            new List<AssociationUpdateInfo>
            {
                AssociationUpdateInfo.CreateInsert(
                    policy.ToRtEntityId(),
                    permission.ToRtEntityId(),
                    IdentityAssociationConstants.PolicyPermissionId)
            }, operationResult);
        await session.CommitTransactionAsync();
        return policy.RtId;
    }

    /// <inheritdoc />
    public async Task RemovePolicyAsync(OctoObjectId policyRtId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();
        await GetRepository().DeleteOneRtEntityByRtIdAsync<RtDataPolicy>(session, policyRtId, DeleteOptions.Erase);
        await session.CommitTransactionAsync();
    }

    /// <inheritdoc />
    public async Task SetPolicyEnforcementModeAsync(OctoObjectId policyRtId,
        RtDataPolicyEnforcementModeEnum enforcementMode)
    {
        var repository = GetRepository();
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var policy = await repository.GetRtEntityByRtIdAsync<RtDataPolicy>(session, policyRtId)
                     ?? throw new InvalidOperationException($"Data policy '{policyRtId}' not found.");

        var update = new RtDataPolicy { EnforcementMode = enforcementMode };
        var operationResult = new OperationResult();
        await repository.ApplyChangesAsync(session,
            new List<IEntityUpdateInfo<RtEntity>>
            {
                EntityUpdateInfo<RtEntity>.CreateUpdate(policy.ToRtEntityId(), update)
            }, operationResult);
        await session.CommitTransactionAsync();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetGrantedRoleNamesAsync(OctoObjectId permissionRtId)
    {
        var repository = GetRepository();
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var permissionEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPermission>(), permissionRtId);
        var associations = await repository.GetRtAssociationsAsync(session, permissionEntityId,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Any,
                IdentityAssociationConstants.GrantsPermissionId));

        var roleRtIds = associations.Items
            .Select(a => a.OriginRtId == permissionRtId ? a.TargetRtId : a.OriginRtId)
            .Distinct()
            .ToList();

        var roleNames = new List<string>();
        if (roleRtIds.Count > 0)
        {
            var roles = await repository.GetRtEntitiesByIdAsync<RtRole>(session, roleRtIds,
                RtEntityQueryOptions.Create());
            roleNames.AddRange(roles.Items.Select(r => r.Name).Where(n => !string.IsNullOrWhiteSpace(n))
                .Select(n => n!));
        }

        await session.CommitTransactionAsync();
        return roleNames;
    }

    /// <inheritdoc />
    public async Task GrantToRoleAsync(string permissionId, string roleName)
    {
        var repository = GetRepository();
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var permission = await FindByPermissionIdAsync(session, permissionId)
                         ?? throw new InvalidOperationException($"Data permission '{permissionId}' not found.");
        var role = await FindRoleByNameAsync(session, roleName)
                   ?? throw new InvalidOperationException($"Role '{roleName}' not found.");

        var existing = await repository.GetRtAssociationOrDefaultAsync(session, role.ToRtEntityId(),
            permission.ToRtEntityId(), IdentityAssociationConstants.GrantsPermissionId);
        if (existing == null)
        {
            var operationResult = new OperationResult();
            await repository.ApplyChangesAsync(session,
                new List<AssociationUpdateInfo>
                {
                    AssociationUpdateInfo.CreateInsert(role.ToRtEntityId(), permission.ToRtEntityId(),
                        IdentityAssociationConstants.GrantsPermissionId)
                }, operationResult);
        }

        await session.CommitTransactionAsync();
    }

    /// <inheritdoc />
    public async Task RevokeFromRoleAsync(string permissionId, string roleName)
    {
        var repository = GetRepository();
        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var permission = await FindByPermissionIdAsync(session, permissionId)
                         ?? throw new InvalidOperationException($"Data permission '{permissionId}' not found.");
        var role = await FindRoleByNameAsync(session, roleName)
                   ?? throw new InvalidOperationException($"Role '{roleName}' not found.");

        var operationResult = new OperationResult();
        await repository.ApplyChangesAsync(session,
            new List<AssociationUpdateInfo>
            {
                AssociationUpdateInfo.CreateDelete(role.ToRtEntityId(), permission.ToRtEntityId(),
                    IdentityAssociationConstants.GrantsPermissionId)
            }, operationResult);
        await session.CommitTransactionAsync();
    }

    private async Task<RtDataPermission?> FindByPermissionIdAsync(IOctoSession session, string permissionId)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtDataPermission.PermissionId), permissionId);
        var result = await GetRepository().GetRtEntitiesByTypeAsync<RtDataPermission>(session, queryOptions);
        return result.Items.SingleOrDefault();
    }

    private async Task<IReadOnlyList<OctoObjectId>> GetPolicyRtIdsAsync(IOctoSession session,
        OctoObjectId permissionRtId)
    {
        var permissionEntityId = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPermission>(), permissionRtId);
        var associations = await GetRepository().GetRtAssociationsAsync(session, permissionEntityId,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Any,
                IdentityAssociationConstants.PolicyPermissionId));
        return associations.Items
            .Select(a => a.OriginRtId == permissionRtId ? a.TargetRtId : a.OriginRtId)
            .Distinct()
            .ToList();
    }

    private async Task<RtRole?> FindRoleByNameAsync(IOctoSession session, string roleName)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtRole.NormalizedName), roleName.ToUpperInvariant());
        var result = await GetRepository().GetRtEntitiesByTypeAsync<RtRole>(session, queryOptions);
        return result.Items.SingleOrDefault();
    }
}
