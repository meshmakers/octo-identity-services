using System.Globalization;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
/// CK-association-based implementation of <see cref="IClientRoleStore" />. Manages the
/// <c>AssignedRole</c> edges between a <c>Client</c> and its <c>Role</c>s and resolves the
/// effective role set (direct + group-inherited) for token issuance.
/// </summary>
public class ClientRoleStore(
    IMultiTenancyResolverService multiTenancyResolverService,
    IGroupRoleResolver groupRoleResolver,
    ILogger<ClientRoleStore> logger) : IClientRoleStore
{
    // Resolve lazily — like GroupStore, this may be constructed during token issuance before the
    // inline middleware has resolved the tenant from the route.
    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async Task<IReadOnlyList<string>> GetDirectRoleIdsAsync(OctoObjectId clientRtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var client = await TenantRepository.GetRtEntityByRtIdAsync<RtClient>(session, clientRtId);
        if (client == null)
        {
            await session.CommitTransactionAsync();
            return [];
        }

        var associations = await TenantRepository.GetRtAssociationsAsync(
            session,
            client.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        await session.CommitTransactionAsync();

        return associations.Items.Select(a => a.TargetRtId.ToString()).ToList();
    }

    public async Task SetRoleIdsAsync(OctoObjectId clientRtId, IReadOnlyList<string> roleIds)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var client = await TenantRepository.GetRtEntityByRtIdAsync<RtClient>(session, clientRtId);
        if (client == null)
        {
            await session.CommitTransactionAsync();
            return;
        }

        var clientEntityId = client.ToRtEntityId();

        var currentAssociations = await TenantRepository.GetRtAssociationsAsync(
            session,
            clientEntityId,
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
                    clientEntityId,
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
                    clientEntityId,
                    new RtEntityId(roleCkTypeId, new OctoObjectId(roleId)),
                    IdentityAssociationConstants.AssignedRoleId));
            }
        }

        if (updates.Count > 0)
        {
            var opResult = new OperationResult();
            await TenantRepository.ApplyChangesAsync(session, updates, opResult);
        }

        await session.CommitTransactionAsync();

        logger.LogInformation(
            "Set {RoleCount} role(s) on client '{ClientRtId}' in tenant '{TenantId}' (added/removed {ChangeCount} association(s))",
            desiredRoleIds.Count, clientRtId, TenantRepository.TenantId, updates.Count);
    }

    public async Task AddRoleAsync(OctoObjectId clientRtId, string roleName)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var client = await TenantRepository.GetRtEntityByRtIdAsync<RtClient>(session, clientRtId);
        if (client == null)
        {
            await session.CommitTransactionAsync();
            throw new NotExistingException($"Client '{clientRtId}' does not exist.");
        }

        var role = await FindRoleByNameAsync(session, roleName);
        if (role == null)
        {
            await session.CommitTransactionAsync();
            throw new InvalidOperationException(string.Format(
                CultureInfo.CurrentCulture, "Role {0} does not exist.", roleName));
        }

        var clientEntityId = client.ToRtEntityId();
        var roleEntityId = role.ToRtEntityId();

        var existing = await TenantRepository.GetRtAssociationOrDefaultAsync(
            session, clientEntityId, roleEntityId, IdentityAssociationConstants.AssignedRoleId);
        if (existing == null)
        {
            var updates = new List<AssociationUpdateInfo>
            {
                AssociationUpdateInfo.CreateInsert(clientEntityId, roleEntityId,
                    IdentityAssociationConstants.AssignedRoleId)
            };
            var opResult = new OperationResult();
            await TenantRepository.ApplyChangesAsync(session, updates, opResult);

            logger.LogInformation(
                "Assigned role '{RoleName}' to client '{ClientRtId}' in tenant '{TenantId}'",
                roleName, clientRtId, TenantRepository.TenantId);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveRoleAsync(OctoObjectId clientRtId, string roleName)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var client = await TenantRepository.GetRtEntityByRtIdAsync<RtClient>(session, clientRtId);
        if (client == null)
        {
            await session.CommitTransactionAsync();
            return;
        }

        var role = await FindRoleByNameAsync(session, roleName);
        if (role == null)
        {
            await session.CommitTransactionAsync();
            return;
        }

        var updates = new List<AssociationUpdateInfo>
        {
            AssociationUpdateInfo.CreateDelete(
                client.ToRtEntityId(),
                role.ToRtEntityId(),
                IdentityAssociationConstants.AssignedRoleId)
        };
        var opResult = new OperationResult();
        await TenantRepository.ApplyChangesAsync(session, updates, opResult);

        await session.CommitTransactionAsync();

        logger.LogInformation(
            "Removed role '{RoleName}' from client '{ClientRtId}' in tenant '{TenantId}'",
            roleName, clientRtId, TenantRepository.TenantId);
    }

    public async Task<IReadOnlySet<string>> GetEffectiveRoleNamesAsync(OctoObjectId clientRtId)
    {
        // Direct role RtIds via AssignedRole, merged with group-inherited role RtIds.
        var allRoleIds = new HashSet<string>(await GetDirectRoleIdsAsync(clientRtId));

        var groupRoleIds = await groupRoleResolver.ResolveEffectiveRoleIdsAsync(clientRtId.ToString());
        allRoleIds.UnionWith(groupRoleIds);

        if (allRoleIds.Count == 0)
        {
            return new HashSet<string>();
        }

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var roleNames = new HashSet<string>();
        foreach (var roleRtIdString in allRoleIds)
        {
            var role = await TenantRepository.GetRtEntityByRtIdAsync<RtRole>(
                session, new OctoObjectId(roleRtIdString));
            if (!string.IsNullOrWhiteSpace(role?.Name))
            {
                roleNames.Add(role.Name);
            }
        }

        await session.CommitTransactionAsync();
        return roleNames;
    }

    private async Task<RtRole?> FindRoleByNameAsync(IOctoSession session, string roleName)
    {
        // Roles store an uppercase NormalizedName (ASP.NET Identity UpperInvariant normalizer).
        var normalized = roleName.ToUpperInvariant();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, normalized);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, queryOptions);
        return result.Items.FirstOrDefault();
    }
}
