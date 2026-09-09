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
///     CK-association-based implementation of <see cref="IClientImpersonationStore" /> over the
///     <c>System.Identity/MayActAs</c> edge (AB#5114). Same tenant-resolution idiom as
///     <see cref="ClientRoleStore" />: the repository is resolved lazily per call, so construction
///     during token issuance (before the inline middleware wired the tenant) is safe.
/// </summary>
public class ClientImpersonationStore(
    IMultiTenancyResolverService multiTenancyResolverService) : IClientImpersonationStore
{
    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async Task<bool> HasMayActAsEdgeAsync(OctoObjectId actorClientRtId, OctoObjectId targetClientRtId)
    {
        var clientCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtClient>();

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var association = await TenantRepository.GetRtAssociationOrDefaultAsync(
            session,
            new RtEntityId(clientCkTypeId, actorClientRtId),
            new RtEntityId(clientCkTypeId, targetClientRtId),
            IdentityAssociationConstants.MayActAsId);

        await session.CommitTransactionAsync();
        return association != null;
    }

    public async Task<IReadOnlyList<string>> GetActorClientIdsAsync(OctoObjectId targetClientRtId)
    {
        var clientCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtClient>();

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var target = await TenantRepository.GetRtEntityByRtIdAsync<RtClient>(session, targetClientRtId);
        if (target == null)
        {
            await session.CommitTransactionAsync();
            return [];
        }

        // Inbound MayActAs associations: actor Client --MayActAs--> target Client. Same inbound
        // idiom as GroupStore's mapping→group resolution.
        var associations = await TenantRepository.GetRtAssociationsAsync(
            session,
            target.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Inbound,
                roleId: IdentityAssociationConstants.MayActAsId));

        var actorClientIds = new List<string>();
        foreach (var association in associations.Items.Where(a => a.OriginCkTypeId == clientCkTypeId))
        {
            var actor = await TenantRepository.GetRtEntityByRtIdAsync<RtClient>(session, association.OriginRtId);
            if (!string.IsNullOrWhiteSpace(actor?.ClientId))
            {
                actorClientIds.Add(actor.ClientId);
            }
        }

        await session.CommitTransactionAsync();
        return actorClientIds;
    }
}
