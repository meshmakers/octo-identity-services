using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
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
}
