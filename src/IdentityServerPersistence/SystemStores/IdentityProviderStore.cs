using AutoMapper;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repository;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public class IdentityProviderStore : IOctoIdentityProviderStore
{
    private readonly IMapper _mapper;
    private readonly ITenantRepository _tenantRepository;

    public IdentityProviderStore(IMultiTenancyResolverService multiTenancyResolverService, IMapper mapper)
    {
        _tenantRepository = multiTenancyResolverService.GetTenantRepository();
        _mapper = mapper;
    }

    public async Task<RtIdentityProvider?> GetByNameAsync(string name)
    {
        ArgumentValidation.ValidateString(nameof(name), name);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtIdentityProvider.Name), FieldFilterOperator.Equals, name);

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, dataQueryOperation);

        await session.CommitTransactionAsync();
        return result.Items.SingleOrDefault();
    }

    public async Task<IEnumerable<RtIdentityProvider>> GetAllAsync()
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var dataQueryOperation = DataQueryOperation.Create();

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, dataQueryOperation);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task StoreAsync(RtIdentityProvider identityProvider)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await _tenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(session, identityProvider.RtId);
        if (result == null)
        {
            await _tenantRepository.InsertOneRtEntityAsync(session, identityProvider);
        }
        else
        {
            await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, identityProvider.RtId, identityProvider);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAsync(string id)
    {
        ArgumentValidation.ValidateString(nameof(id), id);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtIdentityProvider>(session, new OctoObjectId(id));

        await session.CommitTransactionAsync();
    }
}