using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class IdentityProviderStore(IMultiTenancyResolverService multiTenancyResolverService)
    : IOctoIdentityProviderStore
{
    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public string TenantId => TenantRepository.TenantId;

    public async Task<RtIdentityProvider?> GetByNameAsync(string name)
    {
        ArgumentValidation.ValidateString(nameof(name), name);

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtIdentityProvider.Name), name)
            .FieldEquals(nameof(RtIdentityProvider.IsEnabled), true);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.SingleOrDefault();
    }

    public async Task<RtIdentityProvider?> GetByIdAsync(OctoObjectId rtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await TenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(session, rtId);

        await session.CommitTransactionAsync();
        return result;
    }


    public async Task<IEnumerable<RtIdentityProvider>> GetAllAsync()
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task StoreAsync(RtIdentityProvider identityProvider)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await TenantRepository.GetRtEntityByRtIdAsync<RtIdentityProvider>(session, identityProvider.RtId);
        if (result == null)
        {
            await TenantRepository.InsertOneRtEntityAsync(session, identityProvider);
        }
        else
        {
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, identityProvider.RtId, identityProvider);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAsync(OctoObjectId rtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtIdentityProvider>(session, rtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }
}