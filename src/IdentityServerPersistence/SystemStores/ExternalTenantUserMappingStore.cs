using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class ExternalTenantUserMappingStore(
    IMultiTenancyResolverService multiTenancyResolverService) : IExternalTenantUserMappingStore
{
    private readonly ITenantRepository _tenantRepository = multiTenancyResolverService.GetTenantRepository();

    public async Task<RtExternalTenantUserMapping?> FindBySourceUserAsync(
        string sourceTenantId, string sourceUserId)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId)
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), sourceUserId);

        var result = await _tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items.SingleOrDefault();
    }

    public async Task<IEnumerable<RtExternalTenantUserMapping>> GetAllAsync(
        int? skip = null, int? take = null)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();
        var result = await _tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions, skip, take);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task<IEnumerable<RtExternalTenantUserMapping>> GetBySourceTenantAsync(
        string sourceTenantId)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId);

        var result = await _tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task StoreAsync(RtExternalTenantUserMapping mapping)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existing = await _tenantRepository
            .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mapping.RtId);
        if (existing == null)
        {
            await _tenantRepository.InsertOneRtEntityAsync(session, mapping);
        }
        else
        {
            await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, mapping.RtId, mapping);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAsync(OctoObjectId rtId)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        await _tenantRepository
            .DeleteOneRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, rtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task<RtExternalTenantUserMapping?> GetByIdAsync(OctoObjectId rtId)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await _tenantRepository
            .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, rtId);
        await session.CommitTransactionAsync();

        return result;
    }
}
