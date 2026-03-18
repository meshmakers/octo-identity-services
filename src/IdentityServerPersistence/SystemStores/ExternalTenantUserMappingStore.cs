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
    // Resolve lazily to ensure correct tenant context (see GroupStore for explanation)
    private ITenantRepository GetRepository() => multiTenancyResolverService.GetTenantRepository();

    public async Task<RtExternalTenantUserMapping?> FindBySourceUserAsync(
        string sourceTenantId, string sourceUserId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId)
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), sourceUserId);

        var result = await GetRepository()
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items.SingleOrDefault();
    }

    public async Task<IEnumerable<RtExternalTenantUserMapping>> GetAllAsync(
        int? skip = null, int? take = null)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();
        var result = await GetRepository()
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions, skip, take);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task<IEnumerable<RtExternalTenantUserMapping>> GetBySourceTenantAsync(
        string sourceTenantId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId);

        var result = await GetRepository()
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, queryOptions);
        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task StoreAsync(RtExternalTenantUserMapping mapping)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var existing = await GetRepository()
            .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mapping.RtId);
        if (existing == null)
        {
            await GetRepository().InsertOneRtEntityAsync(session, mapping);
        }
        else
        {
            await GetRepository().ReplaceOneRtEntityByIdAsync(session, mapping.RtId, mapping);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAsync(OctoObjectId rtId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        await GetRepository()
            .DeleteOneRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, rtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task<RtExternalTenantUserMapping?> GetByIdAsync(OctoObjectId rtId)
    {
        var session = await GetRepository().GetSessionAsync();
        session.StartTransaction();

        var result = await GetRepository()
            .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, rtId);
        await session.CommitTransactionAsync();

        return result;
    }
}
