using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class EmailDomainGroupRuleStore(IMultiTenancyResolverService multiTenancyResolverService)
    : IEmailDomainGroupRuleStore
{
    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async Task<RtEmailDomainGroupRule?> GetByIdAsync(OctoObjectId rtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await TenantRepository.GetRtEntityByRtIdAsync<RtEmailDomainGroupRule>(session, rtId);

        await session.CommitTransactionAsync();
        return result;
    }

    public async Task<IEnumerable<RtEmailDomainGroupRule>> GetAllAsync()
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtEmailDomainGroupRule>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items;
    }

    public async Task<RtEmailDomainGroupRule?> GetByDomainPatternAsync(string domainPattern)
    {
        ArgumentValidation.ValidateString(nameof(domainPattern), domainPattern);

        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEmailDomainGroupRule.EmailDomainPattern), domainPattern);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtEmailDomainGroupRule>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.SingleOrDefault();
    }

    public async Task StoreAsync(RtEmailDomainGroupRule rule)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existing = await TenantRepository.GetRtEntityByRtIdAsync<RtEmailDomainGroupRule>(session, rule.RtId);
        if (existing == null)
        {
            await TenantRepository.InsertOneRtEntityAsync(session, rule);
        }
        else
        {
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, rule.RtId, rule);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAsync(OctoObjectId rtId)
    {
        var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtEmailDomainGroupRule>(session, rtId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }
}
