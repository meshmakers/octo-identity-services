using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class ResourceStore(IMultiTenancyResolverService multiTenancyResolverService)
    : IOctoResourceStore
{
    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public string TenantId => TenantRepository.TenantId;

    public async Task CreateApiResourceAsync(RtApiResource apiResource)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.InsertOneRtEntityAsync(session, apiResource);

        await session.CommitTransactionAsync();
    }

    public async Task CreateIdentityResourceAsync(RtIdentityResource identityResource)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.InsertOneRtEntityAsync(session, identityResource);

        await session.CommitTransactionAsync();
    }

    public async Task CreateApiScopeAsync(RtApiScope apiScope)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.InsertOneRtEntityAsync(session, apiScope);

        await session.CommitTransactionAsync();
    }


    public async Task DeleteApiResourceAsync(OctoObjectId resourceId)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtApiResource>(session, resourceId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task DeleteApiScopeAsync(OctoObjectId resourceId)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtApiScope>(session, resourceId, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task<RtApiResource?> GetApiResourceByNameAsync(string apiResourceName)
    {
        ArgumentValidation.ValidateString(nameof(apiResourceName), apiResourceName);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiResource.Name), FieldFilterOperator.Equals, apiResourceName);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, queryOptions);

        await session.CommitTransactionAsync();

        return result.Items.FirstOrDefault();
    }

    public async Task<RtIdentityResource?> GetIdentityResourceByNameAsync(string identityResourceName)
    {
        ArgumentValidation.ValidateString(nameof(identityResourceName), identityResourceName);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtIdentityResource.Name), FieldFilterOperator.Equals, identityResourceName);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtIdentityResource>(session, queryOptions);

        await session.CommitTransactionAsync();

        return result.Items.FirstOrDefault();
    }

    public async Task<RtApiScope?> GetApiScopeByNameAsync(string apiScopeName)
    {
        ArgumentValidation.ValidateString(nameof(apiScopeName), apiScopeName);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, apiScopeName);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, queryOptions);

        await session.CommitTransactionAsync();

        return result.Items.FirstOrDefault();
    }

    public async Task UpdateApiScopeAsync(string name, RtApiScope newApiScope)
    {
        ArgumentValidation.ValidateString(nameof(name), name);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var apiScope = (await FindRtApiScopesByNameAsync(new[] { name })).FirstOrDefault();
        if (apiScope == null)
        {
            throw new NotExistingException($"API scope with name '{name}' does not exist.");
        }

        await TenantRepository.ReplaceOneRtEntityByIdAsync(session, apiScope.RtId, newApiScope);

        await session.CommitTransactionAsync();
    }

    public async Task UpdateApiResourceAsync(string apiResourceName, RtApiResource newApiResource)
    {
        ArgumentValidation.ValidateString(nameof(apiResourceName), apiResourceName);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var apiResource = (await FindRtApiResourcesByNameAsync(new[] { apiResourceName })).FirstOrDefault();
        if (apiResource == null)
        {
            throw new NotExistingException($"API resource with name '{apiResourceName}' does not exist.");
        }

        await TenantRepository.ReplaceOneRtEntityByIdAsync(session, apiResource.RtId, newApiResource);

        await session.CommitTransactionAsync();
    }

    public async Task<IEnumerable<RtApiResource>> FindRtApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiResource.Scopes), FieldFilterOperator.In, scopeNames);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, queryOptions);

        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task<(IReadOnlyList<RtIdentityResource> IdentityResources, IReadOnlyList<RtApiResource> ApiResources,
        IReadOnlyList<RtApiScope> ApiScopes)> GetAllRtResourcesAsync()
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var queryOptions = RtEntityQueryOptions.Create();
        var identityResources = await TenantRepository.GetRtEntitiesByTypeAsync<RtIdentityResource>(session, queryOptions);
        var apiResources = await TenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, queryOptions);
        var apiScopes = await TenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, queryOptions);

        await session.CommitTransactionAsync();

        return (identityResources.Items.ToList(), apiResources.Items.ToList(), apiScopes.Items.ToList());
    }

    public async Task<IEnumerable<RtApiScope>> FindRtApiScopesByNameAsync(IEnumerable<string> scopeNames)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.In, scopeNames);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, queryOptions);

        await session.CommitTransactionAsync();

        return result.Items;
    }

    public async Task<IEnumerable<RtApiResource>> FindRtApiResourcesByNameAsync(IEnumerable<string> apiResourceNames)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiResource.Name), FieldFilterOperator.In, apiResourceNames);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, queryOptions);

        await session.CommitTransactionAsync();

        return result.Items;
    }
}