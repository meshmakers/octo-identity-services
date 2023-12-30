using AutoMapper;
using Duende.IdentityServer.Models;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.Infrastructure.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repository;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public class ResourceStore : IOctoResourceStore
{
    private readonly IMapper _mapper;
    private readonly ITenantRepository _tenantRepository;

    public ResourceStore(IMultiTenancyResolverService multiTenancyResolverService, IMapper mapper)
    {
        _tenantRepository = multiTenancyResolverService.GetTenantRepository();
        _mapper = mapper;
    }

    public async Task CreateApiResourceAsync(RtApiResource apiResource)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            await _tenantRepository.InsertOneRtEntityAsync(session, apiResource);

            await session.CommitTransactionAsync();
        }
    }

    public async Task CreateIdentityResourceAsync(RtIdentityResource identityResource)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            await _tenantRepository.InsertOneRtEntityAsync(session, identityResource);

            await session.CommitTransactionAsync();
        }
    }

    public async Task CreateApiScopeAsync(RtApiScope apiScope)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            await _tenantRepository.InsertOneRtEntityAsync(session, apiScope);

            await session.CommitTransactionAsync();
        }
    }

    public async Task<RtApiResource> GetOrCreateApiResourceAsync(RtApiResource apiResource)
    {
        var rtApiResource = await GetApiResourceByNameAsync(apiResource.Name);
        if (rtApiResource == null)
        {
            rtApiResource = _mapper.Map<RtApiResource>(apiResource);

            await CreateApiResourceAsync(rtApiResource);
        }

        return rtApiResource;
    }


    public async Task<RtIdentityResource> GetOrCreateIdentityResourceAsync(IdentityResource identityResource)
    {
        var rtIdentityResource = await GetIdentityResourceByNameAsync(identityResource.Name);
        if (rtIdentityResource == null)
        {
            rtIdentityResource = _mapper.Map<RtIdentityResource>(identityResource);

            await CreateIdentityResourceAsync(rtIdentityResource);
        }

        return rtIdentityResource;
    }

    public async Task<RtApiScope> TryCreateApiScopeAsync(ApiScope apiScope)
    {
        var res = (await FindRtApiScopesByNameAsync(new[] { apiScope.Name })).ToArray();
        if (!res.Any())
        {
            var dbApiScope = _mapper.Map<RtApiScope>(apiScope);
            await CreateApiScopeAsync(dbApiScope);

            return dbApiScope;
        }

        return res.First();
    }


    public async Task DeleteApiResourceAsync(OctoObjectId resourceId)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtApiResource>(session, resourceId);

            await session.CommitTransactionAsync();
        }
    }

    public async Task DeleteIdentityResourceAsync(OctoObjectId resourceId)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtIdentityResource>(session, resourceId);

            await session.CommitTransactionAsync();
        }
    }

    public async Task DeleteApiScopeAsync(OctoObjectId resourceId)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtApiScope>(session, resourceId);

            await session.CommitTransactionAsync();
        }
    }

    public async Task<RtApiResource?> GetApiResourceByNameAsync(string apiResourceName)
    {
        ArgumentValidation.ValidateString(nameof(apiResourceName), apiResourceName);

        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var dataQueryOperation = DataQueryOperation.Create()
                .FieldFilter(nameof(RtApiResource.Name), FieldFilterOperator.Equals, apiResourceName);

            var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return result.Items.FirstOrDefault();
        }
    }

    public async Task<RtIdentityResource?> GetIdentityResourceByNameAsync(string identityResourceName)
    {
        ArgumentValidation.ValidateString(nameof(identityResourceName), identityResourceName);

        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var dataQueryOperation = DataQueryOperation.Create()
                .FieldFilter(nameof(RtIdentityResource.Name), FieldFilterOperator.Equals, identityResourceName);

            var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtIdentityResource>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return result.Items.FirstOrDefault();
        }
    }

    public async Task<RtApiScope?> GetApiScopeByNameAsync(string apiScopeName)
    {
        ArgumentValidation.ValidateString(nameof(apiScopeName), apiScopeName);

        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var dataQueryOperation = DataQueryOperation.Create()
                .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, apiScopeName);

            var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return result.Items.FirstOrDefault();
        }
    }

    public async Task UpdateApiScopeAsync(string name, RtApiScope newApiScope)
    {
        ArgumentValidation.ValidateString(nameof(name), name);

        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var apiScope = (await FindRtApiScopesByNameAsync(new[] { name })).FirstOrDefault();
            if (apiScope == null) throw new NotExistingException($"API scope with name '{name}' does not exist.");

            await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, apiScope.RtId, newApiScope);

            await session.CommitTransactionAsync();
        }
    }

    public async Task UpdateApiResourceAsync(string apiResourceName, RtApiResource newApiResource)
    {
        ArgumentValidation.ValidateString(nameof(apiResourceName), apiResourceName);

        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var apiResource = (await FindRtApiResourcesByNameAsync(new[] { apiResourceName })).FirstOrDefault();
            if (apiResource == null) throw new NotExistingException($"API resource with name '{apiResourceName}' does not exist.");

            await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, apiResource.RtId, newApiResource);

            await session.CommitTransactionAsync();
        }
    }

    public async Task<IEnumerable<IdentityResource>> FindIdentityResourcesByScopeNameAsync(
        IEnumerable<string> scopeNames)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var dataQueryOperation = DataQueryOperation.Create()
                .FieldFilter(nameof(RtIdentityResource.Name), FieldFilterOperator.In, scopeNames);

            var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtIdentityResource>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return result.Items.Select(_mapper.Map<IdentityResource>);
        }
    }

    public async Task<IEnumerable<ApiScope>> FindApiScopesByNameAsync(IEnumerable<string> scopeNames)
    {
        var result = await FindRtApiScopesByNameAsync(scopeNames);

        return result.Select(_mapper.Map<ApiScope>);
    }

    public async Task<IEnumerable<ApiResource>> FindApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var dataQueryOperation = DataQueryOperation.Create()
                .FieldFilter(nameof(RtApiResource.Scopes), FieldFilterOperator.In, scopeNames);

            var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return result.Items.Select(_mapper.Map<ApiResource>);
        }
    }

    public async Task<IEnumerable<ApiResource>> FindApiResourcesByNameAsync(IEnumerable<string> apiResourceNames)
    {
        var result = await FindRtApiResourcesByNameAsync(apiResourceNames);

        return result.Select(_mapper.Map<ApiResource>);
    }

    public async Task<Resources> GetAllResourcesAsync()
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();
            DataQueryOperation dataQueryOperation = DataQueryOperation.Create();
            var identityResources = await _tenantRepository.GetRtEntitiesByTypeAsync<RtIdentityResource>(session, dataQueryOperation);
            var apiResources = await _tenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, dataQueryOperation);
            var apiScopes = await _tenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return new Resources(identityResources.Items.Select(_mapper.Map<IdentityResource>),
                apiResources.Items.Select(_mapper.Map<ApiResource>),
                apiScopes.Items.Select(_mapper.Map<ApiScope>));
        }
    }

    public async Task<IEnumerable<RtApiScope>> FindRtApiScopesByNameAsync(IEnumerable<string> scopeNames)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var dataQueryOperation = DataQueryOperation.Create()
                .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.In, scopeNames);

            var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtApiScope>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return result.Items;
        }
    }

    public async Task<IEnumerable<RtApiResource>> FindRtApiResourcesByNameAsync(IEnumerable<string> apiResourceNames)
    {
        using (var session = await _tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();

            var dataQueryOperation = DataQueryOperation.Create()
                .FieldFilter(nameof(RtApiResource.Name), FieldFilterOperator.In, apiResourceNames);

            var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtApiResource>(session, dataQueryOperation);

            await session.CommitTransactionAsync();

            return result.Items;
        }
    }
}