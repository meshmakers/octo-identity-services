using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public interface IOctoResourceStore : IResourceStore
{
    public string TenantId { get; }
    Task CreateApiResourceAsync(RtApiResource apiResource);
    Task CreateIdentityResourceAsync(RtIdentityResource identityResource);
    Task CreateApiScopeAsync(RtApiScope apiScope);
    Task<RtIdentityResource> GetOrCreateIdentityResourceAsync(IdentityResource identityResource);
    Task<RtApiScope> TryCreateApiScopeAsync(ApiScope apiScope);
    Task<RtApiResource> GetOrCreateApiResourceAsync(RtApiResource apiResource);
    Task DeleteApiResourceAsync(OctoObjectId resourceId);
    Task DeleteIdentityResourceAsync(OctoObjectId resourceId);
    Task DeleteApiScopeAsync(OctoObjectId resourceId);

    Task<RtApiResource?> GetApiResourceByNameAsync(string apiResourceName);
    Task<RtIdentityResource?> GetIdentityResourceByNameAsync(string identityResourceName);
    Task<RtApiScope?> GetApiScopeByNameAsync(string apiScopeName);
    Task UpdateApiScopeAsync(string name, RtApiScope newApiScope);
    Task UpdateApiResourceAsync(string apiResourceName, RtApiResource newApiResource);
}