using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     CRUD + query store for OAuth resources (API resources, API scopes, identity resources)
///     over the per-tenant CK entities. Management-plane only since AB#4989/AB#4996 — protocol
///     reads go through <see cref="OpenIddict.OpenIddictScopeStore" />.
/// </summary>
public interface IOctoResourceStore
{
    public string TenantId { get; }
    Task CreateApiResourceAsync(RtApiResource apiResource);
    Task CreateIdentityResourceAsync(RtIdentityResource identityResource);
    Task CreateApiScopeAsync(RtApiScope apiScope);
    Task DeleteApiResourceAsync(OctoObjectId resourceId);
    Task DeleteApiScopeAsync(OctoObjectId resourceId);

    Task<RtApiResource?> GetApiResourceByNameAsync(string apiResourceName);
    Task<RtIdentityResource?> GetIdentityResourceByNameAsync(string identityResourceName);
    Task<RtApiScope?> GetApiScopeByNameAsync(string apiScopeName);
    Task UpdateApiScopeAsync(string name, RtApiScope newApiScope);
    Task UpdateApiResourceAsync(string apiResourceName, RtApiResource newApiResource);

    Task<IEnumerable<RtApiScope>> FindRtApiScopesByNameAsync(IEnumerable<string> scopeNames);
    Task<IEnumerable<RtApiResource>> FindRtApiResourcesByNameAsync(IEnumerable<string> apiResourceNames);

    /// <summary>All enabled-or-not API resources carrying at least one of the scopes (audience resolution).</summary>
    Task<IEnumerable<RtApiResource>> FindRtApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames);

    /// <summary>All resources of the tenant (management/list views).</summary>
    Task<(IReadOnlyList<RtIdentityResource> IdentityResources, IReadOnlyList<RtApiResource> ApiResources,
        IReadOnlyList<RtApiScope> ApiScopes)> GetAllRtResourcesAsync();
}
