using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

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

    /// <summary>
    ///     Changes the stored API resource as one version-checked read-modify-write (AB#7989), see
    ///     <see cref="IOctoClientStore.MutateAsync" />. The only way to change a stored API resource (AB#8015): there is
    ///     no unversioned replace that could write a secret list back that a concurrent request removed.
    /// </summary>
    /// <returns>The API resource as stored; <c>null</c> when it does not exist.</returns>
    Task<RtApiResource?> MutateApiResourceAsync(string apiResourceName, Func<RtApiResource, bool> mutate);

    /// <summary>The API scope with this rtId; <c>null</c> when it does not exist (the target of the API scope methods).</summary>
    Task<RtApiScope?> GetApiScopeByIdAsync(OctoObjectId rtId);

    /// <summary>Replaces the stored API scope with the rtId of <paramref name="apiScope" /> (as <see cref="UpdateApiScopeAsync" />).</summary>
    Task ReplaceApiScopeAsync(RtApiScope apiScope);

    /// <summary>The API resource with this rtId; <c>null</c> when it does not exist (the target of the API resource methods).</summary>
    Task<RtApiResource?> GetApiResourceByIdAsync(OctoObjectId rtId);

    /// <summary>
    ///     <see cref="MutateApiResourceAsync" /> for the API resource with this rtId: one version-checked read-modify-write.
    /// </summary>
    /// <returns>The API resource as stored; <c>null</c> when it does not exist.</returns>
    Task<RtApiResource?> MutateApiResourceByIdAsync(OctoObjectId rtId, Func<RtApiResource, bool> mutate);

    Task<IEnumerable<RtApiScope>> FindRtApiScopesByNameAsync(IEnumerable<string> scopeNames);
    Task<IEnumerable<RtApiResource>> FindRtApiResourcesByNameAsync(IEnumerable<string> apiResourceNames);

    /// <summary>All enabled-or-not API resources carrying at least one of the scopes (audience resolution).</summary>
    Task<IEnumerable<RtApiResource>> FindRtApiResourcesByScopeNameAsync(IEnumerable<string> scopeNames);

    /// <summary>All resources of the tenant (management/list views).</summary>
    Task<(IReadOnlyList<RtIdentityResource> IdentityResources, IReadOnlyList<RtApiResource> ApiResources,
        IReadOnlyList<RtApiScope> ApiScopes)> GetAllRtResourcesAsync();
}
