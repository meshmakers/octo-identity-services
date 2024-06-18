using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public interface IOctoIdentityProviderStore
{
    public string TenantId { get; }
    
    Task<RtIdentityProvider?> GetByNameAsync(string name);

    Task<IEnumerable<RtIdentityProvider>> GetAllAsync();

    Task StoreAsync(RtIdentityProvider identityProvider);
    Task RemoveAsync(OctoObjectId rtId);
    Task<RtIdentityProvider?> GetByIdAsync(OctoObjectId rtId);
}