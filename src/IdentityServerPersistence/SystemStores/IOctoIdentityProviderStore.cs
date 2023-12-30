using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public interface IOctoIdentityProviderStore
{
    Task<RtIdentityProvider?> GetByNameAsync(string name);

    Task<IEnumerable<RtIdentityProvider>> GetAllAsync();

    Task StoreAsync(RtIdentityProvider identityProvider);
    Task RemoveAsync(string id);
}