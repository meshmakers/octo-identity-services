using Duende.IdentityServer.Stores;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public interface IOctoPersistentGrantStore : IPersistedGrantStore
{
    /// <summary>
    ///     Method to clear expired persisted grants.
    /// </summary>
    /// <returns></returns>
    public Task RemoveExpiredGrantsAsync();

    /// <summary>
    ///     Stores the grant.
    /// </summary>
    /// <param name="grant">The grant.</param>
    /// <returns></returns>
    Task StoreAsync(RtPersistedGrant grant);
}