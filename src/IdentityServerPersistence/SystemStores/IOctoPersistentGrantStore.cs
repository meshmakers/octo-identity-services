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

    /// <summary>
    ///     Retrieves the tenant ID stored in the Description field of a persisted grant.
    ///     Used by the OIDC tenant resolution middleware to recover token-to-tenant mappings
    ///     after a service restart.
    /// </summary>
    /// <param name="grantKey">The SHA256 hash of the token (grant key).</param>
    /// <returns>The tenant ID, or null if the grant was not found or has no tenant.</returns>
    Task<string?> GetTenantByGrantKeyAsync(string grantKey);
}