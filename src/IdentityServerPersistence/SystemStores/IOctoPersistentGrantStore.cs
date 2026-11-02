using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Store for legacy persisted grants (<see cref="RtPersistedGrant" />). Since the OpenIddict
///     migration (AB#4989/AB#4996) only the Rt-level surface remains: the email/password-reset
///     token audit trail keeps writing here, and the cleanup service sweeps expired records.
///     OAuth protocol grants live in the OpenIddict authorization/token stores.
/// </summary>
public interface IOctoPersistentGrantStore
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
