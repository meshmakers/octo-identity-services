using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     CRUD + query store for OAuth clients over the per-tenant <see cref="RtClient" /> CK
///     entities, including the client-mirror upkeep hooks. Duende-free since AB#4989/AB#4996 —
///     protocol reads go through <see cref="OpenIddict.OpenIddictApplicationStore" />.
/// </summary>
public interface IOctoClientStore
{
    public string TenantId { get; }

    Task<IEnumerable<RtClient>> GetClients();

    Task CreateAsync(RtClient client);

    Task UpdateAsync(string clientId, RtClient client);

    Task DeleteAsync(string clientId);

    /// <summary>
    ///     Finds a client by id
    /// </summary>
    /// <param name="clientId">The client id</param>
    /// <returns>The client</returns>
    Task<RtClient?> FindRtClientByIdAsync(string clientId);
}
