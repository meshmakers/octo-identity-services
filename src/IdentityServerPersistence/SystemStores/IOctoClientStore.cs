using Duende.IdentityServer.Stores;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public interface IOctoClientStore : IClientStore
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