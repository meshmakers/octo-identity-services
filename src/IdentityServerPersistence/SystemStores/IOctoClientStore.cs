using Duende.IdentityServer.Stores;
using Meshmakers.Octo.Services.Common.Cors;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public interface IOctoClientStore : IClientStore, IKnownOriginsProvider
{
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