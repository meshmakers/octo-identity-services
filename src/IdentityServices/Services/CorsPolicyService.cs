using Duende.IdentityServer.Services;
using IdentityServerPersistence.SystemStores;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class CorsPolicyService : ICorsPolicyService
{
    private readonly IOctoClientStore _clientStore;

    public CorsPolicyService(IOctoClientStore clientStore)
    {
        _clientStore = clientStore;
    }


    public async Task<bool> IsOriginAllowedAsync(string origin)
    {
        var clients = await _clientStore.GetClients();
        var result = clients.Any(x => x.AllowedCorsOrigins.Contains(origin));
        return result;
    }
}