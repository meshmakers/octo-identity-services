using Duende.IdentityServer.Services;
using IdentityServerPersistence.SystemStores;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class CorsPolicyService(IOctoClientStore clientStore) : ICorsPolicyService
{
    public async Task<bool> IsOriginAllowedAsync(string origin)
    {
        var clients = await clientStore.GetClients();
        var result = clients.Any(x => x.AllowedCorsOrigins.Contains(origin));
        return result;
    }
}