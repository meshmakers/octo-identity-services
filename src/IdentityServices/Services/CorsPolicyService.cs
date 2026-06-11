using Duende.IdentityServer.Services;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Duende IdentityServer CORS policy service that delegates to <see cref="IdentityCorsPolicyProvider"/>
///     to check allowed origins across all tenants.
/// </summary>
public class CorsPolicyService(IdentityCorsPolicyProvider corsPolicyProvider) : ICorsPolicyService
{
    public Task<bool> IsOriginAllowedAsync(string origin, CancellationToken cancellationToken = default)
    {
        return corsPolicyProvider.IsOriginAllowedAsync(origin);
    }
}
