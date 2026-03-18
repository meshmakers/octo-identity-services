using System.Collections.Concurrent;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Cors.Infrastructure;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     CORS policy provider for the Identity Service API endpoints.
///     Reads allowed origins from the client store (AllowedCorsOrigins).
/// </summary>
public class IdentityCorsPolicyProvider : ICorsPolicyProvider
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<IdentityCorsPolicyProvider> _logger;
    private CorsPolicy? _cachedPolicy;

    public IdentityCorsPolicyProvider(IServiceProvider serviceProvider, ILogger<IdentityCorsPolicyProvider> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
    {
        if (_cachedPolicy != null)
        {
            return _cachedPolicy;
        }

        using var scope = _serviceProvider.CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
        var clients = await clientStore.GetClients();
        var origins = clients.SelectMany(c => c.AllowedCorsOrigins).Distinct().ToArray();

        _logger.LogInformation("Creating CORS policy for Identity API from client origins: {Origins}",
            string.Join(", ", origins));

        var policyBuilder = new CorsPolicyBuilder();
        if (origins.Length > 0)
        {
            policyBuilder.WithOrigins(origins);
        }

        policyBuilder.AllowAnyHeader()
            .AllowAnyMethod();
        _cachedPolicy = policyBuilder.Build();

        return _cachedPolicy;
    }

    /// <summary>
    ///     Invalidates the cached CORS policy so it will be rebuilt on next request.
    /// </summary>
    public void InvalidateCache()
    {
        _logger.LogInformation("Invalidating Identity CORS policy cache");
        _cachedPolicy = null;
    }
}
