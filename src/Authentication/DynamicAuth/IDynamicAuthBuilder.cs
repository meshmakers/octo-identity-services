using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.Authentication.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Builder for the Dynamic authentication.
/// </summary>
public interface IDynamicAuthBuilder
{
    public IServiceCollection Services { get; }
}

/// <inheritdoc />
public class DynamicAuthBuilder : IDynamicAuthBuilder
{
    internal DynamicAuthBuilder(IServiceCollection serviceCollection)
    {
        Services = serviceCollection ?? throw new ArgumentNullException(nameof(serviceCollection));
        AddCommonRequirements();
    }

    public IServiceCollection Services { get; }

    private void AddCommonRequirements()
    {
        Services.TryAddScoped<IDynamicAuthSchemeService, DynamicAuthSchemeService>();
        Services.TryAddScoped<IAuthSchemeCreatorFactory, AuthSchemeCreatorFactory>();
        Services.TryAddScoped<ILdapAuthenticationService, LdapAuthenticationService>();
        Services.AddInitializationService<DynamicAuthSchemeServiceInitializer>();
        // AB#5540: catch up the schemes of tenants the initializer had to skip, once their setup completes.
        Services.TryAddEnumerable(
            ServiceDescriptor.Scoped<ITenantSetupCompletedHandler, DynamicAuthSchemeTenantSetupHandler>());
    }
}