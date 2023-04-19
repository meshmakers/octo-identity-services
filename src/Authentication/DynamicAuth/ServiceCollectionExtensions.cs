using Meshmakers.Octo.Backend.Authentication.DynamicAuth;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    ///     Add DynamicAuthentication to the Service Collection.
    /// </summary>
    public static IDynamicAuthBuilder AddDynamicAuthentication(this IServiceCollection services)
    {
        return new DynamicAuthBuilder(services);
    }
}
