using System;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.Extensions.DependencyInjection;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <inheritdoc />
/// >
internal class AuthSchemeCreatorFactory : IAuthSchemeCreatorFactory
{
    private readonly IServiceProvider _provider;

    public AuthSchemeCreatorFactory(IServiceProvider provider)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }


    /// <inheritdoc />
    /// >
    public IAuthSchemeCreator<TAuthProvider> GetCreator<TAuthProvider>()
        where TAuthProvider : OctoIdentityProvider
    {
        var requestedType = typeof(IAuthSchemeCreator<>).MakeGenericType(typeof(TAuthProvider));

        return (IAuthSchemeCreator<TAuthProvider>)_provider.GetRequiredService(requestedType);
    }
}
