using System;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Factory to get authentication <see cref="IAuthSchemeCreator{TAuthProvider}" />
/// </summary>
internal interface IAuthSchemeCreatorFactory
{
    /// <summary>
    ///     Get a scheme provider from the DI container.
    /// </summary>
    /// <typeparam name="TAuthProvider">Type of the <see cref="OctoIdentityProvider" /></typeparam>
    /// <exception cref="InvalidOperationException">Is thrown when the requested creator could not be resolved via DI.</exception>
    IAuthSchemeCreator<TAuthProvider> GetCreator<TAuthProvider>()
        where TAuthProvider : OctoIdentityProvider;
}
