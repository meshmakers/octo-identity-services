using Microsoft.AspNetCore.Authentication;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Creates a Authentication scheme and the required options based on the <see cref="TAuthProvider" /> type.
/// </summary>
/// <typeparam name="TAuthProvider"></typeparam>
public interface IAuthSchemeCreator<in TAuthProvider> where TAuthProvider : RtIdentityProvider
{
    /// <summary>
    ///     Create the AuthenticationScheme and configure the options required for the handler.
    /// </summary>
    /// <param name="identityProvider">The identity provider configuration.</param>
    /// <param name="schemeNameOverride">
    ///     Optional override for the scheme name. When provided, the scheme is registered under this name
    ///     (e.g. a tenant-prefixed name) instead of the provider's <see cref="RtIdentityProvider.Name" />.
    /// </param>
    /// <returns></returns>
    public AuthenticationScheme Create(TAuthProvider identityProvider, string? schemeNameOverride = null);
}