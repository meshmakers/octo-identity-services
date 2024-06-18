using Microsoft.AspNetCore.Authentication;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

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
    /// <param name="identityProvider"></param>
    /// <returns></returns>
    public AuthenticationScheme Create(TAuthProvider identityProvider);
}