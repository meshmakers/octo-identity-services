using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;

namespace Meshmakers.Octo.Backend.Authentication.Google;

internal class GoogleAuthSchemeCreator : IAuthSchemeCreator<GoogleIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<GoogleOptions> _googleAuthOptionsBuilder;

    /// <summary>
    ///     c'tor
    /// </summary>
    /// <param name="googleAuthOptionsBuilder">Authentication builder for Google</param>
    public GoogleAuthSchemeCreator(IDynamicAuthOptionsBuilder<GoogleOptions> googleAuthOptionsBuilder)
    {
        _googleAuthOptionsBuilder = googleAuthOptionsBuilder;
    }


    public AuthenticationScheme Create(GoogleIdentityProvider identityProvider)
    {
        var options = _googleAuthOptionsBuilder.CreateOptions(identityProvider.Alias);
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;

        return new AuthenticationScheme(identityProvider.Alias, identityProvider.Alias, typeof(GoogleHandler));
    }
}
