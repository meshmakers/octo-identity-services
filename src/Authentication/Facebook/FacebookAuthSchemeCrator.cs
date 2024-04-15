using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.Authentication.Facebook;

internal class FacebookAuthSchemeCreator : IAuthSchemeCreator<RtFacebookIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<FacebookOptions> _facebookAuthOptionsBuilder;

    /// <summary>
    ///     c'tor
    /// </summary>
    /// <param name="facebookAuthOptionsBuilder">Authentication builder for Facebook</param>
    public FacebookAuthSchemeCreator(IDynamicAuthOptionsBuilder<FacebookOptions> facebookAuthOptionsBuilder)
    {
        _facebookAuthOptionsBuilder = facebookAuthOptionsBuilder;
    }


    public AuthenticationScheme Create(RtFacebookIdentityProvider identityProvider)
    {
        var options = _facebookAuthOptionsBuilder.CreateOptions(identityProvider.Name);
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(identityProvider.Name, displayName, typeof(FacebookHandler));
    }
}