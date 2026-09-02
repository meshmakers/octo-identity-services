using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

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


    public AuthenticationScheme Create(RtFacebookIdentityProvider identityProvider, string? schemeNameOverride = null)
    {
        var schemeName = schemeNameOverride ?? identityProvider.Name;
        var options = _facebookAuthOptionsBuilder.CreateOptions(schemeName);
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;
        // Sign in to our external cookie scheme (OctoAuthSchemes.ExternalCookieScheme) so ExternalLoginCallback can read it
        options.SignInScheme = OctoAuthSchemes.ExternalCookieScheme;
        // Route remote-login failures (wrong secret, user cancelled) to the SPA error page.
        options.Events.OnRemoteFailure = ExternalAuthFailureHandler.HandleRemoteFailureAsync;

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(schemeName, displayName, typeof(FacebookHandler));
    }
}