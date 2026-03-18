using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.Google;

internal class GoogleAuthSchemeCreator : IAuthSchemeCreator<RtGoogleIdentityProvider>
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


    public AuthenticationScheme Create(RtGoogleIdentityProvider identityProvider, string? schemeNameOverride = null)
    {
        var schemeName = schemeNameOverride ?? identityProvider.Name;
        var options = _googleAuthOptionsBuilder.CreateOptions(schemeName);
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;
        // Sign in to IdentityServer's external cookie scheme so ExternalLoginCallback can read it
        options.SignInScheme = AuthenticationConstants.IdentityServerConstants.ExternalCookieAuthenticationScheme;

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(schemeName, displayName, typeof(GoogleHandler));
    }
}