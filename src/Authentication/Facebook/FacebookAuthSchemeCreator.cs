using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.Authentication.Secrets;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.Facebook;

internal class FacebookAuthSchemeCreator : IAuthSchemeCreator<RtFacebookIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<FacebookOptions> _facebookAuthOptionsBuilder;
    private readonly IIdentityProviderSecretReader _secretReader;

    /// <summary>
    ///     c'tor
    /// </summary>
    /// <param name="facebookAuthOptionsBuilder">Authentication builder for Facebook</param>
    /// <param name="secretReader">Reads the counted plaintext of the provider's client secret (AB#5540)</param>
    public FacebookAuthSchemeCreator(IDynamicAuthOptionsBuilder<FacebookOptions> facebookAuthOptionsBuilder,
        IIdentityProviderSecretReader secretReader)
    {
        _secretReader = secretReader;
        _facebookAuthOptionsBuilder = facebookAuthOptionsBuilder;
    }


    public AuthenticationScheme Create(RtFacebookIdentityProvider identityProvider, string? schemeNameOverride = null,
        string? tenantId = null)
    {
        var schemeName = schemeNameOverride ?? identityProvider.Name;
        var options = _facebookAuthOptionsBuilder.CreateOptions(schemeName);
        options.ClientId = identityProvider.ClientId;
        // Secret value type (AB#5540): decrypted on demand, counted, never logged.
        options.ClientSecret = _secretReader.GetClientSecret(identityProvider, tenantId) ?? string.Empty;
        // Sign in to our external cookie scheme (OctoAuthSchemes.ExternalCookieScheme) so ExternalLoginCallback can read it
        options.SignInScheme = OctoAuthSchemes.ExternalCookieScheme;
        // Route remote-login failures (wrong secret, user cancelled) to the SPA error page.
        options.Events.OnRemoteFailure = ExternalAuthFailureHandler.HandleRemoteFailureAsync;

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(schemeName, displayName, typeof(FacebookHandler));
    }
}