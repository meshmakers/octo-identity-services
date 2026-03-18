using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.Microsoft;

internal class MicrosoftAuthSchemeCreator : IAuthSchemeCreator<RtMicrosoftIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<MicrosoftAccountOptions> _micAuthOptions;

    /// <summary>
    ///     c'tor
    /// </summary>
    /// <param name="micAuthOptions">Authentication builder for Microsoft</param>
    public MicrosoftAuthSchemeCreator(IDynamicAuthOptionsBuilder<MicrosoftAccountOptions> micAuthOptions)
    {
        _micAuthOptions = micAuthOptions;
    }

    public AuthenticationScheme Create(RtMicrosoftIdentityProvider identityProvider, string? schemeNameOverride = null)
    {
        var schemeName = schemeNameOverride ?? identityProvider.Name;
        var options = _micAuthOptions.CreateOptions(schemeName);
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;
        // Sign in to IdentityServer's external cookie scheme so ExternalLoginCallback can read it
        options.SignInScheme = AuthenticationConstants.IdentityServerConstants.ExternalCookieAuthenticationScheme;

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(schemeName, displayName,
            typeof(MicrosoftAccountHandler));
    }
}