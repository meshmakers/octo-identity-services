using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

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

    public AuthenticationScheme Create(RtMicrosoftIdentityProvider identityProvider)
    {
        var options = _micAuthOptions.CreateOptions(identityProvider.Name);
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(identityProvider.Name, displayName,
            typeof(MicrosoftAccountHandler));
    }
}