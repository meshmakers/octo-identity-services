using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.Authentication.Options;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Authentication;

namespace Meshmakers.Octo.Backend.Authentication.MicrosoftAd;

public class MicrosoftAdSchemeCreator : IAuthSchemeCreator<MicrosoftAdIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<LdapOptions> _optionsBuilder;

    public MicrosoftAdSchemeCreator(IDynamicAuthOptionsBuilder<LdapOptions> optionsBuilder)
    {
        _optionsBuilder = optionsBuilder;
    }

    public AuthenticationScheme Create(MicrosoftAdIdentityProvider identityProvider)
    {
        var options = _optionsBuilder.CreateOptions(identityProvider.Alias);
        options.Host = identityProvider.Host;
        options.Port = identityProvider.Port;
        options.UseTls = identityProvider.ApplyTlsEncryption;
        options.Name = identityProvider.Alias;

        return new AuthenticationScheme(identityProvider.Alias, identityProvider.Alias, typeof(MicrosoftAdAuthenticationHandler));
    }
}