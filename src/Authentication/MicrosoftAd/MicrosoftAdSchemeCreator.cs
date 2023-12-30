using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Authentication;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.Authentication.MicrosoftAd;

public class MicrosoftAdSchemeCreator : IAuthSchemeCreator<RtMicrosoftAdIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<LdapOptions> _optionsBuilder;

    public MicrosoftAdSchemeCreator(IDynamicAuthOptionsBuilder<LdapOptions> optionsBuilder)
    {
        _optionsBuilder = optionsBuilder;
    }

    public AuthenticationScheme Create(RtMicrosoftAdIdentityProvider identityProvider)
    {
        var options = _optionsBuilder.CreateOptions(identityProvider.Name);
        options.Host = identityProvider.HostAddress;
        options.Port = identityProvider.HostPort;
        options.UseTls = identityProvider.UseTls;
        options.Name = identityProvider.Name;

        return new AuthenticationScheme(identityProvider.Name, identityProvider.DisplayName, typeof(MicrosoftAdAuthenticationHandler));
    }
}