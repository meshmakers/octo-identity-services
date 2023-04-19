using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.Authentication.Options;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Authentication;

namespace Meshmakers.Octo.Backend.Authentication.OpenLdap;

public class OpenLdapSchemeCreator : IAuthSchemeCreator<OpenLdapIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<LdapOptions> _optionsBuilder;

    public OpenLdapSchemeCreator(IDynamicAuthOptionsBuilder<LdapOptions> optionsBuilder)
    {
        _optionsBuilder = optionsBuilder;
    }

    public AuthenticationScheme Create(OpenLdapIdentityProvider identityProvider)
    {
        var options = _optionsBuilder.CreateOptions(identityProvider.Alias);
        options.Host = identityProvider.Host;
        options.Port = identityProvider.Port;
        options.UseTls = identityProvider.ApplyTlsEncryption;
        options.Name = identityProvider.Alias;
        options.UserBaseDn = identityProvider.UserBaseDn;
        options.UserNameAttribute = identityProvider.UserNameAttribute;

        return new AuthenticationScheme(identityProvider.Alias, identityProvider.Alias, typeof(OpenLdapAuthenticationHandler));
    }
}