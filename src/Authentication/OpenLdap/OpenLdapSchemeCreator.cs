using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Authentication;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.OpenLdap;

public class OpenLdapSchemeCreator : IAuthSchemeCreator<RtOpenLdapIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<LdapOptions> _optionsBuilder;

    public OpenLdapSchemeCreator(IDynamicAuthOptionsBuilder<LdapOptions> optionsBuilder)
    {
        _optionsBuilder = optionsBuilder;
    }

    public AuthenticationScheme Create(RtOpenLdapIdentityProvider identityProvider, string? schemeNameOverride = null)
    {
        var schemeName = schemeNameOverride ?? identityProvider.Name;
        var options = _optionsBuilder.CreateOptions(schemeName);
        options.Host = identityProvider.Host;
        options.Port = identityProvider.Port;
        options.UseTls = identityProvider.UseTls;
        options.Name = identityProvider.Name;
        options.UserBaseDn = identityProvider.UserBaseDn;
        options.UserNameAttribute = identityProvider.UserNameAttribute;

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(schemeName, displayName, typeof(OpenLdapAuthenticationHandler));
    }
}