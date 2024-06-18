using Microsoft.AspNetCore.Authentication;

namespace Meshmakers.Octo.Backend.Authentication.Options;

public class LdapOptions : AuthenticationSchemeOptions
{
    public string Name { get; set; } = null!;
    public string Host { get; set; } = null!;
    public int Port { get; set; }
    public bool UseTls { get; set; }

    public string UserBaseDn { get; set; } = null!;

    public string UserNameAttribute { get; set; } = null!;
}