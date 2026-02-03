using System.Text.Encodings.Web;
using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.Authentication.OpenLdap;

public class OpenLdapAuthenticationHandler : AuthenticationHandler<LdapOptions>
{
    private readonly ILdapConnectionFactory _ldapConnectionFactory;

    public OpenLdapAuthenticationHandler(IOptionsMonitor<LdapOptions> options, ILoggerFactory logger, UrlEncoder encoder,
        ILdapConnectionFactory ldapConnectionFactory) : base(options, logger, encoder)
    {
        _ldapConnectionFactory = ldapConnectionFactory;
    }


    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Context.Request.Form.TryGetValue("Username", out var username) ||
            !Context.Request.Form.TryGetValue("Password", out var password))
        {
            return AuthenticateResult.Fail("Username or password missing");
        }

        try
        {
            var authentication = new OpenLdapAuthentication(_ldapConnectionFactory, Options);
            var info = await authentication.AuthenticateAsync(username!, password!);
            return AuthenticateResult.Success(new AuthenticationTicket(info.Principal, Options.Name));
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Authentication at external provider failed");

            //Username / Password wrong
            return AuthenticateResult.Fail("Username or password is wrong.");
        }
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // Redirect to SPA LDAP login page
        var queryParams = new Dictionary<string, string?>
        {
            ["scheme"] = Options.Name,
            ["name"] = Options.Name,
            ["returnUrl"] = properties.RedirectUri
        };
        var url = QueryHelpers.AddQueryString("/System/ldap-login", queryParams);
        Context.Response.Redirect(url);
        return Task.CompletedTask;
    }
}