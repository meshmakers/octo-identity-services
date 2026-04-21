using System.Text.Encodings.Web;
using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.Authentication.MicrosoftAd;

public class MicrosoftAdAuthenticationHandler : AuthenticationHandler<LdapOptions>
{
    private readonly ILdapConnectionFactory _ldapConnectionFactory;

    public MicrosoftAdAuthenticationHandler(IOptionsMonitor<LdapOptions> options, ILoggerFactory logger, UrlEncoder encoder,
        ILdapConnectionFactory ldapConnectionFactory) : base(options, logger, encoder)
    {
        _ldapConnectionFactory = ldapConnectionFactory;
    }


    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Context.Request.Form.TryGetValue("Email", out var email) ||
            !Context.Request.Form.TryGetValue("Password", out var password))
        {
            return AuthenticateResult.Fail("Username or password missing");
        }

        try
        {
            var authentication = new MicrosoftAdAuthentication(_ldapConnectionFactory, Options, Logger);
            var info = await authentication.AuthenticateAsync(email!, password!);
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