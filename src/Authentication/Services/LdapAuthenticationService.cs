using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.MicrosoftAd;
using Meshmakers.Octo.Backend.Authentication.OpenLdap;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.Authentication.Services;

/// <summary>
/// Service for authenticating users against LDAP providers
/// </summary>
public class LdapAuthenticationService : ILdapAuthenticationService
{
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IOptionsMonitorCache<LdapOptions> _optionsCache;
    private readonly ILdapConnectionFactory _ldapConnectionFactory;
    private readonly ILogger<LdapAuthenticationService> _logger;

    public LdapAuthenticationService(
        IAuthenticationSchemeProvider schemeProvider,
        IOptionsMonitorCache<LdapOptions> optionsCache,
        ILdapConnectionFactory ldapConnectionFactory,
        ILogger<LdapAuthenticationService> logger)
    {
        _schemeProvider = schemeProvider;
        _optionsCache = optionsCache;
        _ldapConnectionFactory = ldapConnectionFactory;
        _logger = logger;
    }

    public async Task<LdapAuthenticationResult> AuthenticateAsync(string scheme, string username, string password)
    {
        // Get the authentication scheme
        var authScheme = await _schemeProvider.GetSchemeAsync(scheme);
        if (authScheme == null)
        {
            _logger.LogWarning("Authentication scheme {Scheme} not found", scheme);
            return LdapAuthenticationResult.Failure("Authentication scheme not found");
        }

        // Verify this is an LDAP-based scheme
        if (!IsLdapHandlerType(authScheme.HandlerType))
        {
            _logger.LogWarning("Scheme {Scheme} is not an LDAP provider (handler: {Handler})",
                scheme, authScheme.HandlerType.Name);
            return LdapAuthenticationResult.Failure("Scheme is not an LDAP provider");
        }

        // Get LDAP options for this scheme
        var options = _optionsCache.GetOrAdd(scheme, () => new LdapOptions());
        if (string.IsNullOrEmpty(options.Host))
        {
            _logger.LogWarning("LDAP options not configured for scheme {Scheme}", scheme);
            return LdapAuthenticationResult.Failure("LDAP provider not properly configured");
        }

        try
        {
            // Authenticate based on handler type
            if (authScheme.HandlerType == typeof(OpenLdapAuthenticationHandler))
            {
                var authentication = new OpenLdapAuthentication(_ldapConnectionFactory, options);
                var loginInfo = await authentication.AuthenticateAsync(username, password);
                _logger.LogInformation("OpenLDAP authentication successful for user {Username} on scheme {Scheme}",
                    username, scheme);
                return LdapAuthenticationResult.Success(loginInfo);
            }
            else if (authScheme.HandlerType == typeof(MicrosoftAdAuthenticationHandler))
            {
                var authentication = new MicrosoftAdAuthentication(_ldapConnectionFactory, options, _logger);
                var loginInfo = await authentication.AuthenticateAsync(username, password);
                _logger.LogInformation("Microsoft AD authentication successful for user {Username} on scheme {Scheme}",
                    username, scheme);
                return LdapAuthenticationResult.Success(loginInfo);
            }

            return LdapAuthenticationResult.Failure("Unknown LDAP handler type");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "LDAP authentication failed for user {Username} on scheme {Scheme}",
                username, scheme);
            return LdapAuthenticationResult.Failure("Invalid username or password");
        }
    }

    public async Task<bool> IsLdapSchemeAsync(string scheme)
    {
        var authScheme = await _schemeProvider.GetSchemeAsync(scheme);
        return authScheme != null && IsLdapHandlerType(authScheme.HandlerType);
    }

    private static bool IsLdapHandlerType(Type handlerType)
    {
        return handlerType == typeof(OpenLdapAuthenticationHandler) ||
               handlerType == typeof(MicrosoftAdAuthenticationHandler);
    }
}
