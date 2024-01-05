using System.Security.Claims;
using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Identity;
using Novell.Directory.Ldap;
using LdapConnection = Novell.Directory.Ldap.LdapConnection;

namespace Meshmakers.Octo.Backend.Authentication.OpenLdap;

internal class OpenLdapAuthentication
{
    private const string UserIdAttributeName = "entryUUID";
    private const string UserFullNameAttributeName = "cn";
    private const string MailAttribute = "mail";

    private readonly ILdapConnectionFactory _connectionFactory;
    private readonly LdapOptions _options;

    public OpenLdapAuthentication(ILdapConnectionFactory connectionFactory, LdapOptions options)
    {
        _connectionFactory = connectionFactory;
        _options = options;
    }

    public Task<ExternalLoginInfo> AuthenticateAsync(string username, string password)
    {
        var userDn = $"{_options.UserNameAttribute}={username},{_options.UserBaseDn}";

        using var connection = _connectionFactory.CreateLdapConnection(_options.Host, _options.Port, userDn, password, _options.UseTls,
            ConnectionType.OpenLdap);
        var entry = connection.ExecuteQuery(parameters =>
        {
            parameters.BaseDn = userDn;
            parameters.Scope = LdapConnection.ScopeSub;
            parameters.Attrs = new[] { UserIdAttributeName, UserFullNameAttributeName, MailAttribute };
        }).FirstOrDefault();

        if (entry == null)
        {
            throw new ArgumentException("Could not authenticate user.");
        }

        return Task.FromResult(LdapEntryToUser(entry));
    }

    private ExternalLoginInfo LdapEntryToUser(LdapEntry entry)
    {
        var userId = entry.GetAttribute(UserIdAttributeName)?.StringValue;
        var userName = entry.GetAttribute(UserFullNameAttributeName)?.StringValue;
        var mail = entry.GetAttribute(MailAttribute).StringValue;

        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(userName))
        {
            throw new ArgumentException("Could not authenticate user.");
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userName),
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Email, mail)
        };

        var claimsIdentity = new ClaimsIdentity(claims, _options.Name);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        return new ExternalLoginInfo(claimsPrincipal, _options.Name, userId, userName);
    }
}