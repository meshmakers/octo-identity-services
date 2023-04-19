using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Identity;
using Novell.Directory.Ldap;

namespace Meshmakers.Octo.Backend.Authentication.MicrosoftAd;

internal class MicrosoftAdAuthentication
{
    private const string UserIdAttributeName = "objectGUID";
    private const string UserFullNameAttributeName = "name";
    private const string GivenNameAttribute = "givenName";
    private const string SurNameAttribute = "sn";
    private const string UserPrincipalNameAttribute = "userPrincipalName";
    private const string MailAttribute = "mail";

    private readonly ILdapConnectionFactory _connectionFactory;
    private readonly LdapOptions _options;

    public MicrosoftAdAuthentication(ILdapConnectionFactory connectionFactory, LdapOptions options)
    {
        _connectionFactory = connectionFactory;
        _options = options;
    }

    public Task<ExternalLoginInfo> AuthenticateAsync(string username, string password)
    {
        using var connection = _connectionFactory.CreateLdapConnection(_options.Host, _options.Port, username, password, _options.UseTls, ConnectionType.MicrosoftActiveDirectory);
        var entry = connection.ExecuteQuery(parameters =>
        {
            parameters.Scope = Novell.Directory.Ldap.LdapConnection.ScopeSub;
            parameters.Filter = $"{UserPrincipalNameAttribute}={username}";
        }).SingleOrDefault();
        
        if (entry == null)
        {
            throw new InvalidOperationException("Could not authenticate user.");
        }
        
        var ldapGroupHandler = new LdapGroupHandler(_options.UserBaseDn, UserPrincipalNameAttribute);
        var groupNames = ldapGroupHandler.GetGroupsForUser(connection, username);

        return Task.FromResult(LdapEntryToUser(entry, groupNames.ToList()));
    }

    private ExternalLoginInfo LdapEntryToUser(LdapEntry entry, List<string> groupNames)
    {
        var userIdBytes = entry.GetAttribute(UserIdAttributeName)?.ByteValue;
        if (userIdBytes == null)
        {
            throw new InvalidOperationException("Could not authenticate user.");
        }

        var userId = new Guid(userIdBytes).ToString();
        var userName = entry.GetAttribute(UserFullNameAttributeName).StringValue;
        var givenName = entry.GetAttribute(GivenNameAttribute).StringValue;
        var sn = entry.GetAttribute(SurNameAttribute).StringValue;
        var mail = entry.GetAttribute(MailAttribute).StringValue;


        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userName),
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.GivenName, givenName),
            new(ClaimTypes.Surname, sn),
            new(ClaimTypes.Email, mail),
        };
        
        foreach (var groupName in groupNames)
        {
            claims.Add(new(JwtClaimTypes.Role, groupName));
        }

        var claimsIdentity = new ClaimsIdentity(claims, _options.Name);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        return new ExternalLoginInfo(claimsPrincipal, _options.Name, userId, userName);
    }
}
