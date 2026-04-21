using System.Security.Claims;
using System.Text.RegularExpressions;
using IdentityModel;
using Meshmakers.Octo.Backend.Authentication.Connection;
using Meshmakers.Octo.Backend.Authentication.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;
using LdapConnection = Novell.Directory.Ldap.LdapConnection;

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
    private readonly ILogger _logger;
    private readonly LdapOptions _options;

    public MicrosoftAdAuthentication(ILdapConnectionFactory connectionFactory, LdapOptions options, ILogger logger)
    {
        _connectionFactory = connectionFactory;
        _options = options;
        _logger = logger;
    }

    public async Task<ExternalLoginInfo> AuthenticateAsync(string username, string password)
    {
        using var connection = _connectionFactory.CreateLdapConnection(_options.Host, _options.Port, username, password, _options.UseTls,
            ConnectionType.MicrosoftActiveDirectory);
        var result = await connection.ExecuteQueryAsync(parameters =>
        {
            parameters.Scope = LdapConnection.ScopeSub;
            parameters.Filter = $"{UserPrincipalNameAttribute}={username}";
        });
        var entry = result.SingleOrDefault();

        if (entry == null)
        {
            throw new InvalidOperationException("Could not authenticate user.");
        }

        // Extract group names directly from the user entry's memberOf attribute
        // instead of making a separate LDAP query via LdapGroupHandler, which can fail
        // silently when the LDAP connection is in a degraded state after VLV fallback
        List<string> groupNames;
        try
        {
            groupNames = ExtractGroupNamesFromEntry(entry);
            _logger.LogInformation("Extracted {Count} AD group(s) for user '{Username}': [{Groups}]",
                groupNames.Count, username, string.Join(", ", groupNames));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to extract AD group memberships from memberOf attribute for user '{Username}'. User will be authenticated without group claims.",
                username);
            groupNames = [];
        }

        return LdapEntryToUser(entry, groupNames);
    }

    private List<string> ExtractGroupNamesFromEntry(LdapEntry entry)
    {
        var groups = new List<string>();
        var memberOfAttr = entry.GetOrDefault("memberOf");
        if (memberOfAttr == null)
        {
            _logger.LogWarning("User LDAP entry has no 'memberOf' attribute. No AD groups will be mapped.");
            return groups;
        }

        _logger.LogInformation("Found {Count} memberOf values in LDAP entry", memberOfAttr.StringValueArray.Length);

        foreach (var dn in memberOfAttr.StringValueArray)
        {
            var match = Regex.Match(dn, "^CN=([^,]*)");
            if (match.Success)
            {
                groups.Add(match.Groups[1].Value);
            }
            else
            {
                _logger.LogWarning("Could not extract CN from memberOf DN: '{Dn}'", dn);
            }
        }

        return groups;
    }

    private ExternalLoginInfo LdapEntryToUser(LdapEntry entry, List<string> groupNames)
    {
        var userIdBytes = entry.GetOrDefault(UserIdAttributeName)?.ByteValue;
        if (userIdBytes == null)
        {
            throw new InvalidOperationException("Could not authenticate user.");
        }

        var userId = new Guid(userIdBytes).ToString();
        var userName = entry.Get(UserFullNameAttributeName).StringValue;
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userName),
            new(ClaimTypes.NameIdentifier, userId)
        };

        if (entry.GetAttributeSet().ContainsKey(GivenNameAttribute))
        {
            var value = entry.Get(GivenNameAttribute).StringValue;
            claims.Add(new Claim(ClaimTypes.GivenName, value));
        }

        if (entry.GetAttributeSet().ContainsKey(SurNameAttribute))
        {
            var value = entry.Get(SurNameAttribute).StringValue;
            claims.Add(new Claim(ClaimTypes.Surname, value));
        }

        if (entry.GetAttributeSet().ContainsKey(MailAttribute))
        {
            var value = entry.Get(MailAttribute).StringValue;
            claims.Add(new Claim(ClaimTypes.Email, value));
        }

        foreach (var groupName in groupNames)
        {
            claims.Add(new Claim(JwtClaimTypes.Role, groupName));
        }

        var claimsIdentity = new ClaimsIdentity(claims, _options.Name);
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        return new ExternalLoginInfo(claimsPrincipal, _options.Name, userId, userName);
    }
}