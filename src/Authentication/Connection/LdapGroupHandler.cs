using System.Text.RegularExpressions;
using Novell.Directory.Ldap;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

public class LdapGroupHandler
{
    private readonly string _searchBase;
    private readonly string _userNameAttributeName;

    public LdapGroupHandler(string searchBase, string userNameAttributeName)
    {
        _searchBase = searchBase;
        _userNameAttributeName = userNameAttributeName;
    }

    public async IAsyncEnumerable<string> GetGroupsForUserAsync(ILdapConnection ldapConnection, string userName)
    {
        var groups = new Stack<string>();
        var uniqueGroups = new HashSet<string>();

        await foreach (var group in GetGroupsForUserCoreAsync(ldapConnection, userName))
        {
            groups.Push(group);
        }

        while (groups.Count > 0)
        {
            var group = groups.Pop();
            if (uniqueGroups.Add(group))
            {
                yield return group;
            }

            await foreach (var parentGroup in GetGroupsForUserCoreAsync(ldapConnection, group))
            {
                groups.Push(parentGroup);
            }
        }
    }

    private async IAsyncEnumerable<string> GetGroupsForUserCoreAsync(ILdapConnection ldapConnection, string user)
    {
        var entries = await ldapConnection.ExecuteQueryAsync(parameters =>
        {
            parameters.BaseDn = _searchBase;
            parameters.Filter = $"({_userNameAttributeName}={user})";
            parameters.Scope = Novell.Directory.Ldap.LdapConnection.ScopeSub;
            parameters.Attrs = ["cn", "memberOf"];
            parameters.TypesOnly = false;
        });

        foreach (var entry in entries)
            foreach (var value in HandleEntry(entry))
            {
                yield return value;
            }

        IEnumerable<string> HandleEntry(LdapEntry entry)
        {
            var attr = entry.GetOrDefault("memberOf");

            if (attr == null)
            {
                yield break;
            }

            foreach (var value in attr.StringValueArray)
            {
                var groupName = GetGroup(value);
                if (!string.IsNullOrEmpty(groupName))
                {
                    yield return groupName;
                }
            }
        }

        string? GetGroup(string value)
        {
            var match = Regex.Match(value, "^CN=([^,]*)");

            if (!match.Success)
            {
                return null;
            }

            return match.Groups[1].Value;
        }
    }
}