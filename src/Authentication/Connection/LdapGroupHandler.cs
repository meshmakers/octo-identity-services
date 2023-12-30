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

    public IEnumerable<string> GetGroupsForUser(ILdapConnection ldapConnection, string userName)
    {
        var groups = new Stack<string>();
        var uniqueGroups = new HashSet<string>();

        foreach (var group in GetGroupsForUserCore(ldapConnection, userName)) groups.Push(group);

        while (groups.Count > 0)
        {
            var group = groups.Pop();
            if (uniqueGroups.Add(group)) yield return group;

            foreach (var parentGroup in GetGroupsForUserCore(ldapConnection, group)) groups.Push(parentGroup);
        }
    }

    private IEnumerable<string> GetGroupsForUserCore(ILdapConnection ldapConnection, string user)
    {
        var entries = ldapConnection.ExecuteQuery(parameters =>
        {
            parameters.BaseDn = _searchBase;
            parameters.Filter = $"({_userNameAttributeName}={user})";
            parameters.Scope = Novell.Directory.Ldap.LdapConnection.ScopeSub;
            parameters.Attrs = new[] { "cn", "memberOf" };
            parameters.TypesOnly = false;
        });

        foreach (var entry in entries)
        foreach (var value in HandleEntry(entry))
            yield return value;

        IEnumerable<string> HandleEntry(LdapEntry entry)
        {
            var attr = entry.GetAttribute("memberOf");

            if (attr == null) yield break;

            foreach (var value in attr.StringValueArray)
            {
                var groupName = GetGroup(value);
                if (!string.IsNullOrEmpty(groupName)) yield return groupName;
            }
        }

        string? GetGroup(string value)
        {
            var match = Regex.Match(value, "^CN=([^,]*)");

            if (!match.Success) return null;

            return match.Groups[1].Value;
        }
    }
}