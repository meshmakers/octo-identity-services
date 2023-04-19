using System.Collections.Generic;
using Novell.Directory.Ldap;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

internal static class LdapSearchQueueExtensions
{
    /// <summary>
    /// Gets LDAP entries from the LDAP search response.
    /// </summary>
    /// <returns>The list of the LDAP entries.</returns>
    internal static List<LdapEntry> GetLdapEntries(this LdapSearchQueue? searchQueue)
    {
        var entries = new List<LdapEntry>();
        while (searchQueue != null && searchQueue.GetResponse() is { } ldapMessage)
        {
            if (ldapMessage is LdapSearchResult searchResult)
            {
                var entry = searchResult.Entry;
                entries.Add(entry);
            }
        }

        return entries;
    }
}