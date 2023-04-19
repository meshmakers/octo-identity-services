using Novell.Directory.Ldap;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

public class LdapSearchParameters
{
    /// <summary>
    /// The base distinguished name to search from. If not specified it will be set
    /// as the root of the directory data tree on a directory server.
    /// </summary>
    public string? BaseDn { get; set; }

    /// <summary>
    /// The scope of the entries to search. The following
    ///     are the valid options:
    ///     <ul>
    ///         <li>SCOPE_BASE - searches only the base DN</li>
    ///         <li>SCOPE_ONE - searches only entries under the base DN</li>
    ///         <li>
    ///             SCOPE_SUB - searches the base DN and all entries
    ///             within its subtree
    ///         </li>
    ///     </ul>
    /// </summary>
    public int Scope { get; set; }

    /// <summary>
    /// The search filter specifying the search criteria.
    /// </summary>
    public string Filter { get; set; } = null!;

    /// <summary>
    /// The names of attributes to retrieve.
    /// </summary>
    public string[] Attrs { get; set; } = null!;

    /// <summary>
    /// If true, returns the names but not the values of
    /// the attributes found.  If false, returns the
    /// names and values for attributes found.
    /// </summary>
    public bool TypesOnly { get; set; } = default!;

    /// <summary>
    /// The queue for messages returned from a server in
    /// response to this request. If it is null, a
    /// queue object is created internally.
    /// </summary>
    public LdapSearchQueue Queue { get; set; } = null!;

    /// <summary>
    /// The constraints specific to the search.
    /// </summary>
    public LdapSearchConstraints Constraints { get; set; } = null!;
}
