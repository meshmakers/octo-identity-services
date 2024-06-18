using System.Diagnostics.CodeAnalysis;
using Meshmakers.Common.Shared;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Controls;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

internal class LdapConnection : ILdapConnection
{
    private const int PageSize = 100;

    private static readonly Dictionary<ConnectionType, string> RootDseAttributeMapping =
        new()
        {
            { ConnectionType.OpenLdap, "namingContexts" },
            { ConnectionType.MicrosoftActiveDirectory, "rootDomainNamingContext" }
        };

    private readonly LdapConnectionContext _context;
    private readonly ILogger<LdapConnection> _logger;
    private readonly string _rootDseAttrName;

    /// <summary>
    ///     Set to true if the LDAP search with paging is not supported. This flag is
    ///     needed so that the connection with VLV is not configured again afterwards
    /// </summary>
    private bool _connectedWithoutVlv;

    private Novell.Directory.Ldap.LdapConnection? _connection;
    private bool _disposed;

    internal LdapConnection(LdapConnectionContext context, ILogger<LdapConnection> logger)
    {
        _context = context;
        _logger = logger;
        _rootDseAttrName = RootDseAttributeMapping[context.ConnectionType];
    }

    /// <summary>
    ///     Property used to access the ldap connection.
    /// </summary>
    [AllowNull]
    private Novell.Directory.Ldap.LdapConnection Connection
    {
        get
        {
            if (_connection == null || _connection.Connected != true)
            {
                _connection = new Novell.Directory.Ldap.LdapConnection { SecureSocketLayer = _context.UseTls };
                try
                {
                    _connection.Connect(_context.Host, _context.Port);
                }
                catch (LdapException e)
                {
                    _logger.LogError(e, "Cannot connect to the LDAP server");

                    // throw NotSupported rather than InvalidOperationException, since the authentication source is scoped and does not do reconnects
                    throw new NotSupportedException("Cannot connect to the LDAP server.", e);
                }
            }

            return _connection;
        }

        set
        {
            _connection?.Disconnect();

            _connection = value;
        }
    }

    public List<LdapEntry> ExecuteQuery(Action<LdapSearchParameters> configureSearchParams)
    {
        ArgumentValidation.Validate<Action<LdapSearchParameters>>(nameof(configureSearchParams), configureSearchParams);

        // Try VLV search only if not already connected to connection without VLV (searchQueue)
        if (_connectedWithoutVlv == false)
        {
            BindBrowsingUser();
            try
            {
                // Try search with virtual list view (VLV), which supports paged results
                return SearchWithVirtualList(configureSearchParams);
            }
            catch (NotSupportedException)
            {
                _logger.LogWarning(
                    "LDAP search with virtual list view (VLV) failed. Trying with search queue. Disabling VLV means that large user groups may not work correctly!");

                // The LDAP connection has to be recreated, because configuration with VLV did not work
                DisableVirtualListView();
            }
        }

        // If search with VLV did not work then try search with search queue
        // This search does not support paged results. There may be a max results limit.
        BindBrowsingUser();
        return SearchWithSearchQueue(configureSearchParams);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _connection?.Dispose();
            _connection = null;
        }

        _disposed = true;
    }

    private List<LdapEntry> SearchWithSearchQueue(
        Action<LdapSearchParameters> configureSearchParams)
    {
        var parameters = new LdapSearchParameters();
        configureSearchParams(parameters);

        try
        {
            var searchQueue = Connection.Search(
                parameters.BaseDn ?? GetRootDse(),
                parameters.Scope,
                parameters.Filter,
                parameters.Attrs,
                parameters.TypesOnly,
                parameters.Queue,
                parameters.Constraints);
            return searchQueue.GetLdapEntries();
        }
        catch (LdapException e)
        {
            _logger.LogError(e, "LDAP search with search queue failed");
            throw new NotSupportedException("LDAP search with search queue failed.", e);
        }
    }

    private void DisableVirtualListView()
    {
        Connection = null;
        _connectedWithoutVlv = true;
    }

    private string GetRootDse()
    {
        try
        {
            var searchQueue = Connection.Search(
                string.Empty, Novell.Directory.Ldap.LdapConnection.ScopeBase, "(objectClass=*)", new[] { _rootDseAttrName },
                false, null, null);
            var entry = searchQueue.GetLdapEntries().FirstOrDefault();
            if (entry == null)
            {
                throw new NotSupportedException("LDAP search did not returned results.");
            }

            var attribute = entry.GetAttribute(_rootDseAttrName);
            return attribute.StringValue;
        }
        catch (LdapException e)
        {
            _logger.LogError(e, "LDAP search failed");
            throw new NotSupportedException("LDAP search failed.", e);
        }
    }

    /// <summary>
    ///     Search with a virtual list view control (VLV), which is needed to get paged results from the LDAP server.
    ///     If the server does not support VLV, an LDAP exception will be thrown.
    /// </summary>
    /// <param name="configureSearchParams">An action configuring the search parameters</param>
    /// <returns>A list of the found entries</returns>
    private List<LdapEntry> SearchWithVirtualList(
        Action<LdapSearchParameters> configureSearchParams)
    {
        var parameters = new LdapSearchParameters();
        configureSearchParams(parameters);

        var resultIndex = 1;
        var pageIndex = PageSize;
        var ldapEntries = new List<LdapEntry>();
        var keys = new LdapSortKey[1];
        keys[0] = new LdapSortKey("cn");
        var sort = new LdapSortControl(keys, true);

        // break when we did not get a full page anymore
        while (pageIndex >= PageSize)
        {
            var ctrl = new LdapVirtualListControl(resultIndex, 0, PageSize - 1, 0);
            var constraints = Connection.SearchConstraints;
            constraints.SetControls(new LdapControl[] { ctrl, sort });
            Connection.Constraints = constraints;

            try
            {
                var searchResults = Connection.Search(
                    parameters.BaseDn ?? GetRootDse(),
                    parameters.Scope,
                    parameters.Filter,
                    parameters.Attrs,
                    false);
                pageIndex = 1;
                while (searchResults.HasMore())
                {
                    ldapEntries.Add(searchResults.Next());
                    resultIndex++;
                    pageIndex++;
                }
            }
            catch (LdapException e)
            {
                throw new NotSupportedException("LDAP search with virtual list view (VLV) failed.", e);
            }

            // If the page had only one entry, check if last entry was entered twice
            if (pageIndex == 2)
            {
                CheckIfLastEntryTwice(ldapEntries);
            }
        }

        return ldapEntries;
    }

    private void BindBrowsingUser()
    {
        try
        {
            Connection.Bind(_context.Username, _context.Password);
        }
        catch (LdapException e)
        {
            _logger.LogError(e, "Invalid browsing user credentials");
            throw new NotSupportedException("Invalid ldap browsing user credentials", e);
        }
    }

    /// <summary>
    ///     Check for special case. The problem is that if the search is done with a startIndex higher then the last ldap entry, then LDAP server
    ///     will always return the last entry.
    ///     This can happen if the number of elements on the ldap server can be divided through the page size (eg. 300 entries with a page size of
    ///     100 will be 3 full pages).
    ///     Because of the full page at the end, this function will try to get another page with an index higher than available entries on the
    ///     server. The server will return
    ///     its last entry again. As a result the ldapEntries-list will have the last entry twice.
    /// </summary>
    /// <param name="ldapEntries">A list of the entries which will be modified in-place</param>
    private void CheckIfLastEntryTwice(List<LdapEntry> ldapEntries)
    {
        if (ldapEntries.Count >= 2)
        {
            var lastEntry = ldapEntries.Last();
            var secondLastEntry = ldapEntries.ElementAt(ldapEntries.Count - 2);
            if (lastEntry.CompareTo(secondLastEntry) == 0)
                // The last two objects are the same. Remove last one.
            {
                ldapEntries.Remove(lastEntry);
            }
        }
    }
}