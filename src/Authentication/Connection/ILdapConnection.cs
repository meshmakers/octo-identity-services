using System;
using System.Collections.Generic;
using Novell.Directory.Ldap;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

public interface ILdapConnection : IDisposable
{
    public List<LdapEntry> ExecuteQuery(Action<LdapSearchParameters> configureSearchParams);
}
