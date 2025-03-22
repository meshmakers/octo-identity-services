using Novell.Directory.Ldap;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

public interface ILdapConnection : IDisposable
{
    public Task<List<LdapEntry>> ExecuteQueryAsync(Action<LdapSearchParameters> configureSearchParams);
}