namespace Meshmakers.Octo.Backend.Authentication.Connection;

public interface ILdapConnectionFactory
{
    ILdapConnection CreateLdapConnection(string host, int port, string user, string password, bool useTls, ConnectionType connectionType);
}
