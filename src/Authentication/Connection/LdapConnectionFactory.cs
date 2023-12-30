using Microsoft.Extensions.Logging;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

internal class LdapConnectionFactory : ILdapConnectionFactory
{
    private readonly ILoggerFactory _loggerFactory;

    public LdapConnectionFactory(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    public ILdapConnection CreateLdapConnection(string host, int port, string user, string password, bool useTls,
        ConnectionType connectionType)
    {
        var context = new LdapConnectionContext(user, password, host, port, useTls, connectionType);
        return new LdapConnection(context, _loggerFactory.CreateLogger<LdapConnection>());
    }
}