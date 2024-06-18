using Meshmakers.Common.Shared;

namespace Meshmakers.Octo.Backend.Authentication.Connection;

internal class LdapConnectionContext
{
    internal LdapConnectionContext(string username, string password, string host, int port, bool useTls, ConnectionType connectionType)
    {
        ArgumentValidation.ValidateInt(nameof(port), port, ushort.MinValue, ushort.MaxValue);

        Username = username ?? throw new ArgumentNullException(nameof(username));
        Password = password ?? throw new ArgumentNullException(nameof(password));
        Host = host ?? throw new ArgumentNullException(nameof(host));
        Port = port;
        UseTls = useTls;
        ConnectionType = connectionType;
    }

    public string Username { get; }
    public string Password { get; }
    public string Host { get; }
    public int Port { get; }
    public bool UseTls { get; }
    public ConnectionType ConnectionType { get; }
}