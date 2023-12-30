namespace IdentityServerPersistence;

public class InitializationException : Exception
{
    public InitializationException()
    {
    }

    public InitializationException(string message) : base(message)
    {
    }

    public InitializationException(string message, Exception inner) : base(message, inner)
    {
    }

    internal static Exception ImportCkModelFailed(string tenantId, string messages)
    {
        return new InitializationException($"Importing CK model failed for system context tenant '{tenantId}'. {messages}");
    }
}