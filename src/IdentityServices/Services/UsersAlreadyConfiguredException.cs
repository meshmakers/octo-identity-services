namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UsersAlreadyConfiguredException : UserManagementException
{
    private UsersAlreadyConfiguredException()
    {
    }

    private UsersAlreadyConfiguredException(string message) : base(message)
    {
    }

    private UsersAlreadyConfiguredException(string message, Exception inner) : base(message, inner)
    {
    }

    public static Exception UsersConfigured()
    {
        return new UsersAlreadyConfiguredException("The request is not valid for this configuration.");
    }
}