namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserManagementException : Exception
{
    protected UserManagementException()
    {
    }

    protected UserManagementException(string message) : base(message)
    {
    }

    protected UserManagementException(string message, Exception inner) : base(message, inner)
    {
    }

    public static Exception EMailMissing()
    {
        return new UserManagementException("E-Mail value is missing");
    }

    public static Exception PasswordMissing()
    {
        return new UserManagementException("Password value is missing");
    }

    public static Exception PasswordComplexityCheckFailed()
    {
        return new UserManagementException("The password does not comply with the minimum requirements");
    }

    public static Exception RoleNotFound(string roleName)
    {
        return new UserManagementException($"No {roleName}-Role has been found");
    }
}
