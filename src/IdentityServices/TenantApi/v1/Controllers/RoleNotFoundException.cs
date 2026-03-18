namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

[Serializable]
public class RoleNotFoundException : Exception
{

    public RoleNotFoundException()
    {
    }

    public RoleNotFoundException(string message) : base(message)
    {
    }

    public RoleNotFoundException(string message, Exception inner) : base(message, inner)
    {
    }
}