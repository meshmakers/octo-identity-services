using System.Threading.Tasks;

#pragma warning disable 1591

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public interface IUserSchemaService
{
    Task SetupAsync();
}
