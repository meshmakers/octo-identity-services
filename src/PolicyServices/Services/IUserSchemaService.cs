using System.Threading.Tasks;

#pragma warning disable 1591

namespace Meshmakers.Octo.Backend.PolicyServices.Services;

public interface IUserSchemaService
{
    Task SetupAsync();
}
