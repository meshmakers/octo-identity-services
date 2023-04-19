using System.Threading.Tasks;
using Meshmakers.Octo.Backend.Infrastructure.Initialization;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserSchemaInitializer : IAsyncInitializationService
{
    private readonly IUserSchemaService _userSchemaService;

    public UserSchemaInitializer(IUserSchemaService userSchemaService)
    {
        _userSchemaService = userSchemaService;
    }

    public async Task InitializeAsync()
    {
        await _userSchemaService.SetupAsync();
    }
}
