using System.Threading.Tasks;
using Meshmakers.Octo.Backend.Infrastructure.Initialization;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

public class DynamicAuthSchemeServiceInitializer : IAsyncInitializationService
{
    private readonly IDynamicAuthSchemeService _dynamicAuthSchemeService;

    public DynamicAuthSchemeServiceInitializer(IDynamicAuthSchemeService dynamicAuthSchemeService)
    {
        _dynamicAuthSchemeService = dynamicAuthSchemeService;
    }

    public async Task InitializeAsync()
    {
        await _dynamicAuthSchemeService.ConfigureAsync();
    }
}
