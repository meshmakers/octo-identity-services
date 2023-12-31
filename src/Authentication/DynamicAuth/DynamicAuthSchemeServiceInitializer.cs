using Meshmakers.Octo.Services.Infrastructure.Initialization;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

internal class DynamicAuthSchemeServiceInitializer : IAsyncInitializationService
{
    private readonly IDynamicAuthSchemeService _dynamicAuthSchemeService;

    public DynamicAuthSchemeServiceInitializer(IDynamicAuthSchemeService dynamicAuthSchemeService)
    {
        _dynamicAuthSchemeService = dynamicAuthSchemeService;
    }

    public int Order => 50;

    public async Task InitializeAsync()
    {
        await _dynamicAuthSchemeService.ConfigureAsync(null);
    }
}