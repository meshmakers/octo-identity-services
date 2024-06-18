using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Initialization;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

internal class DynamicAuthSchemeServiceInitializer : IAsyncInitializationService
{
    private readonly ISystemContext _systemContext;
    private readonly IDynamicAuthSchemeService _dynamicAuthSchemeService;

    public DynamicAuthSchemeServiceInitializer(ISystemContext systemContext, IDynamicAuthSchemeService dynamicAuthSchemeService)
    {
        _systemContext = systemContext;
        _dynamicAuthSchemeService = dynamicAuthSchemeService;
    }

    public int Order => 50;

    public async Task InitializeAsync()
    {
        await _dynamicAuthSchemeService.ConfigureAsync(_systemContext.TenantId);
    }
}