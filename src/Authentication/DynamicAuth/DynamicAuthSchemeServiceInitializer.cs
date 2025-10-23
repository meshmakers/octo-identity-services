using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Initialization;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

// ReSharper disable once ClassNeverInstantiated.Global
internal class DynamicAuthSchemeServiceInitializer(
    ISystemContext systemContext,
    IDynamicAuthSchemeService dynamicAuthSchemeService)
    : IAsyncInitializationService
{
    public int Order => 50;

    public async Task InitializeAsync()
    {
        await dynamicAuthSchemeService.ConfigureAsync(systemContext.TenantId);
    }
}