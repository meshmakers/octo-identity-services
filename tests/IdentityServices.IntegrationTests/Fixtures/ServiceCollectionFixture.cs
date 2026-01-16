using MartinCostello.Logging.XUnit;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Services;
using Meshmakers.Octo.Runtime.Engine.MongoDb.Services.Defaults;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
/// Base fixture that provides a service collection and service provider.
/// This is the foundation for all integration test fixtures.
/// </summary>
public abstract class ServiceCollectionFixture : ITestOutputHelperAccessor, IAsyncLifetime
{
    private bool _isInitialized;

    protected ServiceCollectionFixture()
    {
        Services = new ServiceCollection();

        // Add runtime engine with identity persistence for testing
        // Note: We pass null for configureDistributionEventHub to skip RabbitMQ setup
        Services.AddRuntimeEngine()
            .AddOctoIdentityPersistence(
                _ => new OctoSystemConfiguration(),
                configureDistributionEventHub: null);

        // Replace tenant notifications with default implementation (no RabbitMQ in tests)
        Services.AddSingleton<ITenantNotifications, DefaultTenantNotifications>();

        // Add logging with xUnit output
        Services.AddLogging(loggingBuilder =>
        {
            loggingBuilder.ClearProviders();
            loggingBuilder.SetMinimumLevel(LogLevel.Trace);
            loggingBuilder.AddXUnit(this);
        });
    }

    public ServiceCollection Services { get; }

    public ServiceProvider? Provider { get; private set; }

    public ITestOutputHelper? OutputHelper { get; set; }

    public void EnsureInitialized()
    {
        if (!_isInitialized)
        {
            throw new InvalidOperationException("Fixture is not initialized. Call InitializeAsync first.");
        }
    }

    public async Task DisposeAsync()
    {
        await DisposeServicesAsync();

        if (Provider is not null)
        {
            await Provider.DisposeAsync();
        }
    }

    public async Task InitializeAsync()
    {
        if (_isInitialized)
        {
            return;
        }

        await InitializeServicesAsync();
    }

    protected virtual Task InitializeServicesAsync()
    {
        Provider = Services.BuildServiceProvider();
        _isInitialized = true;

        return Task.CompletedTask;
    }

    protected abstract Task DisposeServicesAsync();

    public T GetService<T>() where T : notnull
    {
        if (Provider == null)
        {
            throw new InvalidOperationException("Provider is not initialized. Call InitializeAsync first.");
        }

        return Provider.GetRequiredService<T>();
    }

    public ISystemContext GetSystemContext()
    {
        if (Provider == null)
        {
            throw new InvalidOperationException("Provider is not initialized. Call InitializeAsync first.");
        }

        return Provider.GetRequiredService<ISystemContext>();
    }
}
