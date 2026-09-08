using IdentityServerPersistence;
using MartinCostello.Logging.XUnit;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Services;
using Meshmakers.Octo.Runtime.Engine.MongoDb.Services.Defaults;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

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

        // System.Notification CK model + services. Production Program.cs registers this via
        // AddOctoNotification(); the fixture has to mirror it because Phase 3 PR #4 made
        // SetupTenantAsync call CreateTenantConfiguration unconditionally (previously it was
        // gated by the IdentitySchemaVersion < 17 check, which test setups skipped). Without
        // this registration RtNotificationTemplate / RtMailNotificationConfiguration BSON
        // class maps are missing and GetRtEntitiesByTypeAsync throws InvalidCastException.
        Services.AddOctoNotification();

        // Add runtime engine with identity persistence for testing
        // Note: We pass null for configureDistributionEventHub to skip RabbitMQ setup
        Services.AddRuntimeEngine()
            .AddOctoIdentityPersistence(
                _ => new OctoSystemConfiguration(),
                configureDistributionEventHub: null);

        // Replace tenant notifications with default implementation (no RabbitMQ in tests)
        Services.AddSingleton<ITenantNotifications, DefaultTenantNotifications>();

        // MigrationService + the identity-service migrations themselves. Production
        // wires this in Program.cs; tests that exercise DefaultConfigurationCreatorService
        // (e.g. ClientMirrorProvisioningIntegrationTests) hit a DI failure without it
        // because the service has a required (nullable but resolved-by-DI) MigrationService
        // ctor argument.
        Services.AddMigrations(typeof(IdentityServiceConstants).Assembly);

        // Add logging with xUnit output.
        //
        // AB#5160: this used to be LogLevel.Trace, which routes every MongoDB command — including the full
        // BSON payload — into the xUnit output of every test. Together with the CI test task's
        // `--logger "console;verbosity=detailed"` that produced a 131 MB build log in which a genuine
        // failure was unfindable. Warning keeps the diagnostics that matter: failed assertions carry their
        // own message, the TRX logger still records every test, and the container/tenant progress markers
        // in DatabaseFixture / CustomWebApplicationFactory are Console writes, not ILogger calls, so they
        // survive. Raise this locally when a specific test needs the command stream.
        Services.AddLogging(loggingBuilder =>
        {
            loggingBuilder.ClearProviders();
            loggingBuilder.SetMinimumLevel(LogLevel.Warning);
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

    public async ValueTask DisposeAsync()
    {
        await DisposeServicesAsync();

        if (Provider is not null)
        {
            await Provider.DisposeAsync();
        }
    }

    public async ValueTask InitializeAsync()
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
