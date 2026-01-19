using IdentityServices.IntegrationTests.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.MongoDb;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
/// Fixture that starts MongoDB test container.
/// </summary>
public class DatabaseFixture : ConfigurationFixture
{
    protected readonly IntegrationTestOptions _options;
    private MongoDbContainer? _mongoDbContainer;

    public DatabaseFixture()
    {
        _options = GetOptions<IntegrationTestOptions>("integrationTest");
    }

    protected override async Task InitializeServicesAsync()
    {
        Console.WriteLine($"[Testcontainers] Starting MongoDB container with image: {_options.MongoDbImage}");
        Console.WriteLine($"[Testcontainers] DOCKER_HOST: {Environment.GetEnvironmentVariable("DOCKER_HOST") ?? "(not set)"}");
        Console.WriteLine($"[Testcontainers] TESTCONTAINERS_HOST_OVERRIDE: {Environment.GetEnvironmentVariable("TESTCONTAINERS_HOST_OVERRIDE") ?? "(not set)"}");
        Console.WriteLine($"[Testcontainers] TESTCONTAINERS_RYUK_DISABLED: {Environment.GetEnvironmentVariable("TESTCONTAINERS_RYUK_DISABLED") ?? "(not set)"}");

        // Start MongoDB test container with authentication
        _mongoDbContainer = new MongoDbBuilder(_options.MongoDbImage)
            .WithReplicaSet()
            .WithName($"mongodb-identity-test-{Guid.NewGuid():N}")
            .WithUsername(_options.AdminUser)
            .WithPassword(_options.AdminUserPassword)
            .WithCleanUp(true) // Ensure cleanup even if Ryuk is disabled in CI
            .Build();

        Console.WriteLine("[Testcontainers] Container built, starting...");
        var startTime = DateTime.UtcNow;

        // Use explicit timeout for container startup (5 minutes should be enough for image pull + startup)
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        await _mongoDbContainer.StartAsync(cts.Token);

        var elapsed = DateTime.UtcNow - startTime;
        Console.WriteLine($"[Testcontainers] Container started in {elapsed.TotalSeconds:F1}s");

        var mappedPort = _mongoDbContainer.GetMappedPublicPort();
        // Use localhost like the working project - this works in DinD with shared docker.sock
        var databaseHost = $"localhost:{mappedPort}";
        Console.WriteLine($"[Testcontainers] MongoDB available at: {databaseHost}");

        // Configure services with the test container connections
        Services.Configure<OctoSystemConfiguration>(t =>
        {
            t.SystemDatabaseName = SystemDatabaseName;
            t.DatabaseHost = databaseHost;
            t.AdminUser = _options.AdminUser;
            t.AdminUserPassword = _options.AdminUserPassword;
            t.DatabaseUserPassword = _options.DatabaseUserPassword;
            t.UseDirectConnection = true; // For single-node replica set in tests
        });

        await base.InitializeServicesAsync();
    }

    protected override async Task DisposeServicesAsync()
    {
        await Task.Yield();

        if (_mongoDbContainer != null)
        {
            await _mongoDbContainer.StopAsync();
            await _mongoDbContainer.DisposeAsync();
        }
    }

    public string GetConnectionString()
    {
        EnsureInitialized();

        if (_mongoDbContainer is null)
        {
            throw new InvalidOperationException("MongoDB container is not initialized. Call InitializeAsync first.");
        }

        return _mongoDbContainer.GetConnectionString();
    }
}
