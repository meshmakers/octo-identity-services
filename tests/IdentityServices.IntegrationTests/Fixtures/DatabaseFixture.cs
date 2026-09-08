using IdentityServices.IntegrationTests.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.MongoDb;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     Fixture that starts a MongoDB Testcontainer with a replica set (required for transactions).
///
///     Container-bringup pattern matches octo-construction-kit-engine-mongodb /
///     octo-ai-services — Testcontainers' rs.initiate() handshake and mongo's keyfile-init
///     entrypoint race with port binding on CI agents under load (build 34386 hung 40+ min
///     in a sibling service due to exit-48 on 27017 inside the entrypoint restart). The
///     retry loop with a *fresh* container per attempt is the proven fix.
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

        const int maxAttempts = 3;
        var perAttemptTimeout = TimeSpan.FromMinutes(2);

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            Console.WriteLine($"[Testcontainers] StartAsync attempt {attempt}/{maxAttempts}");

            // No WithCleanUp(true) — Ryuk's TCP handshake blocks silently on the self-hosted
            // DinD agent; DisposeServicesAsync handles cleanup explicitly.
            _mongoDbContainer = new MongoDbBuilder(_options.MongoDbImage)
                .WithReplicaSet()
                .WithName($"mongodb-identity-test-{Guid.NewGuid():N}")
                .WithUsername(_options.AdminUser)
                .WithPassword(_options.AdminUserPassword)
                .Build();

            using var startCts = new CancellationTokenSource(perAttemptTimeout);
            var startTime = DateTime.UtcNow;

            try
            {
                await _mongoDbContainer.StartAsync(startCts.Token);
                var elapsed = DateTime.UtcNow - startTime;
                Console.WriteLine($"[Testcontainers] Container started in {elapsed.TotalSeconds:F1}s");
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[Testcontainers] StartAsync attempt {attempt}/{maxAttempts} failed: {ex.GetType().Name}: {ex.Message}");

                try
                {
                    await _mongoDbContainer.DisposeAsync();
                }
                catch (Exception disposeEx)
                {
                    Console.WriteLine($"[Testcontainers]   Disposal of failed container also threw: {disposeEx.Message}");
                }

                _mongoDbContainer = null;

                if (attempt == maxAttempts)
                {
                    throw;
                }

                await Task.Delay(TimeSpan.FromSeconds(2 * attempt));
            }
        }

        var mappedPort = _mongoDbContainer!.GetMappedPublicPort();
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
