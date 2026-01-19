using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using IdentityServerPersistence.Configuration.Options;
using IdentityServices.IntegrationTests.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Services;
using Meshmakers.Octo.Runtime.Engine.MongoDb.Services.Defaults;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Testcontainers.MongoDb;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly IntegrationTestConfiguration _configuration = new();
    private readonly IntegrationTestOptions _options;
    private MongoDbContainer? _mongoContainer;

    public CustomWebApplicationFactory()
    {
        _options = new IntegrationTestOptions();
        _configuration.GetSection("integrationTest").Bind(_options);
    }

    public string MongoConnectionString => _mongoContainer?.GetConnectionString()
        ?? throw new InvalidOperationException("MongoDB container not initialized");

    public async ValueTask InitializeAsync()
    {
        // Write to stderr for immediate output (stdout is buffered)
        Console.Error.WriteLine($"[WebFactory] Starting MongoDB container with image: {_options.MongoDbImage}");
        Console.Error.WriteLine($"[WebFactory] DOCKER_HOST: {Environment.GetEnvironmentVariable("DOCKER_HOST") ?? "(not set)"}");
        Console.Error.WriteLine($"[WebFactory] TESTCONTAINERS_HOST_OVERRIDE: {Environment.GetEnvironmentVariable("TESTCONTAINERS_HOST_OVERRIDE") ?? "(not set)"}");
        Console.Error.Flush();

        _mongoContainer = new MongoDbBuilder(_options.MongoDbImage)
            .WithReplicaSet()
            .WithName($"mongodb-identity-webtest-{Guid.NewGuid():N}")
            .WithUsername(_options.AdminUser)
            .WithPassword(_options.AdminUserPassword)
            .WithCleanUp(true) // Ensure cleanup even if Ryuk is disabled in CI
            .Build();

        Console.Error.WriteLine("[WebFactory] Container built, starting...");
        Console.Error.Flush();
        var startTime = DateTime.UtcNow;

        // Use explicit timeout for container startup (2 minutes)
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try
        {
            await _mongoContainer.StartAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("[WebFactory] ERROR: Container startup timed out after 2 minutes!");
            Console.Error.Flush();
            throw new TimeoutException("MongoDB container startup timed out after 2 minutes");
        }

        var elapsed = DateTime.UtcNow - startTime;
        Console.Error.WriteLine($"[WebFactory] Container started in {elapsed.TotalSeconds:F1}s");
        Console.Error.Flush();

        // Initialize system tenant before web host starts
        Console.Error.WriteLine("[WebFactory] Initializing system tenant...");
        Console.Error.Flush();
        await InitializeSystemTenantAsync();
        Console.Error.WriteLine("[WebFactory] System tenant initialized");
        Console.Error.Flush();
    }

    private async Task InitializeSystemTenantAsync()
    {
        if (_mongoContainer == null)
        {
            throw new InvalidOperationException("MongoDB container not initialized");
        }

        var mappedPort = _mongoContainer.GetMappedPublicPort();
        // Use localhost like the working project - this works in DinD with shared docker.sock
        var databaseHost = $"localhost:{mappedPort}";
        Console.Error.WriteLine($"[WebFactory] MongoDB connection: {databaseHost}");
        Console.Error.Flush();

        // Build a temporary service provider for system tenant initialization
        var services = new ServiceCollection();

        services.AddLogging(builder => builder.AddConsole());

        services.AddRuntimeEngine()
            .AddOctoIdentityPersistence(
                _ => new OctoSystemConfiguration(),
                configureDistributionEventHub: null);

        services.AddSingleton<ITenantNotifications, DefaultTenantNotifications>();

        services.Configure<OctoSystemConfiguration>(t =>
        {
            t.SystemDatabaseName = "identityintegrationtests";
            t.DatabaseHost = databaseHost;
            t.AdminUser = _options.AdminUser;
            t.AdminUserPassword = _options.AdminUserPassword;
            t.DatabaseUserPassword = _options.DatabaseUserPassword;
            t.UseDirectConnection = true;
        });

        await using var provider = services.BuildServiceProvider();
        var systemContext = provider.GetRequiredService<ISystemContext>();

        Console.Error.WriteLine("[WebFactory] Ensuring system CK model...");
        Console.Error.Flush();
        // Ensure the system CK model is available
        await systemContext.EnsureSystemCkModelAsync();
        Console.Error.WriteLine("[WebFactory] System CK model ensured");
        Console.Error.Flush();

        // Ensure clean state - delete if exists
        Console.Error.WriteLine("[WebFactory] Checking for existing system tenant...");
        Console.Error.Flush();
        for (var i = 0; i < 10; i++)
        {
            try
            {
                var exists = await systemContext.IsSystemTenantExistingAsync();
                Console.Error.WriteLine($"[WebFactory] Iteration {i}: System tenant exists = {exists}");
                Console.Error.Flush();

                if (i == 0 && exists)
                {
                    Console.Error.WriteLine("[WebFactory] Deleting existing system tenant...");
                    Console.Error.Flush();
                    await systemContext.DeleteSystemTenantAsync();
                    Console.Error.WriteLine("[WebFactory] System tenant deleted");
                    Console.Error.Flush();
                }

                if (await systemContext.IsSystemTenantExistingAsync())
                {
                    Console.Error.WriteLine($"[WebFactory] Tenant still exists, waiting 1s (iteration {i})...");
                    Console.Error.Flush();
                    await Task.Delay(1000);
                    continue;
                }

                Console.Error.WriteLine("[WebFactory] Tenant cleanup complete");
                Console.Error.Flush();
                break;
            }
            catch (TenantException ex)
            {
                Console.Error.WriteLine($"[WebFactory] TenantException during cleanup: {ex.Message}");
                Console.Error.Flush();
                // Ignore tenant exceptions during cleanup
            }
        }

        // Create system tenant
        Console.Error.WriteLine("[WebFactory] Creating system tenant...");
        Console.Error.Flush();
        await systemContext.CreateSystemTenantAsync();
        Console.Error.WriteLine("[WebFactory] System tenant created");
        Console.Error.Flush();
    }

    public new async ValueTask DisposeAsync()
    {
        if (_mongoContainer != null)
        {
            await _mongoContainer.StopAsync();
            await _mongoContainer.DisposeAsync();
        }

        await base.DisposeAsync();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddJsonFile("appsettings.test.json", optional: true);
        });

        builder.ConfigureTestServices(services =>
        {
            // Add test authentication handler as an additional scheme
            // Don't override the default schemes - IdentityServer needs its cookie auth
            services.AddAuthentication()
                .AddScheme<TestAuthHandlerOptions, TestAuthHandler>(
                    TestAuthHandler.SchemeName, _ => { });

            // Configure MongoDB connection using the test container
            if (_mongoContainer != null)
            {
                var mappedPort = _mongoContainer.GetMappedPublicPort();
                // Use localhost like the working project - this works in DinD with shared docker.sock
                var databaseHost = $"localhost:{mappedPort}";

                services.Configure<OctoSystemConfiguration>(t =>
                {
                    t.SystemDatabaseName = "identityintegrationtests";
                    t.DatabaseHost = databaseHost;
                    t.AdminUser = _options.AdminUser;
                    t.AdminUserPassword = _options.AdminUserPassword;
                    t.DatabaseUserPassword = _options.DatabaseUserPassword;
                    t.UseDirectConnection = true;
                });
            }

            // Configure identity options for testing
            services.Configure<OctoIdentityServicesOptions>(opts =>
            {
                opts.IdentityServerLicenseKey = "test-license-key";
                opts.AutoMapperLicenseKey = "test-automapper-key";
                opts.KeyFilePath = "not-used-in-tests";
                opts.KeyFilePassword = "not-used-in-tests";
                opts.AuthorityUrl = "https://localhost:5003";
                opts.EnableTokenCleanup = false;
            });

            // Replace signing credential stores with test implementations
            services.RemoveAll<ISigningCredentialStore>();
            services.RemoveAll<IValidationKeysStore>();
            services.AddSingleton<ISigningCredentialStore, TestSigningCredentialStore>();
            services.AddSingleton<IValidationKeysStore, TestSigningCredentialStore>();
        });
    }
}

/// <summary>
/// Test implementation of signing credential store using an in-memory RSA key.
/// </summary>
internal class TestSigningCredentialStore : ISigningCredentialStore, IValidationKeysStore
{
    private readonly SigningCredentials _signingCredentials;
    private readonly IEnumerable<SecurityKeyInfo> _validationKeys;

    public TestSigningCredentialStore()
    {
        // Create a test RSA key for signing
        var rsaKey = new RsaSecurityKey(System.Security.Cryptography.RSA.Create(2048))
        {
            KeyId = "test-key-id"
        };

        _signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);
        _validationKeys = new[]
        {
            new SecurityKeyInfo { Key = rsaKey, SigningAlgorithm = SecurityAlgorithms.RsaSha256 }
        };
    }

    public Task<SigningCredentials?> GetSigningCredentialsAsync()
    {
        return Task.FromResult<SigningCredentials?>(_signingCredentials);
    }

    public Task<IEnumerable<SecurityKeyInfo>?> GetValidationKeysAsync()
    {
        return Task.FromResult<IEnumerable<SecurityKeyInfo>?>(_validationKeys);
    }
}
