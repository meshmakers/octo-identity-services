using IdentityServices.IntegrationTests.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     Fixture that binds the service collection to a MongoDB replica set (required for transactions).
///
///     The replica set is the process-wide <see cref="SharedMongoDbContainer" />, not a container of
///     this fixture's own (AB#5117): isolation between fixtures comes from the per-fixture
///     <see cref="ConfigurationFixture.SystemDatabaseName" />, so a private server buys nothing but
///     ~8-12s of container start per test class.
/// </summary>
public class DatabaseFixture : ConfigurationFixture
{
    protected readonly IntegrationTestOptions _options;

    public DatabaseFixture()
    {
        _options = GetOptions<IntegrationTestOptions>("integrationTest");
    }

    protected override async Task InitializeServicesAsync()
    {
        var databaseHost = await SharedMongoDbContainer.GetHostAsync(_options);
        Console.WriteLine(
            $"[Testcontainers] {GetType().Name} uses MongoDB at {databaseHost}, database '{SystemDatabaseName}'");

        // Configure services with the test container connections
        Services.Configure<OctoSystemConfiguration>(t =>
        {
            t.SystemTenantId = SystemTenantId;
            t.SystemDatabaseName = SystemDatabaseName;
            t.DatabaseHost = databaseHost;
            t.AdminUser = _options.AdminUser;
            t.AdminUserPassword = _options.AdminUserPassword;
            t.DatabaseUserPassword = _options.DatabaseUserPassword;
            t.UseDirectConnection = true; // For single-node replica set in tests
        });

        await base.InitializeServicesAsync();
    }

    protected override Task DisposeServicesAsync()
    {
        // Nothing to tear down here: the shared container outlives every individual fixture and is
        // disposed once per test process by SharedMongoDbContainerDisposer. This fixture's database
        // goes with it.
        return Task.CompletedTask;
    }

    public string GetConnectionString()
    {
        EnsureInitialized();

        return SharedMongoDbContainer.ConnectionString;
    }
}
