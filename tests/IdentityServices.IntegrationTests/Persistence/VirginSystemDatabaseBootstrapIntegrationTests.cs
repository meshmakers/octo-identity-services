using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.TenantLifecycle;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// Pins the fresh-install bootstrap through identity's own <c>SetupAsync</c> against a virgin
/// MongoDB (AB#4854). In r3.4.93 the engine's infrastructure collections (lifecycle probe index,
/// setup-retry record) materialized the system database as an empty shell before
/// <c>SetupTenantAsync</c> decided whether to bootstrap; the decision then refused, the datasource
/// user was never created, and every service start failed on a MongoDB authentication error.
/// </summary>
[Collection("Sequential")]
public class VirginSystemDatabaseBootstrapIntegrationTests : IClassFixture<VirginBootstrapFixture>
{
    private readonly VirginBootstrapFixture _fixture;

    public VirginSystemDatabaseBootstrapIntegrationTests(VirginBootstrapFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    private OctoSystemConfiguration Configuration =>
        _fixture.GetService<IOptions<OctoSystemConfiguration>>().Value;

    [Fact]
    public async Task SetupAsync_OnVirginServer_BootstrapsSystemTenant()
    {
        await ResetToVirginAsync();

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);

        Assert.True(await _fixture.GetSystemContext().IsSystemTenantExistingAsync());
        Assert.True(await IsSystemDatabaseUserExistingAsync());
    }

    [Fact]
    public async Task SetupAsync_OverInfrastructureShellDatabase_BootstrapsSystemTenant()
    {
        await ResetToVirginAsync();

        // The exact 3.4.93 wedge sequence: a durable setup-failure record materializes the system
        // database as an infrastructure-only shell before the bootstrap decision runs.
        var retryStore = _fixture.GetService<ITenantSetupRetryStore>();
        await retryStore.RecordFailureAsync("IdentityServerPersistence",
            _fixture.GetSystemContext().TenantId, "transient failure before bootstrap",
            TestContext.Current.CancellationToken);

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);

        Assert.True(await _fixture.GetSystemContext().IsSystemTenantExistingAsync());
        Assert.True(await IsSystemDatabaseUserExistingAsync());
    }

    /// <summary>
    /// Drops the system database and its datasource user, restoring the virgin-server state so the
    /// facts of this class are order-independent on the shared container.
    /// </summary>
    private async Task ResetToVirginAsync()
    {
        var adminClient = CreateAdminClient();
        await adminClient.DropDatabaseAsync(Configuration.SystemDatabaseName,
            TestContext.Current.CancellationToken);

        var userName = string.Format(Configuration.DatabaseUser, Configuration.SystemDatabaseName);
        var authDatabase = adminClient.GetDatabase(Configuration.AuthenticationDatabaseName);
        try
        {
            await authDatabase.RunCommandAsync<BsonDocument>(
                new BsonDocumentCommand<BsonDocument>(new BsonDocument("dropUser", userName)),
                cancellationToken: TestContext.Current.CancellationToken);
        }
        catch (MongoCommandException)
        {
            // User does not exist — already virgin.
        }

        // Dropping the user voids the authentication of every pooled connection in the cached
        // repository clients (they then fail with "requires authentication" even after the user is
        // re-created — AB#4690), so the cache must be rebuilt for the next test.
        var systemContext = _fixture.GetSystemContext();
        await systemContext.InvalidateTenantRepositoryClientsAsync(systemContext.TenantId,
            Configuration.SystemDatabaseName, TestContext.Current.CancellationToken);
    }

    private MongoClient CreateAdminClient()
    {
        var config = Configuration;
        var urlBuilder = new MongoUrlBuilder
        {
            Server = new MongoServerAddress(config.DatabaseHost),
            Username = config.AdminUser,
            Password = config.AdminUserPassword,
            AuthenticationSource = config.AuthenticationDatabaseName,
            DatabaseName = config.AuthenticationDatabaseName,
            DirectConnection = config.UseDirectConnection
        };

        return new MongoClient(urlBuilder.ToMongoUrl());
    }

    private async Task<bool> IsSystemDatabaseUserExistingAsync()
    {
        var config = Configuration;
        var userName = string.Format(config.DatabaseUser, config.SystemDatabaseName);
        var authDatabase = CreateAdminClient().GetDatabase(config.AuthenticationDatabaseName);

        var result = await authDatabase.RunCommandAsync<BsonDocument>(
            new BsonDocumentCommand<BsonDocument>(new BsonDocument("usersInfo", userName)));

        return result.GetValue("ok", 0).ToDouble() > 0
               && result.GetValue("users", new BsonArray()).AsBsonArray.Count > 0;
    }
}
