using FluentAssertions;
using IdentityServices.IntegrationTests.Fixtures;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     A disposed fixture leaves none of its databases in the shared MongoDB container, and no database of anybody else is
///     touched (<see cref="FixtureDatabaseCleanup" />).
/// </summary>
/// <remarks>
///     Without the cleanup every finished test class left its system database and the databases of all tenants it created
///     in the one mongod of the run (several hundred databases at the end), which slowed every later tenant setup down.
///     Asserted on the server (<c>listDatabases</c>), not on the cleanup's own bookkeeping. Builds and disposes its own
///     fixtures, independent of the shared ones.
/// </remarks>
public class FixtureDatabaseCleanupTests
{
    private static readonly TimeSpan DropTimeout = TimeSpan.FromSeconds(60);

    [Fact]
    public async Task ADisposedIdentityFixture_DropsItsSystemDatabaseAndTheDatabasesOfItsTenants()
    {
        var fixture = new IdentityServicesFixture();
        var bystander = $"cleanupbystander{Guid.NewGuid():N}"[..30];
        string systemDatabase;
        string testTenantDatabase;
        string childOfChildDatabase;
        try
        {
            await fixture.InitializeAsync();
            systemDatabase = fixture.SystemDatabaseName;
            testTenantDatabase = fixture.TestTenantId;

            // A tenant below the fixture's test tenant: the system registry names it too, so it must go as well.
            childOfChildDatabase = $"cleanupchild{Guid.NewGuid():N}"[..24];
            var testTenant = await fixture.GetTestTenantContextAsync();
            using (var session = await fixture.GetSystemContext().GetAdminSessionAsync())
            {
                session.StartTransaction();
                await testTenant.CreateChildTenantAsync(session, childOfChildDatabase, childOfChildDatabase);
                await session.CommitTransactionAsync();
            }

            // A database nobody of this fixture owns, as another fixture running in parallel would have one.
            await AdminClient().GetDatabase(bystander).GetCollection<BsonDocument>("marker")
                .InsertOneAsync(new BsonDocument("owner", "another fixture"),
                    cancellationToken: TestContext.Current.CancellationToken);

            var before = await ListDatabasesAsync();
            before.Should().Contain([systemDatabase, testTenantDatabase, childOfChildDatabase, bystander],
                "the probe must see the databases first, otherwise the drop check below is vacuous");
        }
        catch
        {
            await fixture.DisposeAsync();
            await AdminClient().DropDatabaseAsync(bystander, CancellationToken.None);
            throw;
        }

        await fixture.DisposeAsync();

        try
        {
            var after = await WaitUntilGoneAsync(systemDatabase, testTenantDatabase, childOfChildDatabase);
            after.Should().NotContain([systemDatabase, testTenantDatabase, childOfChildDatabase]);
            after.Should().Contain(bystander, "a fixture drops only the databases its own registry names");
        }
        finally
        {
            await AdminClient().DropDatabaseAsync(bystander, CancellationToken.None);
        }
    }

    [Fact]
    public async Task ADisposedWebFactory_DropsItsSystemDatabase()
    {
        var factory = new CustomWebApplicationFactory();
        string systemDatabase;
        try
        {
            await factory.InitializeAsync();
            systemDatabase = factory.SystemDatabaseName;
            (await ListDatabasesAsync()).Should().Contain(systemDatabase,
                "the probe must see the system database first, otherwise the drop check below is vacuous");
        }
        catch
        {
            await factory.DisposeAsync();
            throw;
        }

        await factory.DisposeAsync();

        (await WaitUntilGoneAsync(systemDatabase)).Should().NotContain(systemDatabase);
    }

    /// <summary>
    ///     The drop runs in the background after the dispose (it must not hold up the test thread), so the check waits for
    ///     it, bounded. Returns the last database list read.
    /// </summary>
    private static async Task<List<string>> WaitUntilGoneAsync(params string[] databases)
    {
        var deadline = DateTime.UtcNow + DropTimeout;
        while (true)
        {
            var names = await ListDatabasesAsync();
            if (!names.Intersect(databases).Any() || DateTime.UtcNow >= deadline)
            {
                return names;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), TestContext.Current.CancellationToken);
        }
    }

    private static IMongoClient AdminClient()
    {
        return SharedMongoDbContainer.TryGetAdminClient()
               ?? throw new InvalidOperationException("The shared MongoDB container has not been started.");
    }

    private static async Task<List<string>> ListDatabasesAsync()
    {
        using var cursor = await AdminClient().ListDatabaseNamesAsync(TestContext.Current.CancellationToken);
        return await cursor.ToListAsync(TestContext.Current.CancellationToken);
    }
}
