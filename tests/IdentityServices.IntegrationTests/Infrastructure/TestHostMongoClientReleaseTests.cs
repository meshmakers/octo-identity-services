using FluentAssertions;
using IdentityServices.IntegrationTests.Fixtures;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     AB#8424: a disposed in-process test host leaves no MongoDB connection behind.
/// </summary>
/// <remarks>
///     <para>
///         Every repository client of the runtime engine is a MongoDB driver cluster of its own (own application name),
///         with a heartbeat thread, an RTT monitor thread and a pool maintenance thread. The suite builds ~300 hosts. When
///         a host's clients are not released on dispose, the threads and sockets of every host ever built stay alive: the
///         test process grew to 3,000-4,600 threads (workstation GC allocation lock contention, GC pause ~60 %), the shared
///         MongoDB container to ~7 GB, and the suite never finished on a developer Mac (Mongo transaction aborts,
///         server-selection timeouts and canceled operations in unrelated classes). The release lives in
///         <c>Meshmakers.Octo.Runtime.Engine.MongoDb</c> since AB#8281 (engine-mongodb #229, 2026-11-05):
///         <c>Admin/UserRepositoryAccess</c> dispose every client they built, and a client unregisters its cluster.
///     </para>
///     <para>
///         The local failure was a stale <c>../nuget</c> feed: DebugL resolves 999.0.0 from it, and a package built
///         before AB#8281 still leaks every cluster while CI (feed built from main) does not. This test makes that
///         visible in seconds instead of a run that never ends. Red here means: rebuild the library chain into the
///         DebugL feed (<c>Invoke-BuildRange</c> from <c>octo-construction-kit-engine-mongodb</c>), or a new singleton of
///         this service holds a MongoDB client that its DI container does not dispose.
///     </para>
///     <para>
///         Asserted on the server (<c>$currentOp</c> with idle connections, filtered by the host's unique system database
///         name, which every application name of its repository clients contains), not through driver internals. Own
///         collection: it builds and disposes its own host, independent of the shared web factory.
///     </para>
/// </remarks>
public class TestHostMongoClientReleaseTests
{
    private static readonly TimeSpan ReleaseTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task ADisposedTestHost_LeavesNoMongoDbConnection()
    {
        var factory = new CustomWebApplicationFactory();
        string databaseName;
        try
        {
            await factory.InitializeAsync();
            databaseName = factory.SystemDatabaseName;

            // Starts the host: its startup (migrations, CK cache, system tenant) opens the repository clients.
            using (var client = factory.CreateClient())
            {
                using var response = await client.GetAsync("/.well-known/openid-configuration",
                    TestContext.Current.CancellationToken);
            }

            (await CountConnectionsAsync(databaseName)).Should().BePositive(
                "the probe must see the running host's connections, otherwise the release check below is vacuous");
        }
        finally
        {
            await factory.DisposeAsync();
        }

        var deadline = DateTime.UtcNow + ReleaseTimeout;
        int remaining;
        while ((remaining = await CountConnectionsAsync(databaseName)) > 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        remaining.Should().Be(0,
            "a disposed host must close the MongoDB clusters of all its repository clients (AB#8281). If this fails " +
            "locally, the Meshmakers.Octo.Runtime.Engine.MongoDb package in the DebugL feed (../nuget) predates AB#8281 " +
            "and the full suite will starve on driver threads (AB#8424): rebuild the library chain into the feed");
    }

    /// <summary>
    ///     Counts the server connections (active and idle) whose application name contains <paramref name="databaseName" />.
    /// </summary>
    private static async Task<int> CountConnectionsAsync(string databaseName)
    {
        var url = new MongoUrlBuilder(SharedMongoDbContainer.ConnectionString)
        {
            DirectConnection = true,
            ApplicationName = $"ab8424-probe-{Guid.NewGuid():N}"
        }.ToMongoUrl();

        // The probe must not leak what it measures: MongoClient.Dispose alone keeps the cluster registered (driver 3.x).
        var probe = new MongoClient(url);
        try
        {
            var pipeline = new[]
            {
                new BsonDocument("$currentOp", new BsonDocument { { "allUsers", true }, { "idleConnections", true } }),
                new BsonDocument("$match",
                    new BsonDocument("appName", new BsonDocument("$regex", System.Text.RegularExpressions.Regex.Escape(databaseName)))),
                new BsonDocument("$count", "n")
            };

            using var cursor = await probe.GetDatabase("admin")
                .AggregateAsync<BsonDocument>(pipeline);
            var result = await cursor.FirstOrDefaultAsync();
            return result?["n"].ToInt32() ?? 0;
        }
        finally
        {
            MongoDB.Driver.ClusterRegistry.Instance.UnregisterAndDisposeCluster(probe.Cluster);
            probe.Dispose();
        }
    }
}
