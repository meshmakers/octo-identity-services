using System.Collections.Concurrent;
using System.Diagnostics;
using MongoDB.Bson;
using MongoDB.Driver;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     Drops the databases of one fixture from the shared MongoDB container when the fixture is disposed: its system
///     database and every tenant database its tenant registry names.
/// </summary>
/// <remarks>
///     <para>
///         Every class fixture (<see cref="DatabaseFixture" />, <c>CustomWebApplicationFactory</c>) creates its own system
///         database, and many tests create child tenants on top, each with a database of about 45 collections and their
///         indexes. Without this cleanup all of them stayed in the one shared mongod until the end of the run: a full run
///         ends with several hundred databases and about 100,000 WiredTiger files (one per collection and index).
///         Every new tenant setup then creates its collections and indexes against that growing file set; on a CI agent
///         the index builds and majority commits of the later tenant setups stalled for minutes and the tests ended with
///         <see cref="OperationCanceledException" /> from the CK import. Dropping the databases of a fixture as soon as
///         its tests are done keeps the server at the databases of the fixtures that are alive.
///     </para>
///     <para>
///         The registry is the <c>RtEntity_SystemTenant</c> collection of the system database: the system database is
///         the routing registry of the installation and holds a row for every tenant, children of child tenants
///         included. Database names are unique per fixture (GUID-suffixed), so a drop never reaches a database another
///         fixture uses. The cleanup never throws: a failed drop is reported on the console and leaves the database to
///         the end of the run, as before.
///     </para>
/// </remarks>
internal static class FixtureDatabaseCleanup
{
    /// <summary>Collection of the tenant registry rows in a system database.</summary>
    internal const string TenantRegistryCollection = "RtEntity_SystemTenant";

    /// <summary>Time budget of one fixture's cleanup; a drop still waiting after it is abandoned.</summary>
    private static readonly TimeSpan Budget = TimeSpan.FromMinutes(5);

    private static readonly CancellationTokenSource StopAll = new();
    private static readonly ConcurrentDictionary<Task, string> Pending = new();

    private static readonly HashSet<string> ServerDatabases = new(StringComparer.Ordinal)
    {
        "admin", "local", "config"
    };

    /// <summary>
    ///     Names of the databases that belong to the fixture with the given system database: the system database itself
    ///     and every database its tenant registry names, server databases excluded, each name once.
    /// </summary>
    internal static async Task<IReadOnlyList<string>> GetFixtureDatabasesAsync(IMongoClient client,
        string systemDatabaseName, CancellationToken cancellationToken)
    {
        var names = new List<string> { systemDatabaseName };

        var registry = client.GetDatabase(systemDatabaseName)
            .GetCollection<BsonDocument>(TenantRegistryCollection);
        var rows = await registry
            .Find(FilterDefinition<BsonDocument>.Empty)
            .Project(Builders<BsonDocument>.Projection.Include("attributes.databaseName"))
            .ToListAsync(cancellationToken);

        foreach (var row in rows)
        {
            if (row.TryGetValue("attributes", out var attributes)
                && attributes is BsonDocument attributeDocument
                && attributeDocument.TryGetValue("databaseName", out var databaseName)
                && databaseName.IsString
                && !string.IsNullOrWhiteSpace(databaseName.AsString))
            {
                names.Add(databaseName.AsString);
            }
        }

        return names
            .Where(name => !ServerDatabases.Contains(name))
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    ///     Starts the drop of the system database <paramref name="systemDatabaseName" /> and every tenant database its
    ///     registry names in the background and returns at once. Call it after every host and service provider of the
    ///     fixture is disposed. The returned task never faults; callers do not await it (a drop that waits for a lock must
    ///     not hold up the test thread), only tests that check the cleanup do.
    /// </summary>
    public static Task ScheduleDropOfFixtureDatabases(string systemDatabaseName)
    {
        var client = SharedMongoDbContainer.TryGetAdminClient();
        if (client == null)
        {
            // The fixture never reached the container (failed initialisation): nothing of it is on the server.
            return Task.CompletedTask;
        }

        var drop = Task.Run(() => DropAsync(client, systemDatabaseName, StopAll.Token));
        Pending[drop] = systemDatabaseName;
        _ = drop.ContinueWith(finished => Pending.TryRemove(finished, out _), TaskScheduler.Default);
        return drop;
    }

    /// <summary>
    ///     Stops the drops still running when the shared container is disposed: the container goes away with every
    ///     database in it, so finishing them buys nothing. Waits at most a few seconds for them to observe it.
    /// </summary>
    internal static async Task AbandonPendingDropsAsync()
    {
        await StopAll.CancelAsync();
        await Task.WhenAny(Task.WhenAll(Pending.Keys), Task.Delay(TimeSpan.FromSeconds(5)));
    }

    private static async Task DropAsync(IMongoClient client, string systemDatabaseName,
        CancellationToken stopAll)
    {
        var stopwatch = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(stopAll);
        cts.CancelAfter(Budget);
        var dropped = 0;
        try
        {
            var databases = await GetFixtureDatabasesAsync(client, systemDatabaseName, cts.Token);
            foreach (var database in databases)
            {
                await client.DropDatabaseAsync(database, cts.Token);
                dropped++;
            }

            Console.WriteLine(
                $"[Testcontainers] Dropped {dropped} database(s) of fixture database '{systemDatabaseName}' in {stopwatch.Elapsed.TotalSeconds:F1}s");
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"[Testcontainers] Cleanup of fixture database '{systemDatabaseName}' stopped after {dropped} drop(s) and {stopwatch.Elapsed.TotalSeconds:F1}s: {ex.GetType().Name}: {ex.Message}");
        }
    }
}
