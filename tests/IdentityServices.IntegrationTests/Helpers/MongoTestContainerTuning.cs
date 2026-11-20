using MongoDB.Bson;
using MongoDB.Driver;

namespace IdentityServices.IntegrationTests.Helpers;

/// <summary>
///     Server-side tuning applied to a freshly started MongoDB Testcontainer, before any fixture work runs
///     against it (AB#5160).
/// </summary>
public static class MongoTestContainerTuning
{
    /// <summary>
    ///     mongod's default <c>transactionLifetimeLimitSeconds</c> is 60. The tenant setup
    ///     (<c>CreateSystemTenantAsync</c> / <c>SetupAsync</c> — CK-model import plus the baseline resource
    ///     provisioning) runs inside a single Mongo transaction and takes a large fraction of that on a
    ///     quiet machine. Sharing one container across a whole collection means those setups now compete
    ///     with the accumulated data of every sibling class, and under CI load the transaction reaches the
    ///     limit and the run dies with <c>commitTransaction ... has been aborted</c> — sporadically, which
    ///     is the worst kind. Five minutes is generous enough that the limit stops being a source of noise
    ///     while still bounding a genuinely stuck transaction.
    /// </summary>
    public const int TransactionLifetimeLimitSeconds = 300;

    private static MongoClient CreateAdminClient(string databaseHost, string adminUser, string adminUserPassword)
    {
        var urlBuilder = new MongoUrlBuilder
        {
            Server = MongoServerAddress.Parse(databaseHost),
            Username = adminUser,
            Password = adminUserPassword,
            AuthenticationSource = "admin",
            DirectConnection = true
        };

        return new MongoClient(urlBuilder.ToMongoUrl());
    }

    /// <summary>
    ///     Sets <c>writeConcernMajorityJournalDefault: false</c> in the replica-set configuration of the one-node
    ///     test replica set, so a majority-acknowledged write (every transaction commit of the tenant
    ///     setup) no longer waits for the journal to be flushed to disk. Test data only: a crash may lose the
    ///     last moments of writes. Call directly after <c>StartAsync</c>, before the first tenant is provisioned.
    /// </summary>
    public static async Task RelaxMajorityJournalDurabilityAsync(
        string databaseHost, string adminUser, string adminUserPassword)
    {
        using var client = CreateAdminClient(databaseHost, adminUser, adminUserPassword);
        var admin = client.GetDatabase("admin");

        // The reconfig needs a writable primary; the container may report ready a moment before the one node has
        // won its election.
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            var hello = await admin.RunCommandAsync<BsonDocument>(
                new BsonDocumentCommand<BsonDocument>(new BsonDocument("hello", 1)));
            if (hello.GetValue("isWritablePrimary", false).ToBoolean())
            {
                break;
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("The test MongoDB did not become a writable primary within 30 s.");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500));
        }

        var current = await admin.RunCommandAsync<BsonDocument>(
            new BsonDocumentCommand<BsonDocument>(new BsonDocument("replSetGetConfig", 1)));
        var config = current["config"].AsBsonDocument;
        config["writeConcernMajorityJournalDefault"] = false;
        config["version"] = config["version"].ToInt32() + 1;

        await admin.RunCommandAsync<BsonDocument>(
            new BsonDocumentCommand<BsonDocument>(new BsonDocument("replSetReconfig", config)));
    }

    /// <summary>
    ///     Raises <see cref="TransactionLifetimeLimitSeconds" /> on the running container. Call this
    ///     directly after <c>StartAsync</c> and before the first tenant is provisioned.
    /// </summary>
    public static async Task RaiseTransactionLifetimeLimitAsync(
        string databaseHost, string adminUser, string adminUserPassword)
    {
        using var adminClient = CreateAdminClient(databaseHost, adminUser, adminUserPassword);
        var command = new BsonDocument
        {
            { "setParameter", 1 },
            { "transactionLifetimeLimitSeconds", TransactionLifetimeLimitSeconds }
        };

        await adminClient.GetDatabase("admin")
            .RunCommandAsync<BsonDocument>(new BsonDocumentCommand<BsonDocument>(command));
    }
}
