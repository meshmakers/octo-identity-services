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

    /// <summary>
    ///     Raises <see cref="TransactionLifetimeLimitSeconds" /> on the running container. Call this
    ///     directly after <c>StartAsync</c> and before the first tenant is provisioned.
    /// </summary>
    public static async Task RaiseTransactionLifetimeLimitAsync(
        string databaseHost, string adminUser, string adminUserPassword)
    {
        var urlBuilder = new MongoUrlBuilder
        {
            Server = MongoServerAddress.Parse(databaseHost),
            Username = adminUser,
            Password = adminUserPassword,
            AuthenticationSource = "admin",
            DirectConnection = true
        };

        var adminClient = new MongoClient(urlBuilder.ToMongoUrl());
        var command = new BsonDocument
        {
            { "setParameter", 1 },
            { "transactionLifetimeLimitSeconds", TransactionLifetimeLimitSeconds }
        };

        await adminClient.GetDatabase("admin")
            .RunCommandAsync<BsonDocument>(new BsonDocumentCommand<BsonDocument>(command));
    }
}
