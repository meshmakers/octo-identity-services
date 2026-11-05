using NLog;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Shared retry helper for MongoDB multi-document transaction write conflicts.
/// </summary>
/// <remarks>
///     When multiple tabs renew sessions or refresh tokens simultaneously, their transactions
///     can collide on the same document. MongoDB recommends retrying on transient write
///     conflicts.
/// </remarks>
public static class MongoWriteRetry
{
    private const int MaxRetryAttempts = 3;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    /// <summary>
    ///     Executes <paramref name="action" /> with retry logic for MongoDB write conflicts.
    ///     When multiple tabs renew sessions or refresh tokens simultaneously, their transactions
    ///     can collide on the same document. MongoDB recommends retrying on transient write conflicts.
    /// </summary>
    public static async Task ExecuteWithRetryAsync(Func<Task> action)
    {
        for (var attempt = 1; attempt <= MaxRetryAttempts; attempt++)
        {
            try
            {
                await action();
                return;
            }
            catch (MongoDB.Driver.MongoCommandException ex) when (
                attempt < MaxRetryAttempts &&
                ex.Message.Contains("Write conflict", StringComparison.OrdinalIgnoreCase))
            {
                Logger.Warn("Write conflict on store attempt {Attempt}/{MaxAttempts}, retrying",
                    attempt, MaxRetryAttempts);
                await Task.Delay(50 * attempt); // 50ms, 100ms backoff
            }
        }
    }

    /// <summary>
    ///     Runs <paramref name="action" /> (one complete transaction: read, change, write, commit) again while it fails
    ///     with a write conflict, up to <paramref name="maxAttempts" /> times with a jittered back-off (AB#7854).
    /// </summary>
    /// <remarks>
    ///     Meant for read-modify-write of a hot document under contention, e.g. many parallel sign-in attempts of one
    ///     user: the read inside the transaction sees a snapshot, and MongoDB refuses the write when another transaction
    ///     changed the document after that snapshot. Each retry therefore re-reads the current state; nothing is lost.
    ///     The jitter keeps the losers of one round from colliding again in the next.
    /// </remarks>
    public static async Task<T> ExecuteTransactionWithRetryAsync<T>(Func<Task<T>> action, int maxAttempts,
        CancellationToken cancellationToken = default)
    {
        for (var attempt = 1;; attempt++)
        {
            try
            {
                return await action();
            }
            catch (Exception ex) when (attempt < maxAttempts && IsWriteConflict(ex))
            {
                Logger.Debug("Write conflict on attempt {Attempt}/{MaxAttempts}, retrying", attempt, maxAttempts);
                await Task.Delay(Random.Shared.Next(5, 10 + 15 * Math.Min(attempt, 10)), cancellationToken);
            }
        }
    }

    /// <summary>
    ///     <c>true</c> when <paramref name="exception" /> (or an inner exception) is a MongoDB write conflict or another
    ///     transient transaction error that a retry of the whole transaction resolves.
    /// </summary>
    public static bool IsWriteConflict(Exception exception)
    {
        for (var ex = exception; ex != null; ex = ex.InnerException)
        {
            switch (ex)
            {
                case MongoDB.Driver.MongoException mongo when mongo.HasErrorLabel("TransientTransactionError"):
                case MongoDB.Driver.MongoCommandException { Code: 112 }:
                    return true;
            }

            if (ex.Message.Contains("Write conflict", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
