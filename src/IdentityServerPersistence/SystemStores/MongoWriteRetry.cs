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
internal static class MongoWriteRetry
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
}
