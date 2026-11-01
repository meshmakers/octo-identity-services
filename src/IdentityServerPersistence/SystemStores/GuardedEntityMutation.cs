using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     One version-checked read-modify-write of a stored entity (AB#7989): read it in a transaction, apply the change and
///     replace it with the <c>rtVersion</c> that was read. When another writer was in between, the engine refuses the replace
///     (<see cref="RtVersionConflictException" />), nothing is written, and the step reads again and re-applies the change.
///     So a concurrent write that read the entity earlier can never bring back a secret another request removed.
/// </summary>
internal static class GuardedEntityMutation
{
    /// <summary>Attempts before the <see cref="RtVersionConflictException" /> reaches the caller.</summary>
    internal const int MaxConcurrencyAttempts = 20;

    /// <summary>
    ///     Runs the step. <paramref name="mutate" /> returns <c>false</c> to write nothing; it can run more than once and must
    ///     derive everything from its argument.
    /// </summary>
    /// <returns>The entity as stored after the step and whether it was written; <c>null</c> when it does not exist.</returns>
    internal static async Task<(TEntity Entity, bool Written)?> MutateAsync<TEntity>(ITenantRepository repository,
        Func<IOctoSession, Task<TEntity?>> read, Func<TEntity, bool> mutate)
        where TEntity : RtEntity, new()
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await MongoWriteRetry.ExecuteTransactionWithRetryAsync(async () =>
                {
                    using var session = await repository.GetSessionAsync().ConfigureAwait(false);
                    session.StartTransaction();
                    try
                    {
                        var current = await read(session).ConfigureAwait(false);
                        if (current == null)
                        {
                            await session.AbortTransactionAsync().ConfigureAwait(false);
                            return ((TEntity, bool)?)null;
                        }

                        var readVersion = current.RtVersion;
                        var write = mutate(current);
                        if (write)
                        {
                            await repository.ReplaceOneRtEntityByIdAsync(session, current.RtId, current, readVersion)
                                .ConfigureAwait(false);
                        }

                        await session.CommitTransactionAsync().ConfigureAwait(false);
                        return (current, write);
                    }
                    catch
                    {
                        try
                        {
                            await session.AbortTransactionAsync().ConfigureAwait(false);
                        }
                        catch (Exception)
                        {
                            // The transaction is gone already; the original exception is what matters.
                        }

                        throw;
                    }
                }, MaxConcurrencyAttempts).ConfigureAwait(false);
            }
            catch (RtVersionConflictException) when (attempt < MaxConcurrencyAttempts)
            {
                // Another writer was faster: nothing was written, read again and re-apply.
            }

            await Task.Delay(Random.Shared.Next(1, 4 * attempt + 1)).ConfigureAwait(false);
        }
    }
}
