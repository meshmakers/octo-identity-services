using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Failure counting and lockout as one atomic step on the stored user (AB#7854).
/// </summary>
/// <remarks>
///     The framework's <c>UserManager.AccessFailedAsync</c> increments the counter on the caller's in-memory copy and
///     writes the whole document back — last write wins, so N parallel wrong attempts raised the counter by about one.
///     <see cref="OctoUserManager" /> calls this store instead; the arithmetic is the framework's.
/// </remarks>
public interface IAtomicUserLockoutStore
{
    /// <summary>
    ///     Counts one failed attempt on the stored user and sets the lockout when the count reaches
    ///     <paramref name="maxFailedAccessAttempts" /> (then the count restarts at 0) — in one transaction, retried on write
    ///     conflicts. The caller's <paramref name="user" /> copy receives the stored counter and lockout end.
    /// </summary>
    /// <returns><c>true</c> when this failure set the lockout.</returns>
    Task<bool> RecordAccessFailureAsync(RtUser user, int maxFailedAccessAttempts, TimeSpan lockoutTimeSpan,
        CancellationToken cancellationToken = default);

    /// <summary>
    ///     Resets the stored counter to 0 (whatever the caller's copy believes) and updates the caller's copy.
    /// </summary>
    Task ResetAccessFailedCountAtomicallyAsync(RtUser user, CancellationToken cancellationToken = default);
}

public sealed partial class OctoUserStore
{
    /// <summary>
    ///     Attempts of one atomic update. Each failed attempt means another transaction changed the user in between, so
    ///     the budget only runs out under extreme contention — the per-account sign-in limit keeps it far away.
    /// </summary>
    private const int MaxAtomicUpdateAttempts = 25;

    public async Task<bool> RecordAccessFailureAsync(RtUser user, int maxFailedAccessAttempts,
        TimeSpan lockoutTimeSpan, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        var (stored, lockedOut) = await RecordAccessFailureAsync(TenantRepository, user.RtId, maxFailedAccessAttempts,
            lockoutTimeSpan, cancellationToken).ConfigureAwait(false);
        if (stored != null)
        {
            user.AccessFailedCount = stored.AccessFailedCount;
            user.LockoutEnd = stored.LockoutEnd;
        }

        return lockedOut;
    }

    public async Task ResetAccessFailedCountAtomicallyAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        await ResetAccessFailedCountAsync(TenantRepository, user.RtId, cancellationToken).ConfigureAwait(false);
        user.AccessFailedCount = 0;
    }

    /// <summary>
    ///     <see cref="RecordAccessFailureAsync(RtUser,int,TimeSpan,CancellationToken)" /> against an explicit tenant
    ///     repository — for callers that verify a user of another tenant (cross-tenant password login).
    /// </summary>
    /// <returns>The stored user after the update (<c>null</c> when it does not exist) and whether it was locked out now.</returns>
    public static async Task<(RtUser? User, bool LockedOut)> RecordAccessFailureAsync(ITenantRepository repository,
        OctoObjectId userId, int maxFailedAccessAttempts, TimeSpan lockoutTimeSpan,
        CancellationToken cancellationToken = default)
    {
        var lockedOut = false;
        var stored = await MutateUserAtomicallyAsync(repository, userId, current =>
        {
            // Framework arithmetic (UserManager.AccessFailedAsync): count; at the threshold set the lockout end and
            // restart the count.
            lockedOut = false;
            current.AccessFailedCount++;
            if (current.AccessFailedCount >= maxFailedAccessAttempts)
            {
                current.LockoutEnd = DateTimeOffset.UtcNow.Add(lockoutTimeSpan);
                current.AccessFailedCount = 0;
                lockedOut = true;
            }

            return true;
        }, cancellationToken).ConfigureAwait(false);

        return (stored, lockedOut);
    }

    /// <summary>Resets the stored failure count of a user of an explicit tenant repository.</summary>
    public static Task<RtUser?> ResetAccessFailedCountAsync(ITenantRepository repository, OctoObjectId userId,
        CancellationToken cancellationToken = default)
        => MutateUserAtomicallyAsync(repository, userId, current =>
        {
            if (current.AccessFailedCount == 0)
            {
                return false;
            }

            current.AccessFailedCount = 0;
            return true;
        }, cancellationToken);

    private async Task<bool> RedeemCodeAtomicallyAsync(RtUser user, string code, CancellationToken cancellationToken)
    {
        var redeemed = false;
        var stored = await MutateUserAtomicallyAsync(TenantRepository, user.RtId, current =>
        {
            redeemed = false;
            var token = current.UserTokens?.FirstOrDefault(x =>
                x.LoginProvider == InternalLoginProvider && x.Name == RecoveryCodeTokenName);
            var codes = token?.Value?.Split(';');
            if (token == null || codes == null || !codes.Contains(code))
            {
                return false;
            }

            var remaining = codes.Where(c => c != code).ToArray();
            if (remaining.Length == 0)
            {
                // Same as ReplaceCodesAsync -> SetTokenAsync with an empty value: the token is removed.
                current.UserTokens!.RemoveAll(x =>
                    x.LoginProvider == InternalLoginProvider && x.Name == RecoveryCodeTokenName);
            }
            else
            {
                // Assign through the indexer (as SetTokenAsync does): an in-place change of the record is not persisted.
                token.Value = string.Join(";", remaining);
                var index = current.UserTokens!.FindIndex(x =>
                    x.LoginProvider == InternalLoginProvider && x.Name == RecoveryCodeTokenName);
                current.UserTokens[index] = token;
            }

            redeemed = true;
            return true;
        }, cancellationToken).ConfigureAwait(false);

        if (stored != null)
        {
            user.UserTokens = stored.UserTokens ?? new AttributeRecordValueList<RtUserTokenRecord>();
        }

        return redeemed;
    }

    /// <summary>
    ///     Reads the stored user and writes <paramref name="mutate" />'s change back inside ONE transaction; a write conflict
    ///     (another transaction changed the user after this one read it) re-runs the whole step on the fresh state.
    ///     <paramref name="mutate" /> returns <c>false</c> to write nothing; it must derive everything from its argument,
    ///     because it can run more than once.
    /// </summary>
    /// <returns>The stored user after the step, or <c>null</c> when it does not exist.</returns>
    private static Task<RtUser?> MutateUserAtomicallyAsync(ITenantRepository repository, OctoObjectId userId,
        Func<RtUser, bool> mutate, CancellationToken cancellationToken)
        => MongoWriteRetry.ExecuteTransactionWithRetryAsync(async () =>
        {
            using var session = await repository.GetSessionAsync().ConfigureAwait(false);
            session.StartTransaction();
            try
            {
                var current = await repository.GetRtEntityByRtIdAsync<RtUser>(session, userId).ConfigureAwait(false);
                if (current == null)
                {
                    await session.AbortTransactionAsync().ConfigureAwait(false);
                    return null;
                }

                if (mutate(current))
                {
                    await repository.ReplaceOneRtEntityByIdAsync(session, current.RtId, current).ConfigureAwait(false);
                }

                await session.CommitTransactionAsync().ConfigureAwait(false);
                return current;
            }
            catch
            {
                await TryAbortAsync(session).ConfigureAwait(false);
                throw;
            }
        }, MaxAtomicUpdateAttempts, cancellationToken);

    private static async Task TryAbortAsync(Meshmakers.Octo.Runtime.Contracts.IOctoSession session)
    {
        try
        {
            await session.AbortTransactionAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The transaction is already aborted (or the session is gone); the original exception is what matters.
        }
    }
}
