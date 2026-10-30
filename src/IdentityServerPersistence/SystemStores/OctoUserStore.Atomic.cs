using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
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
    ///     Attempts of one MongoDB transaction that met a write conflict (see <see cref="MongoWriteRetry" />). Attempts for
    ///     a version conflict are <see cref="MaxConcurrencyAttempts" />.
    /// </summary>
    private const int MaxAtomicUpdateAttempts = 25;

    public async Task<bool> RecordAccessFailureAsync(RtUser user, int maxFailedAccessAttempts,
        TimeSpan lockoutTimeSpan, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        var (outcome, lockedOut) = await RecordAccessFailureCoreAsync(TenantRepository, user.RtId,
            maxFailedAccessAttempts, lockoutTimeSpan, cancellationToken).ConfigureAwait(false);
        if (outcome != null)
        {
            AdoptStoredLockoutState(user, outcome);
        }

        return lockedOut;
    }

    public async Task ResetAccessFailedCountAtomicallyAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        var outcome = await ResetAccessFailedCountCoreAsync(TenantRepository, user.RtId, cancellationToken)
            .ConfigureAwait(false);
        user.AccessFailedCount = 0;
        if (outcome != null)
        {
            AdoptStoredLockoutState(user, outcome);
        }
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
        var (outcome, lockedOut) = await RecordAccessFailureCoreAsync(repository, userId, maxFailedAccessAttempts,
            lockoutTimeSpan, cancellationToken).ConfigureAwait(false);
        return (outcome?.User, lockedOut);
    }

    private static async Task<(StoredUserMutation? Outcome, bool LockedOut)> RecordAccessFailureCoreAsync(
        ITenantRepository repository, OctoObjectId userId, int maxFailedAccessAttempts, TimeSpan lockoutTimeSpan,
        CancellationToken cancellationToken)
    {
        var lockedOut = false;
        var stored = await MutateUserGuardedAsync(repository, userId, current =>
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
        }, MaxConcurrencyAttempts, cancellationToken).ConfigureAwait(false);

        return (stored, lockedOut);
    }

    /// <summary>Resets the stored failure count of a user of an explicit tenant repository.</summary>
    public static async Task<RtUser?> ResetAccessFailedCountAsync(ITenantRepository repository, OctoObjectId userId,
        CancellationToken cancellationToken = default)
        => (await ResetAccessFailedCountCoreAsync(repository, userId, cancellationToken).ConfigureAwait(false))?.User;

    private static Task<StoredUserMutation?> ResetAccessFailedCountCoreAsync(ITenantRepository repository,
        OctoObjectId userId, CancellationToken cancellationToken)
        => MutateUserGuardedAsync(repository, userId, current =>
        {
            if (current.AccessFailedCount == 0)
            {
                return false;
            }

            current.AccessFailedCount = 0;
            return true;
        }, MaxConcurrencyAttempts, cancellationToken);

    private async Task<bool> RedeemCodeAtomicallyAsync(RtUser user, string code, CancellationToken cancellationToken)
    {
        var redeemed = false;
        var stored = await MutateUserGuardedAsync(TenantRepository, user.RtId, current =>
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
        }, MaxConcurrencyAttempts, cancellationToken).ConfigureAwait(false);

        if (stored != null)
        {
            user.UserTokens = stored.User.UserTokens ?? new AttributeRecordValueList<RtUserTokenRecord>();
            AdoptStoredVersion(user, stored);
        }

        return redeemed;
    }

    /// <summary>
    ///     The one read-modify-write of the stored user (AB#7770, AB#7908). It reads the user, applies
    ///     <paramref name="mutate" /> and writes it back inside one transaction only if no other writer changed it since
    ///     (expected <c>rtVersion</c>, AB#7769): every write advances <c>rtVersion</c>, so a stale
    ///     <see cref="UpdateAsync" /> that read the user before this write is reported as a concurrency failure instead of
    ///     overwriting it. A <see cref="RtVersionConflictException" /> re-reads and re-applies the change (bounded by
    ///     <paramref name="maxAttempts" />); a MongoDB write conflict is retried inside the transaction by
    ///     <see cref="MongoWriteRetry" />. <paramref name="mutate" /> returns <c>false</c> to write nothing and must derive
    ///     everything from its argument, because it can run more than once.
    /// </summary>
    /// <returns>
    ///     The user as stored after the step (its <c>RtVersion</c> is the new version) with the version that was read, or
    ///     <c>null</c> when the user does not exist.
    /// </returns>
    private static async Task<StoredUserMutation?> MutateUserGuardedAsync(ITenantRepository repository,
        OctoObjectId userId, Func<RtUser, bool> mutate, int maxAttempts, CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await MongoWriteRetry.ExecuteTransactionWithRetryAsync(async () =>
                {
                    using var session = await repository.GetSessionAsync().ConfigureAwait(false);
                    session.StartTransaction();
                    try
                    {
                        var current = await repository.GetRtEntityByRtIdAsync<RtUser>(session, userId)
                            .ConfigureAwait(false);
                        if (current == null)
                        {
                            await session.AbortTransactionAsync().ConfigureAwait(false);
                            return null;
                        }

                        var readVersion = current.RtVersion;
                        if (mutate(current))
                        {
                            await repository.ReplaceOneRtEntityByIdAsync(session, current.RtId, current, readVersion)
                                .ConfigureAwait(false);
                        }

                        await session.CommitTransactionAsync().ConfigureAwait(false);
                        return new StoredUserMutation(current, readVersion);
                    }
                    catch
                    {
                        await TryAbortAsync(session).ConfigureAwait(false);
                        throw;
                    }
                }, MaxConcurrencyAttempts, cancellationToken).ConfigureAwait(false);
            }
            catch (RtVersionConflictException) when (attempt < maxAttempts)
            {
                // Another writer was faster: read again and re-apply (the transaction was aborted, nothing was written).
            }

            await Task.Delay(Random.Shared.Next(1, 4 * attempt + 1), cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed record StoredUserMutation(RtUser User, ulong ReadVersion);

    /// <summary>
    ///     Carries the stored lockout fields to the caller's in-memory user. The caller's <c>rtVersion</c> follows the write
    ///     only if the stored user was still the version the caller holds: then nothing else changed and the caller's
    ///     later <see cref="UpdateAsync" /> stays valid. Otherwise the user is stale and keeps its old version, so
    ///     <see cref="UpdateAsync" /> reports a concurrency failure instead of overwriting the other writer's changes.
    /// </summary>
    private static void AdoptStoredLockoutState(RtUser user, StoredUserMutation outcome)
    {
        user.AccessFailedCount = outcome.User.AccessFailedCount;
        user.LockoutEnd = outcome.User.LockoutEnd;
        AdoptStoredVersion(user, outcome);
    }

    private static void AdoptStoredVersion(RtUser user, StoredUserMutation outcome)
    {
        if (outcome.ReadVersion == user.RtVersion)
        {
            user.RtVersion = outcome.User.RtVersion;
        }
    }

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
