using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     <see cref="UserManager{TUser}" /> whose failure counting and reset are atomic on the stored user (AB#7854).
/// </summary>
/// <remarks>
///     <para>
///         The framework implementation increments <c>AccessFailedCount</c> on the caller's copy and replaces the whole
///         document (<c>UpdateAsync</c>), so parallel wrong passwords or second-factor codes overwrote each other's
///         increments: N parallel attempts counted about once, which multiplied the guesses per lockout window. Here
///         both operations run as one read-modify-write transaction in <see cref="IAtomicUserLockoutStore" />; the
///         arithmetic (threshold, lockout end, counter restart) is unchanged.
///     </para>
///     <para>
///         <see cref="SignInManager{TUser}" /> calls <c>IsLockedOutAsync</c> on the same instance right after
///         <c>AccessFailedAsync</c>, so the store copies the stored counter and lockout end back onto it.
///     </para>
/// </remarks>
public class OctoUserManager(
    IUserStore<RtUser> store,
    IOptions<IdentityOptions> optionsAccessor,
    IPasswordHasher<RtUser> passwordHasher,
    IEnumerable<IUserValidator<RtUser>> userValidators,
    IEnumerable<IPasswordValidator<RtUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errors,
    IServiceProvider services,
    ILogger<UserManager<RtUser>> logger)
    : UserManager<RtUser>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer,
        errors, services, logger)
{
    public override async Task<IdentityResult> AccessFailedAsync(RtUser user)
    {
        ThrowIfDisposed();
        if (Store is not IAtomicUserLockoutStore atomicStore)
        {
            return await base.AccessFailedAsync(user).ConfigureAwait(false);
        }

        ArgumentNullException.ThrowIfNull(user);
        var lockedOut = await atomicStore.RecordAccessFailureAsync(user, Options.Lockout.MaxFailedAccessAttempts,
            Options.Lockout.DefaultLockoutTimeSpan, CancellationToken).ConfigureAwait(false);
        if (lockedOut)
        {
            Logger.LogDebug(new EventId(12, "UserLockedOut"), "User is locked out.");
        }

        return IdentityResult.Success;
    }

    public override async Task<IdentityResult> ResetAccessFailedCountAsync(RtUser user)
    {
        ThrowIfDisposed();
        if (Store is not IAtomicUserLockoutStore atomicStore)
        {
            return await base.ResetAccessFailedCountAsync(user).ConfigureAwait(false);
        }

        ArgumentNullException.ThrowIfNull(user);
        // No short-cut on the caller's copy: it may say 0 while parallel failures were stored meanwhile.
        await atomicStore.ResetAccessFailedCountAtomicallyAsync(user, CancellationToken).ConfigureAwait(false);
        return IdentityResult.Success;
    }
}
