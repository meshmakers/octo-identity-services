using IdentityServerPersistence.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

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
///     <para>
///         AB#8018: every password write (<see cref="ChangePasswordAsync" />, <see cref="ResetPasswordAsync" />,
///         <see cref="AddPasswordAsync" />) revokes the refresh tokens and authorizations of the user <b>before</b> the new
///         password is stored, once the request is known to be valid (current password or reset token verified, new
///         password accepted by the policy). The callers revoke once more after the write
///         (<c>IUserCredentialChangeService.OnPasswordChangedAsync</c>). The token store and the user store are separate
///         writes without a shared transaction, so a crash between the password write and the revocation after it used to
///         leave old refresh tokens redeemable; now they are already revoked when the password changes. A request refused
///         before the write (wrong current password, invalid reset token, policy violation) revokes nothing. A store write
///         that fails after the revocation (<c>ConcurrencyFailure</c>, a user validator) leaves the password unchanged with the
///         sessions ended; the user signs in again (the safe direction). The bodies follow the framework
///         implementation step by step, with the revocation between the in-memory hash update and the store write.
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
    ILogger<UserManager<RtUser>> logger,
    IUserTokenRevocation? tokenRevocation = null)
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

    /// <inheritdoc />
    public override async Task<IdentityResult> ChangePasswordAsync(RtUser user, string currentPassword,
        string newPassword)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        var passwordStore = GetPasswordStore();
        if (await VerifyPasswordAsync(passwordStore, user, currentPassword).ConfigureAwait(false) ==
            PasswordVerificationResult.Failed)
        {
            Logger.LogDebug(new EventId(2, "ChangePasswordFailed"), "Change password failed for user.");
            return IdentityResult.Failed(ErrorDescriber.PasswordMismatch());
        }

        return await WritePasswordAsync(user, newPassword).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task<IdentityResult> ResetPasswordAsync(RtUser user, string token, string newPassword)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        // An invalid reset token must revoke nothing: anyone may post one for any user name.
        if (!await VerifyUserTokenAsync(user, Options.Tokens.PasswordResetTokenProvider, ResetPasswordTokenPurpose,
                token).ConfigureAwait(false))
        {
            return IdentityResult.Failed(ErrorDescriber.InvalidToken());
        }

        return await WritePasswordAsync(user, newPassword).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task<IdentityResult> AddPasswordAsync(RtUser user, string password)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        var passwordStore = GetPasswordStore();
        var hash = await passwordStore.GetPasswordHashAsync(user, CancellationToken).ConfigureAwait(false);
        if (hash != null)
        {
            Logger.LogDebug(new EventId(1, "UserAlreadyHasPassword"), "User already has a password.");
            return IdentityResult.Failed(ErrorDescriber.UserAlreadyHasPassword());
        }

        return await WritePasswordAsync(user, password).ConfigureAwait(false);
    }

    /// <summary>
    ///     Validates and sets the new hash (and security stamp) on the instance, revokes the user's tokens, then stores the
    ///     user. A revocation failure throws before anything is stored; a failed store write after the revocation keeps
    ///     the old password and leaves the sessions ended.
    /// </summary>
    private async Task<IdentityResult> WritePasswordAsync(RtUser user, string newPassword)
    {
        var result = await UpdatePasswordHash(user, newPassword, validatePassword: true).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }

        if (tokenRevocation != null)
        {
            await tokenRevocation.RevokeAllAsync(user.RtId.ToString(), CancellationToken).ConfigureAwait(false);
        }

        return await UpdateUserAsync(user).ConfigureAwait(false);
    }

    private IUserPasswordStore<RtUser> GetPasswordStore() =>
        Store as IUserPasswordStore<RtUser> ??
        throw new NotSupportedException("The user store does not implement IUserPasswordStore<RtUser>.");
}
