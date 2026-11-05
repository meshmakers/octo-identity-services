using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>The REST path through which a password was changed (audit label, AB#7765).</summary>
public enum PasswordChangePath
{
    /// <summary><c>POST {tenantId}/api/manage/change-password</c></summary>
    ChangePassword,

    /// <summary><c>POST {tenantId}/api/manage/set-password</c></summary>
    SetPassword,

    /// <summary><c>POST system/v1/users/ResetPassword</c> (administrator)</summary>
    AdminResetPassword,

    /// <summary><c>POST {tenantId}/api/auth/reset-password</c> (anonymous, reset token)</summary>
    TokenResetPassword,

    /// <summary>CK method <c>User.ChangePassword</c> (AB#5672), self only</summary>
    MethodChangePassword,

    /// <summary>CK method <c>User.ResetPassword</c> (AB#7774), administrator</summary>
    MethodResetPassword
}

/// <summary>
///     Single place that runs after every successful password change (AB#7765, review finding M3):
///     rotates the security stamp, revokes every refresh token and authorization of the user in the
///     current tenant and writes one audit log entry. The CK method handlers of Feature AB#5696
///     (AB#5672, AB#7774) call the same helper; so does switching the second factor off (AB#7879).
/// </summary>
public interface IUserCredentialChangeService
{
    /// <summary>
    ///     Must be called after the new password was persisted. Throws when the revocation fails, so the
    ///     caller never reports success while old refresh tokens are still redeemable. This is the second revocation of a
    ///     password change: <c>OctoUserManager</c> already revoked before the password was stored (AB#8018), so a crash
    ///     between the password write and this call leaves no old refresh token valid.
    /// </summary>
    /// <param name="user">The user whose password changed.</param>
    /// <param name="path">The path that changed the password.</param>
    /// <param name="actingUser">User name of the caller, or <c>null</c> when anonymous (reset token).</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task OnPasswordChangedAsync(RtUser user, PasswordChangePath path, string? actingUser,
        CancellationToken cancellationToken = default);

    /// <summary>
    ///     AB#7879: the same revocation after an administrator switched the second factor of the user off (the flag and the
    ///     authenticator material are already persisted): rotates the security stamp, revokes every refresh token and
    ///     authorization of the user in the current tenant and writes one audit log line (tenant, subject, acting user, path,
    ///     whether 2FA was on). Throws when the revocation fails.
    /// </summary>
    /// <param name="user">The user whose second factor was switched off.</param>
    /// <param name="path">The administrative path.</param>
    /// <param name="actingUser">The caller as the audit names it.</param>
    /// <param name="twoFactorWasEnabled">Whether the user had the second factor on before the call.</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task OnSecondFactorDisabledAsync(RtUser user, TwoFactorDisablePath path, string? actingUser,
        bool twoFactorWasEnabled, CancellationToken cancellationToken = default);
}
