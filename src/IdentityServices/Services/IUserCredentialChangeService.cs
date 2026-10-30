using Persistence.IdentityCkModel.Generated.System.Identity.v2;

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
    TokenResetPassword
}

/// <summary>
///     Single place that runs after every successful password change (AB#7765, review finding M3):
///     rotates the security stamp, revokes every refresh token and authorization of the user in the
///     current tenant and writes one audit log entry. The CK method handlers of Feature AB#5696
///     (AB#5672, AB#7774) call the same helper.
/// </summary>
public interface IUserCredentialChangeService
{
    /// <summary>
    ///     Must be called after the new password was persisted. Throws when the revocation fails, so the
    ///     caller never reports success while old refresh tokens are still redeemable.
    /// </summary>
    /// <param name="user">The user whose password changed.</param>
    /// <param name="path">The path that changed the password.</param>
    /// <param name="actingUser">User name of the caller, or <c>null</c> when anonymous (reset token).</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task OnPasswordChangedAsync(RtUser user, PasswordChangePath path, string? actingUser,
        CancellationToken cancellationToken = default);
}
