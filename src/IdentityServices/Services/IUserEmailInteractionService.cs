using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     A service that interacts with users via email to perform tasks like resetting the password, or confirming the email address.
/// </summary>
public interface IUserEmailInteractionService
{
    /// <summary>
    ///     Send a notification to the user, to confirm his email address.
    /// </summary>
    /// <param name="tenantId">The tenant id the user like to log in to.</param>
    /// <param name="user">User that receives the notification.</param>
    Task SendWelcomeNotificationAsync(string tenantId, RtUser user);

    /// <summary>
    ///     Send a welcome Notification to the user, that allows him to reset his password.
    /// </summary>
    /// <param name="tenantId">The tenant id the user like to log in to.</param>
    /// <param name="user">User that receives the notification.</param>
    Task SendWelcomeNotificationWithoutPasswordAsync(string tenantId, RtUser user);

    /// <summary>
    ///     Send a notification to the user to reset his password.
    /// </summary>
    /// <param name="tenantId">The tenant id the user like to log in to.</param>
    /// <param name="user">User that receives the notification.</param>
    Task SendPasswordResetNotificationAsync(string tenantId, RtUser user);

}