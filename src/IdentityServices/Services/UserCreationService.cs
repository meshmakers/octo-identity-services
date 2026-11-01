using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     AB#7777: the one way the identity service creates a user. Shared by the REST endpoint <c>POST {tenant}/v1/users</c> and the
///     CK method <c>User.CreateUser-1</c>, so both run the same user manager steps and send the same welcome notification.
///     Every other generic path (GraphQL create, <c>ImportRt</c>, blueprint seed, pipeline insert) refuses a new user
///     (<c>GENERIC_CREATE_REPLACED_BY_METHOD</c>, engine <c>GenericCreateReplacement</c>).
/// </summary>
public interface IUserCreationService
{
    /// <summary>
    ///     Creates <paramref name="user" /> through <see cref="UserManager{TUser}" />: the user validators (unique user name,
    ///     allowed characters), the password validators and the hasher when a password is given, the normalised user name and
    ///     e-mail and a new security stamp. With a password the password is validated before the user is stored, so a policy
    ///     failure never leaves a user behind (AB#4503). On success the welcome notification is sent: with a password the one
    ///     that confirms the e-mail address, without a password the invitation that lets the user set one.
    /// </summary>
    /// <param name="tenantId">The tenant the user is created in (the current tenant of the user manager).</param>
    /// <param name="user">The new user (user name, e-mail, first and last name, <c>ResetPasswordOnLogin</c>).</param>
    /// <param name="password">The initial password, or <c>null</c>/blank for an invitation without a password.</param>
    /// <returns>The result of the user manager; the caller maps its error codes.</returns>
    Task<IdentityResult> CreateAsync(string tenantId, RtUser user, string? password);
}

internal sealed class UserCreationService(
    UserManager<RtUser> userManager,
    IUserEmailInteractionService userEmailInteractionService) : IUserCreationService
{
    public async Task<IdentityResult> CreateAsync(string tenantId, RtUser user, string? password)
    {
        var withPassword = !string.IsNullOrWhiteSpace(password);
        var result = withPassword
            ? await userManager.CreateAsync(user, password!)
            : await userManager.CreateAsync(user);
        if (!result.Succeeded)
        {
            return result;
        }

        if (withPassword)
        {
            await userEmailInteractionService.SendWelcomeNotificationAsync(tenantId, user);
        }
        else
        {
            await userEmailInteractionService.SendWelcomeNotificationWithoutPasswordAsync(tenantId, user);
        }

        return result;
    }
}
