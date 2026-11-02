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
    /// <remarks>
    ///     AB#8064: an e-mail address another user of the tenant already has (compared normalised, so case-insensitive) is
    ///     refused before anything is stored, with the identity error <c>DuplicateEmail</c>. The REST endpoint answers it with
    ///     <c>409</c> and <c>code: USER_ALREADY_EXISTS</c>, the method with the declared error <c>USER_ALREADY_EXISTS</c>
    ///     (<c>field=email</c>). The rule (<see cref="UserEmailUniqueness" />) also covers a change of the address through
    ///     <c>PUT users/{userName}</c> (AB#8084), never an unchanged one: <see cref="IdentityOptions.User" /> <c>RequireUniqueEmail</c> stays
    ///     off, because the user validator runs on every update too and would lock out the updates of users in tenants that
    ///     already hold duplicate e-mail addresses. A taken user name wins (the user manager answers <c>DuplicateUserName</c>
    ///     as before), so creating the same user twice keeps its previous answer. A blank e-mail is not checked (users without an e-mail address stay
    ///     possible). The check and the insert are not atomic (no unique index on runtime entities): two concurrent creates with
    ///     the same address can both succeed.
    /// </remarks>
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
        // A taken user name is reported by the user manager as before (DuplicateUserName), so the e-mail check runs only when
        // the name is free: creating the same user twice keeps its previous answer.
        if (!string.IsNullOrWhiteSpace(user.Email)
            && (string.IsNullOrWhiteSpace(user.UserName) || await userManager.FindByNameAsync(user.UserName) == null)
            && await UserEmailUniqueness.IsTakenByAnotherUserAsync(userManager, user, user.Email))
        {
            return IdentityResult.Failed(userManager.ErrorDescriber.DuplicateEmail(user.Email));
        }

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
