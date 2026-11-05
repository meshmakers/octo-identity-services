using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     The duplicate-e-mail rule of the user administration (AB#8064 create, AB#8084 change): an e-mail address another user of
///     the tenant already has is refused. Compared normalised (<see cref="UserManager{TUser}.NormalizeEmail" />, so
///     case-insensitive); a blank address is never checked.
/// </summary>
/// <remarks>
///     Only <b>new</b> conflicts are refused: a create, or a change of the address to a different one. Keeping the address a
///     user already has is never checked, so users of tenants that already hold duplicates stay editable.
///     <see cref="IdentityOptions.User" /> <c>RequireUniqueEmail</c> stays off for that reason (its validator runs on every
///     update). Check and write are not atomic (no unique index on runtime entities).
/// </remarks>
internal static class UserEmailUniqueness
{
    /// <summary>
    ///     <c>true</c> when <paramref name="email" /> is not blank and another user than <paramref name="user" /> already has it.
    ///     For a create pass the new (not yet stored) user.
    /// </summary>
    public static async Task<bool> IsTakenByAnotherUserAsync(UserManager<RtUser> userManager, RtUser user, string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }

        var owner = await userManager.FindByEmailAsync(email);
        return owner != null && owner.RtId != user.RtId;
    }

    /// <summary>
    ///     <c>true</c> when an update changes the address from <paramref name="previousEmail" /> to a different, not blank
    ///     <paramref name="newEmail" /> (normalised comparison). Only such a change is checked; an unchanged address, a change of
    ///     the casing only, or clearing the address are not.
    /// </summary>
    public static bool ChangesAddress(UserManager<RtUser> userManager, string? previousEmail, string? newEmail)
    {
        if (string.IsNullOrWhiteSpace(newEmail))
        {
            return false;
        }

        return string.IsNullOrWhiteSpace(previousEmail)
               || !string.Equals(userManager.NormalizeEmail(previousEmail), userManager.NormalizeEmail(newEmail),
                   StringComparison.Ordinal);
    }
}
