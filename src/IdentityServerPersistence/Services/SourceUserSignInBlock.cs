using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services;

/// <summary>
///     AB#7855: why a user may not cross a tenant boundary on its own account — a lockout or a sign-in rule of
///     <see cref="SignInOptions" /> (confirmed e-mail / phone / account, the rules <c>SignInManager.CanSignInAsync</c>
///     applies on the token endpoint; RtUser has no separate "disabled" flag). Shared by the crossing gate
///     (<see cref="CrossTenantAuthenticationService" />) and the source user lookup (AB#8341), so both refuse the same
///     users.
/// </summary>
public static class SourceUserSignInBlock
{
    /// <summary>The reason <paramref name="user" /> is blocked, or <c>null</c> when it may sign in.</summary>
    public static string? Get(RtUser user, SignInOptions signIn, DateTimeOffset now)
    {
        if (IsLockedOut(user, now))
        {
            return "locked out";
        }

        if (signIn.RequireConfirmedEmail && !user.EmailConfirmed)
        {
            return "e-mail not confirmed";
        }

        if (signIn.RequireConfirmedPhoneNumber && !user.PhoneNumberConfirmed)
        {
            return "phone number not confirmed";
        }

        // DefaultUserConfirmation: an account is confirmed when its e-mail is.
        if (signIn.RequireConfirmedAccount && !user.EmailConfirmed)
        {
            return "account not confirmed";
        }

        return null;
    }

    /// <summary>Whether <paramref name="user" /> is locked out at <paramref name="now" />.</summary>
    public static bool IsLockedOut(RtUser user, DateTimeOffset now)
        => user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd.Value > now;
}
