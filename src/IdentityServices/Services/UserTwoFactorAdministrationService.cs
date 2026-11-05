using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>The administrative path through which the second factor of a user was switched off (audit label, AB#7879).</summary>
public enum TwoFactorDisablePath
{
    /// <summary><c>POST {tenant}/v1/users/{userName}/disableTwoFactor</c></summary>
    AdminRest,

    /// <summary>CK method <c>User.DisableTwoFactor-1</c></summary>
    MethodDisableTwoFactor
}

/// <summary>Result of <see cref="IUserTwoFactorAdministrationService.DisableAsync" /> (no secret, only the prior state).</summary>
/// <param name="TwoFactorWasEnabled"><c>true</c> when the user had the second factor switched on before the call.</param>
public sealed record UserTwoFactorDisableResultDto(bool TwoFactorWasEnabled);

/// <summary>
///     AB#7879: the administrator recovery path of AB#7830 (option a) - a user who lost the authenticator (or whose key did not
///     survive a clone or restore) cannot sign in until a user administrator switches the second factor off. Shared by the REST
///     facade and the CK method handler so that both paths do exactly the same.
/// </summary>
public interface IUserTwoFactorAdministrationService
{
    /// <summary>
    ///     Switches the second factor of <paramref name="user" /> off: removes the authenticator key and the recovery codes, sets
    ///     <c>TwoFactorEnabled = false</c>, then rotates the security stamp and revokes every refresh token and authorization of
    ///     the user in the current tenant (and writes one audit log line). Idempotent: a user without a second factor is
    ///     handled the same way (the sessions are revoked all the same). Throws when a write or the revocation fails, so a caller
    ///     never reports success while the old state or old refresh tokens survive.
    /// </summary>
    /// <param name="user">The user, read through <see cref="UserManager{TUser}" /> of the current tenant.</param>
    /// <param name="path">The path that switched the factor off.</param>
    /// <param name="actingUser">The caller as the audit names it (user name, or <c>client &lt;id&gt;</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<UserTwoFactorDisableResultDto> DisableAsync(RtUser user, TwoFactorDisablePath path, string? actingUser,
        CancellationToken cancellationToken = default);
}

internal sealed class UserTwoFactorAdministrationService(
    UserManager<RtUser> userManager,
    IUserCredentialChangeService credentialChangeService) : IUserTwoFactorAdministrationService
{
    /// <summary>Login provider of the tokens ASP.NET Core Identity stores for the authenticator (as in <c>ManageApiController</c>).</summary>
    internal const string InternalLoginProvider = "[AspNetUserStore]";

    internal const string AuthenticatorKeyTokenName = "AuthenticatorKey";
    internal const string RecoveryCodeTokenName = "RecoveryCodes";

    public async Task<UserTwoFactorDisableResultDto> DisableAsync(RtUser user, TwoFactorDisablePath path,
        string? actingUser, CancellationToken cancellationToken = default)
    {
        var wasEnabled = await userManager.GetTwoFactorEnabledAsync(user);

        // Through the manager and the store (guarded, versioned writes of AB#7908), never by writing the entity: every call
        // persists on its own and the instance follows the stored version.
        Ensure(await userManager.RemoveAuthenticationTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName),
            "the authenticator key could not be removed");
        Ensure(await userManager.RemoveAuthenticationTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName),
            "the recovery codes could not be removed");
        Ensure(await userManager.SetTwoFactorEnabledAsync(user, false), "the second factor could not be switched off");

        // Same helper as every password path (AB#7765): stamp, token and authorization revocation in this tenant, audit line.
        await credentialChangeService.OnSecondFactorDisabledAsync(user, path, actingUser, wasEnabled, cancellationToken);
        return new UserTwoFactorDisableResultDto(wasEnabled);
    }

    private static void Ensure(IdentityResult result, string what)
    {
        if (!result.Succeeded)
        {
            // Error codes only (e.g. ConcurrencyFailure), never a value.
            throw new InvalidOperationException(
                $"Disabling the second factor failed: {what} ({string.Join(",", result.Errors.Select(e => e.Code))}).");
        }
    }
}
