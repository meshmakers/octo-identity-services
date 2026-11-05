using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.DisableTwoFactor-1</c> (AB#7879, System.Identity 2.30.0): a user administrator switches
///     off the second factor of a user (recovery path of AB#7830). Since AB#8042 it is, next to the user's own self-service, the
///     only write path for <c>TwoFactorEnabled</c>: generic GraphQL and caller imports are refused.
/// </summary>
/// <remarks>
///     <para>
///         <b>Caller.</b> <see cref="IdentityAdminMethodHandlerBase{TParameters}" />: scope <c>octo_api</c> and role
///         <c>UserManagement</c> on the validated principal (REST parity with <c>POST users/{userName}/disableTwoFactor</c>),
///         <c>METHOD_FORBIDDEN</c> / <c>role-required</c> before the target is read; one <c>Identity.Method</c> event per call.
///     </para>
///     <para>
///         <b>Effect.</b> <see cref="IUserTwoFactorAdministrationService" />: authenticator key and recovery codes removed,
///         <c>TwoFactorEnabled = false</c>, security stamp rotated, refresh tokens and authorizations of the user in the tenant
///         revoked. A failure throws (<c>METHOD_HANDLER_FAILED</c>), never a success with the old state. The method carries no
///         secret (no <c>sensitive</c> parameter or result), so it is hosted whatever <c>EnablePasswordMethods</c> says.
///     </para>
///     <para>
///         <b>Audit detail</b> <c>twoFactorWasEnabled</c> (<c>true</c>/<c>false</c>); never a key or a code.
///     </para>
/// </remarks>
internal sealed class UserDisableTwoFactorHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<UserDisableTwoFactorParameters>(services)
{
    /// <summary>Audit detail: the user had the second factor switched on before the call.</summary>
    internal const string TwoFactorWasEnabledDetail = "twoFactorWasEnabled";

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        UserDisableTwoFactorParameters parameters, CancellationToken cancellationToken)
    {
        var userManager = call.Services.GetRequiredService<UserManager<RtUser>>();
        var user = await userManager.FindByIdAsync(targetRtId.ToString()).ConfigureAwait(false);
        if (user == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var result = await call.Services.GetRequiredService<IUserTwoFactorAdministrationService>()
            .DisableAsync(user, TwoFactorDisablePath.MethodDisableTwoFactor,
                await ActingUserAsync(userManager, call).ConfigureAwait(false), cancellationToken)
            .ConfigureAwait(false);
        call.Details[TwoFactorWasEnabledDetail] = result.TwoFactorWasEnabled ? "true" : "false";
        return CkMethodOutcome.Ok();
    }

    private static async Task<string?> ActingUserAsync(UserManager<RtUser> userManager, IdentityMethodCall call)
    {
        var principal = call.Principal;
        if (principal.SubjectId == null)
        {
            return principal.ClientId == null ? principal.Subject : $"client {principal.ClientId}";
        }

        var caller = await userManager.FindByIdAsync(principal.SubjectId).ConfigureAwait(false);
        return caller?.UserName ?? principal.SubjectId;
    }
}
