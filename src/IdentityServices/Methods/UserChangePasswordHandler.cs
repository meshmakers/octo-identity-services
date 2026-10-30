using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.ChangePassword-1</c> (AB#5672): the signed-in user changes their own password.
/// </summary>
/// <remarks>
///     <para>
///         <b>Self only.</b> The declared authorization (<c>allowSelf</c>, no role) also admits an administrator for any
///         target (default-deny rule of the host), so the handler decides itself: the validated subject of the caller
///         (<see cref="CkMethodContext.CallerPrincipal" />, from the token the host verified) must be the target. A service
///         token (no subject) and every other user get <c>METHOD_FORBIDDEN</c> / <c>not-self</c>, answered before the
///         target is looked up, so the answer is the same whether the target exists or not. An administrator uses
///         <c>ResetPassword</c> (AB#7774).
///     </para>
///     <para>
///         <b>Tenant.</b> The handler runs on the bus without an HTTP request. It binds the tenant of the invocation to
///         <see cref="IMethodTenantAccessor" /> first and resolves the user manager and the stores afterwards, from the
///         scope of the invocation (hence the <see cref="IServiceProvider" />: a constructor-injected store would be created
///         before the tenant is known).
///     </para>
///     <para>
///         <b>Brute force.</b> The method checks the current password, so it is a password oracle for a stolen session. It
///         refuses a locked-out user (<c>USER_LOCKED_OUT</c>), counts a wrong current password like a failed sign-in
///         (atomic lockout counter of AB#7854) and resets the counter on success.
///     </para>
///     <para>
///         <b>Secrets.</b> <c>currentPassword</c> and <c>newPassword</c> are read only here and passed to
///         <see cref="UserManager{TUser}" />. Nothing of them reaches a log, an audit record or an error parameter: the
///         policy violation names the failed rules by code, never a value.
///     </para>
/// </remarks>
internal sealed class UserChangePasswordHandler(
    IServiceProvider services,
    ILogger<UserChangePasswordHandler> logger) : ICkMethodHandler<UserChangePasswordParameters>
{
    /// <summary>The Identity error code of a wrong current password (<c>IdentityErrorDescriber.PasswordMismatch</c>).</summary>
    private const string PasswordMismatchCode = "PasswordMismatch";

    public async Task<CkMethodOutcome> HandleAsync(CkMethodContext<UserChangePasswordParameters> context,
        CancellationToken cancellationToken)
    {
        var outcome = await ChangeAsync(context, cancellationToken).ConfigureAwait(false);

        var audit = services.GetRequiredService<IIdentityMethodAuditWriter>();
        await audit.RecordAsync(context.TenantId, context.MethodId, context.InvocationId, context.TargetRtId,
            context.CallerPrincipal?.Subject,
            outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome).ConfigureAwait(false);
        return outcome;
    }

    private async Task<CkMethodOutcome> ChangeAsync(CkMethodContext<UserChangePasswordParameters> context,
        CancellationToken cancellationToken)
    {
        var principal = context.CallerPrincipal;
        if (principal?.SubjectId is null || string.IsNullOrWhiteSpace(context.TargetRtId) ||
            !string.Equals(principal.SubjectId, context.TargetRtId, StringComparison.OrdinalIgnoreCase))
        {
            return CkMethodOutcome.Forbidden("not-self");
        }

        var tenantAccessor = services.GetRequiredService<IMethodTenantAccessor>();
        if (!await tenantAccessor.BindAsync(context.TenantId).ConfigureAwait(false))
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var userManager = services.GetRequiredService<UserManager<RtUser>>();
        var user = await userManager.FindByIdAsync(context.TargetRtId).ConfigureAwait(false);
        if (user == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        // AB#5708: cross-tenant shadow users sign in through their home tenant and have no local password.
        if (CrossTenantShadowUserName.IsShadowUserName(user.UserName))
        {
            return CkMethodOutcome.Fail("SHADOW_USER_PASSWORD_NOT_ALLOWED");
        }

        if (userManager.SupportsUserLockout && await userManager.IsLockedOutAsync(user).ConfigureAwait(false))
        {
            return CkMethodOutcome.Fail("USER_LOCKED_OUT");
        }

        var result = await userManager
            .ChangePasswordAsync(user, context.Parameters.CurrentPassword, context.Parameters.NewPassword)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return await FailureAsync(userManager, user, result).ConfigureAwait(false);
        }

        if (userManager.SupportsUserLockout)
        {
            await userManager.ResetAccessFailedCountAsync(user).ConfigureAwait(false);
        }

        // Rotates the security stamp, revokes the refresh tokens and authorizations of the user in this tenant and logs
        // (AB#7765). Throws when the revocation fails: the caller then gets METHOD_HANDLER_FAILED, never a success while
        // old refresh tokens are redeemable.
        var credentialChange = services.GetRequiredService<IUserCredentialChangeService>();
        await credentialChange.OnPasswordChangedAsync(user, PasswordChangePath.MethodChangePassword, user.UserName,
            cancellationToken).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }

    private async Task<CkMethodOutcome> FailureAsync(UserManager<RtUser> userManager, RtUser user,
        IdentityResult result)
    {
        if (result.Errors.Any(e => e.Code == PasswordMismatchCode))
        {
            if (userManager.SupportsUserLockout)
            {
                await userManager.AccessFailedAsync(user).ConfigureAwait(false);
            }

            return CkMethodOutcome.Fail("CURRENT_PASSWORD_INVALID");
        }

        // Codes of the failed rules only (PasswordTooShort, PasswordRequiresDigit, ...), never a value.
        var details = result.Errors
            .Where(e => !string.IsNullOrWhiteSpace(e.Code))
            .Select(e => new CkMethodErrorDetail { Code = e.Code })
            .ToList();
        logger.LogInformation(
            "User.ChangePassword refused: the new password violates the password policy ({RuleCount} rule(s))",
            details.Count);
        return CkMethodOutcome.Fail(new CkMethodFailure("PASSWORD_POLICY_VIOLATION", details: details));
    }
}
