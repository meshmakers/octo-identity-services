using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.SetPassword-1</c> (AB#8414): the signed-in user who has only external logins sets a
///     first local password. Its REST facade is <c>POST {tenant}/api/manage/set-password</c> of the account pages.
/// </summary>
/// <remarks>
///     <para>
///         <b>Self only.</b> Like <see cref="UserChangePasswordHandler" />: the declared authorization (<c>allowSelf</c>, no
///         role) also admits an administrator for any target (default-deny rule of the host), so the handler requires the
///         validated subject of the caller to be the target and answers <c>METHOD_FORBIDDEN</c> / <c>not-self</c> before the
///         target is looked up. An administrator uses <c>ResetPassword</c>.
///     </para>
///     <para>
///         <b>Order.</b> Tenant, user, shadow user (<c>SHADOW_USER_PASSWORD_NOT_ALLOWED</c>), existing password
///         (<c>PASSWORD_ALREADY_SET</c>: without a current password this method must never replace one), then
///         <see cref="UserManager{TUser}.AddPasswordAsync" /> (policy failure = <c>PASSWORD_POLICY_VIOLATION</c> with the codes
///         of the failed rules). After the password is stored the shared helper of AB#7765 rotates the security stamp and
///         revokes the refresh tokens and authorizations of the user in the tenant; it throws when the revocation fails and the
///         caller gets <c>METHOD_HANDLER_FAILED</c>, never a success while old refresh tokens are redeemable.
///     </para>
///     <para>
///         <b>Secrets.</b> <c>newPassword</c> is read only here and passed to <see cref="UserManager{TUser}" />. Nothing of it
///         reaches a log, an audit record or an error parameter. One audit record per call (success or failure).
///     </para>
/// </remarks>
internal sealed class UserSetPasswordHandler(
    IServiceProvider services,
    ILogger<UserSetPasswordHandler> logger) : ICkMethodHandler<UserSetPasswordParameters>
{
    /// <summary>Declared error: the user already has a local password (use <c>ChangePassword</c>).</summary>
    internal const string PasswordAlreadySet = "PASSWORD_ALREADY_SET";

    /// <summary>Declared error: the new password violates the password policy (details: codes of the failed rules).</summary>
    internal const string PasswordPolicyViolation = "PASSWORD_POLICY_VIOLATION";

    /// <summary>Declared error: a cross-tenant shadow user has no local password (AB#5708).</summary>
    internal const string ShadowUserPasswordNotAllowed = "SHADOW_USER_PASSWORD_NOT_ALLOWED";

    public async Task<CkMethodOutcome> HandleAsync(CkMethodContext<UserSetPasswordParameters> context,
        CancellationToken cancellationToken)
    {
        var outcomeCode = CkMethodErrorCodes.MethodHandlerFailed;
        try
        {
            var outcome = await SetAsync(context, cancellationToken).ConfigureAwait(false);
            outcomeCode = outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome;
            return outcome;
        }
        finally
        {
            // One audit record per call, also when the call throws (the host answers METHOD_HANDLER_FAILED then).
            var audit = services.GetRequiredService<IIdentityMethodAuditWriter>();
            await audit.RecordAsync(context.TenantId, context.MethodId, context.InvocationId, context.TargetRtId,
                context.CallerPrincipal?.Subject, outcomeCode).ConfigureAwait(false);
        }
    }

    private async Task<CkMethodOutcome> SetAsync(CkMethodContext<UserSetPasswordParameters> context,
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
            return CkMethodOutcome.Fail(ShadowUserPasswordNotAllowed);
        }

        if (await userManager.HasPasswordAsync(user).ConfigureAwait(false))
        {
            return CkMethodOutcome.Fail(PasswordAlreadySet);
        }

        var result = await userManager.AddPasswordAsync(user, context.Parameters.NewPassword).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            // The pre-check and the write are not atomic: a concurrent call (double submit) set a password in between.
            return result.Errors.Any(e => e.Code == nameof(IdentityErrorDescriber.UserAlreadyHasPassword))
                ? CkMethodOutcome.Fail(PasswordAlreadySet)
                : Failure(result);
        }

        // Rotates the security stamp, revokes the refresh tokens and authorizations of the user in this tenant and logs
        // (AB#7765). Throws when the revocation fails: METHOD_HANDLER_FAILED, never a success with redeemable old tokens.
        var credentialChange = services.GetRequiredService<IUserCredentialChangeService>();
        await credentialChange.OnPasswordChangedAsync(user, PasswordChangePath.MethodSetPassword, user.UserName,
            cancellationToken).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }

    private CkMethodOutcome Failure(IdentityResult result)
    {
        // Codes of the failed rules only (PasswordTooShort, PasswordRequiresDigit, ...), never a value.
        var details = result.Errors
            .Where(e => !string.IsNullOrWhiteSpace(e.Code))
            .Select(e => new CkMethodErrorDetail { Code = e.Code })
            .ToList();
        logger.LogInformation(
            "User.SetPassword refused: the new password violates the password policy ({RuleCount} rule(s))",
            details.Count);
        return CkMethodOutcome.Fail(new CkMethodFailure(PasswordPolicyViolation, details: details));
    }
}
