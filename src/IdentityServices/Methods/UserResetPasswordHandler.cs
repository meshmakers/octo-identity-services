using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.ResetPassword-1</c> (AB#7774): a user administrator sets a new password without
///     the current one, also for a locked-out user.
/// </summary>
/// <remarks>
///     <para>
///         <b>Caller.</b> The gateway and the host already evaluate the declared role (<c>UserManagement</c>) against the
///         validated token. The handler checks it again on the principal the host validated (defense in depth: a forged
///         request on the bus never reaches a store) and answers <c>METHOD_FORBIDDEN</c> before the target is looked up, so
///         the answer is the same whether the target exists or not. <c>METHOD_TARGET_NOT_FOUND</c> is therefore only seen
///         by an authorized caller.
///     </para>
///     <para>
///         <b>Lockout.</b> The method lifts the lockout: <c>LockoutEnd</c> becomes <c>null</c> and <c>AccessFailedCount</c>
///         0 (since AB#8413 also for <c>POST {tenant}/v1/users/ResetPassword</c>, its REST facade, which left the lockout in
///         place before). Both go through <see cref="UserManager{TUser}" /> (the store applies them with the
///         versioned, guarded write of AB#7908, never as a whole-document replace). A failed call lifts nothing. No e-mail
///         is sent (AB#7775); the REST facade sends the reset notification after a success until then.
///     </para>
///     <para>
///         <b>Sessions.</b> After the password is stored the shared helper of AB#7765 rotates the security stamp and revokes
///         the refresh tokens and authorizations of the user in the tenant. It throws when the revocation fails: the caller
///         gets <c>METHOD_HANDLER_FAILED</c>, never a success while old refresh tokens are redeemable.
///     </para>
///     <para>
///         <b>Secrets.</b> <c>newPassword</c> is read only here and passed to <see cref="UserManager{TUser}" />. Nothing of
///         it reaches a log, an audit record or an error parameter; the policy violation names the failed rules by code.
///         The audit record names tenant, actor, target, outcome and <c>lockoutLifted</c> (one per call, success or failure).
///     </para>
/// </remarks>
internal sealed class UserResetPasswordHandler(
    IServiceProvider services,
    ILogger<UserResetPasswordHandler> logger) : ICkMethodHandler<UserResetPasswordParameters>
{
    /// <summary>The role that the declaration of the method requires (REST parity: <c>IdentityUserAdministrationWritePolicy</c>).</summary>
    internal const string RequiredRole = "UserManagement";

    /// <summary>Audit detail: the call lifted an active lockout (<c>true</c>/<c>false</c>).</summary>
    internal const string LockoutLiftedDetail = "lockoutLifted";

    /// <summary>Declared error: the new password violates the password policy (details: codes of the failed rules).</summary>
    internal const string PasswordPolicyViolation = "PASSWORD_POLICY_VIOLATION";

    /// <summary>Declared error: a cross-tenant shadow user has no local password (AB#5708).</summary>
    internal const string ShadowUserPasswordNotAllowed = "SHADOW_USER_PASSWORD_NOT_ALLOWED";

    public async Task<CkMethodOutcome> HandleAsync(CkMethodContext<UserResetPasswordParameters> context,
        CancellationToken cancellationToken)
    {
        var lockoutLifted = false;
        var outcomeCode = "METHOD_HANDLER_FAILED";
        try
        {
            var (outcome, lifted) = await ResetAsync(context, cancellationToken).ConfigureAwait(false);
            lockoutLifted = lifted;
            outcomeCode = outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome;
            return outcome;
        }
        finally
        {
            // One audit record per call, also when the call throws (the host answers METHOD_HANDLER_FAILED then).
            var audit = services.GetRequiredService<IIdentityMethodAuditWriter>();
            await audit.RecordAsync(context.TenantId, context.MethodId, context.InvocationId, context.TargetRtId,
                context.CallerPrincipal?.Subject, outcomeCode,
                new Dictionary<string, string> { [LockoutLiftedDetail] = lockoutLifted ? "true" : "false" })
                .ConfigureAwait(false);
        }
    }

    private async Task<(CkMethodOutcome Outcome, bool LockoutLifted)> ResetAsync(
        CkMethodContext<UserResetPasswordParameters> context, CancellationToken cancellationToken)
    {
        var principal = context.CallerPrincipal;
        if (principal == null || !principal.Roles.Contains(RequiredRole, StringComparer.OrdinalIgnoreCase))
        {
            return (CkMethodOutcome.Forbidden("missing-role"), false);
        }

        var tenantAccessor = services.GetRequiredService<IMethodTenantAccessor>();
        if (string.IsNullOrWhiteSpace(context.TargetRtId) ||
            !await tenantAccessor.BindAsync(context.TenantId).ConfigureAwait(false))
        {
            return (CkMethodOutcome.TargetNotFound(), false);
        }

        var userManager = services.GetRequiredService<UserManager<RtUser>>();
        var user = await userManager.FindByIdAsync(context.TargetRtId).ConfigureAwait(false);
        if (user == null)
        {
            return (CkMethodOutcome.TargetNotFound(), false);
        }

        // AB#5708: cross-tenant shadow users sign in through their home tenant and have no local password.
        if (CrossTenantShadowUserName.IsShadowUserName(user.UserName))
        {
            return (CkMethodOutcome.Fail(ShadowUserPasswordNotAllowed), false);
        }

        var wasLockedOut = userManager.SupportsUserLockout && await userManager.IsLockedOutAsync(user).ConfigureAwait(false);

        // Same two calls as the REST endpoint: the password validators and the hasher run in ResetPasswordAsync.
        var token = await userManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false);
        var result = await userManager.ResetPasswordAsync(user, token, context.Parameters.NewPassword)
            .ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return (Failure(result), false);
        }

        if (userManager.SupportsUserLockout)
        {
            // Through the manager and the store (guarded, versioned write of AB#7908), never by writing the entity.
            var lifted = await userManager.SetLockoutEndDateAsync(user, null).ConfigureAwait(false);
            if (!lifted.Succeeded && wasLockedOut)
            {
                // Never report a success while the user stays locked out (METHOD_HANDLER_FAILED).
                throw new InvalidOperationException("The lockout of the user could not be lifted.");
            }

            await userManager.ResetAccessFailedCountAsync(user).ConfigureAwait(false);
        }

        // Rotates the security stamp, revokes the refresh tokens and authorizations of the user in this tenant and logs
        // (AB#7765). Throws when the revocation fails: METHOD_HANDLER_FAILED, never a success with redeemable old tokens.
        var credentialChange = services.GetRequiredService<IUserCredentialChangeService>();
        await credentialChange.OnPasswordChangedAsync(user, PasswordChangePath.MethodResetPassword,
            await ActingUserAsync(userManager, principal).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        return (CkMethodOutcome.Ok(), wasLockedOut);
    }

    /// <summary>
    ///     The acting user of the credential-change log line, in the form of <c>AuditActor.Actor</c> (AB#8008, kept for the
    ///     REST facade since AB#8413): the user name, for a client-credentials caller <c>client &lt;id&gt;</c>, else the subject.
    /// </summary>
    private static async Task<string?> ActingUserAsync(UserManager<RtUser> userManager, CkMethodPrincipal principal)
    {
        if (principal.IsServiceToken)
        {
            return $"client {principal.ClientId}";
        }

        // A subject that is not an object id names no local user (the store would throw on it; same rule as User.Merge).
        if (principal.SubjectId == null || !OctoObjectId.TryParse(principal.SubjectId, out _))
        {
            return principal.Subject;
        }

        var caller = await userManager.FindByIdAsync(principal.SubjectId).ConfigureAwait(false);
        return caller?.UserName ?? principal.SubjectId;
    }

    private CkMethodOutcome Failure(IdentityResult result)
    {
        // Codes of the failed rules only (PasswordTooShort, PasswordRequiresDigit, ...), never a value.
        var details = result.Errors
            .Where(e => !string.IsNullOrWhiteSpace(e.Code))
            .Select(e => new CkMethodErrorDetail { Code = e.Code })
            .ToList();
        logger.LogInformation(
            "User.ResetPassword refused: the new password violates the password policy ({RuleCount} rule(s))",
            details.Count);
        return CkMethodOutcome.Fail(new CkMethodFailure(PasswordPolicyViolation, details: details));
    }
}
