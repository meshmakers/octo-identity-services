using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of the static method <c>System.Identity/User.CreateUser-1</c> (AB#7777): a user administrator creates a user,
///     with an initial password or as an invitation without one. The result is the rtId of the new user.
/// </summary>
/// <remarks>
///     <para>
///         <b>Only way besides REST.</b> The method and <c>POST {tenant}/v1/users</c> share <see cref="IUserCreationService" />
///         (user manager: user validators, password policy, normalised name and e-mail, security stamp; then the welcome
///         notification). The generic paths refuse a new user: GraphQL create, caller <c>ImportRt</c>, blueprint seeds and
///         pipeline inserts answer <c>GENERIC_CREATE_REPLACED_BY_METHOD</c> naming this method (engine
///         <c>GenericCreateReplacement</c>, driven by <c>replacesGenericCreate</c> of this method since System.Identity 3.0.0).
///     </para>
///     <para>
///         <b>Caller.</b> Same rule as the REST write policy: scope <c>octo_api</c> and tenant role <c>UserManagement</c> on the
///         principal the host validated from the forwarded access token (<see cref="IdentityMethodCallerRules" />). The gateway
///         refuses a caller without the declared role before dispatch; the handler checks again, so a forged bus message never
///         reaches the store (<c>METHOD_FORBIDDEN</c>, reason <c>role-required</c>).
///     </para>
///     <para>
///         <b>Declared errors.</b> <c>USER_NAME_RESERVED</c> (prefix <c>xt_</c> of cross-tenant shadow users),
///         <c>USER_ALREADY_EXISTS</c> (parameter <c>field</c> = <c>userName</c> or <c>email</c>; a second user with the same
///         e-mail address is refused by <see cref="IUserCreationService" />, the REST endpoint answers it with 409 and the same
///         code since AB#8064), <c>PASSWORD_POLICY_VIOLATION</c> (details: the
///         codes of the failed rules, never the value). A missing or malformed user name or e-mail is
///         <c>METHOD_VALIDATION_FAILED</c>. Any other failure of the user manager throws (<c>METHOD_HANDLER_FAILED</c>).
///     </para>
///     <para>
///         <b>Secrets and audit.</b> The method has a <c>sensitive</c> parameter (<c>password</c>), so the handler is hosted only
///         when <c>Methods:Identity:EnablePasswordMethods</c> is on - also for invitations without a password, the switch is per
///         method. The password is read only here and passed to the user manager; it never reaches a log, an audit record or an
///         error parameter. One <c>Identity.Method</c> event per call (success, every refusal, <c>METHOD_HANDLER_FAILED</c>) with
///         the new user's rtId as target and the details <c>userName</c> and <c>withPassword</c>.
///     </para>
/// </remarks>
internal sealed class UserCreateUserHandler(
    IServiceProvider services,
    ILogger<UserCreateUserHandler> logger) : ICkMethodHandler<UserCreateUserParameters, UserCreateUserResult>
{
    /// <summary>Declared error: the user name is reserved for cross-tenant shadow users.</summary>
    internal const string UserNameReserved = "USER_NAME_RESERVED";

    /// <summary>Declared error: a user with this name or e-mail address exists.</summary>
    internal const string UserAlreadyExists = "USER_ALREADY_EXISTS";

    /// <summary>Declared error: the initial password violates the password policy.</summary>
    internal const string PasswordPolicyViolation = "PASSWORD_POLICY_VIOLATION";

    /// <summary>Audit detail: the user name of the new user.</summary>
    internal const string UserNameDetail = "userName";

    /// <summary>Audit detail: the call carried an initial password (<c>true</c>) or was an invitation (<c>false</c>).</summary>
    internal const string WithPasswordDetail = "withPassword";

    public async Task<CkMethodOutcome<UserCreateUserResult>> HandleAsync(
        CkMethodContext<UserCreateUserParameters> context, CancellationToken cancellationToken)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [WithPasswordDetail] = string.IsNullOrWhiteSpace(context.Parameters.Password) ? "false" : "true"
        };
        string? createdRtId = null;
        var outcomeCode = "METHOD_HANDLER_FAILED";
        try
        {
            var outcome = await CreateAsync(context, details, cancellationToken).ConfigureAwait(false);
            outcomeCode = outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome;
            createdRtId = outcome.Failure == null ? outcome.Value?.Value : null;
            return outcome;
        }
        finally
        {
            // One audit record per call, also when the call throws (the host answers METHOD_HANDLER_FAILED then).
            var audit = services.GetRequiredService<IIdentityMethodAuditWriter>();
            await audit.RecordAsync(context.TenantId, context.MethodId, context.InvocationId, createdRtId,
                context.CallerPrincipal?.Subject, outcomeCode, details).ConfigureAwait(false);
        }
    }

    private async Task<CkMethodOutcome<UserCreateUserResult>> CreateAsync(
        CkMethodContext<UserCreateUserParameters> context, Dictionary<string, string> details,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!IdentityMethodCallerRules.IsAdministrator(context.CallerPrincipal))
        {
            return CkMethodOutcome<UserCreateUserResult>.Forbidden("role-required");
        }

        var parameters = context.Parameters;
        var userName = parameters.UserName?.Trim();
        if (string.IsNullOrEmpty(userName))
        {
            return CkMethodOutcome<UserCreateUserResult>.ValidationFailed("userName", "required");
        }

        details[UserNameDetail] = userName;
        if (CrossTenantShadowUserName.IsShadowUserName(userName))
        {
            return CkMethodOutcome<UserCreateUserResult>.Fail(UserNameReserved);
        }

        // The tenant of the invocation is bound per scope; the stores of the user manager resolve it from there.
        if (!await services.GetRequiredService<IMethodTenantAccessor>().BindAsync(context.TenantId)
                .ConfigureAwait(false))
        {
            return CkMethodOutcome<UserCreateUserResult>.TargetNotFound();
        }

        var userManager = services.GetRequiredService<UserManager<RtUser>>();
        if (await userManager.FindByNameAsync(userName).ConfigureAwait(false) != null)
        {
            return CkMethodOutcome<UserCreateUserResult>.Fail(UserAlreadyExists, ("field", "userName"));
        }

        // A duplicate e-mail address is refused by the shared creation service (DuplicateEmail, mapped below), so REST and
        // method apply the same rule (AB#8064).
        var email = string.IsNullOrWhiteSpace(parameters.Email) ? null : parameters.Email.Trim();

        var user = new RtUser
        {
            UserName = userName,
            Email = email,
            FirstName = parameters.FirstName,
            LastName = parameters.LastName,
            ResetPasswordOnLogin = false
        };
        var result = await services.GetRequiredService<IUserCreationService>()
            .CreateAsync(context.TenantId, user, parameters.Password).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return Failure(result);
        }

        logger.LogInformation("User.CreateUser created user {UserRtId} in tenant {TenantId} ({Kind})", user.RtId,
            context.TenantId, details[WithPasswordDetail] == "true" ? "initial password" : "invitation");
        return new UserCreateUserResult { Value = user.RtId.ToString() };
    }

    private CkMethodOutcome<UserCreateUserResult> Failure(IdentityResult result)
    {
        var codes = result.Errors.Select(e => e.Code).Where(c => !string.IsNullOrWhiteSpace(c)).ToList();
        if (codes.Contains(nameof(IdentityErrorDescriber.DuplicateUserName)))
        {
            return CkMethodOutcome<UserCreateUserResult>.Fail(UserAlreadyExists, ("field", "userName"));
        }

        if (codes.Contains(nameof(IdentityErrorDescriber.DuplicateEmail)))
        {
            return CkMethodOutcome<UserCreateUserResult>.Fail(UserAlreadyExists, ("field", "email"));
        }

        if (codes.Contains(nameof(IdentityErrorDescriber.InvalidUserName)))
        {
            return CkMethodOutcome<UserCreateUserResult>.ValidationFailed("userName", "invalid");
        }

        if (codes.Contains(nameof(IdentityErrorDescriber.InvalidEmail)))
        {
            return CkMethodOutcome<UserCreateUserResult>.ValidationFailed("email", "invalid");
        }

        var policy = codes.Where(c => c.StartsWith("Password", StringComparison.Ordinal)).ToList();
        if (policy.Count > 0)
        {
            // Codes of the failed rules only (PasswordTooShort, PasswordRequiresDigit, ...), never a value.
            logger.LogInformation(
                "User.CreateUser refused: the initial password violates the password policy ({RuleCount} rule(s))",
                policy.Count);
            return CkMethodOutcome<UserCreateUserResult>.Fail(new CkMethodFailure(PasswordPolicyViolation,
                details: policy.Select(c => new CkMethodErrorDetail { Code = c }).ToList()));
        }

        throw new InvalidOperationException(
            $"Creating the user failed ({string.Join(",", codes)}).");
    }
}
