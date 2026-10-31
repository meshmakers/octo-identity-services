using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the user role methods (declared in <c>ck-user.yaml</c>).</summary>
internal static class UserRoleMethodErrors
{
    public const string RoleNotFound = "ROLE_NOT_FOUND";
    public const string RoleAlreadyAssigned = "ROLE_ALREADY_ASSIGNED";
    public const string RoleNotAssigned = "ROLE_NOT_ASSIGNED";

    /// <summary>Name of the parameter of a <c>ROLE_NOT_FOUND</c> answer that carries the unknown role name.</summary>
    public const string RoleNameParameter = "roleName";
}

/// <summary>
///     Shared flow of <c>User.SetRoles</c>, <c>User.AddRole</c> and <c>User.RemoveRole</c> (AB#7776): the same rules as the
///     REST endpoints <c>PUT/DELETE system/v1/users/{user}/roles[/{role}]</c> of <c>UsersController</c>, never more.
/// </summary>
/// <remarks>
///     <para>
///         <b>Parity with REST.</b> REST lets a caller change roles when the token carries the scope <c>octo_api</c> and the
///         tenant role <c>UserManagement</c> (<c>IdentityUserAdministrationWritePolicy</c>, enforcement mode
///         <c>Enforce</c>), the target user exists, the role exists (by name; SetRoles by id), a role that is already assigned
///         cannot be added and a role that is not assigned cannot be removed. On top of that both transports run the same
///         <see cref="IRoleChangeGuard" /> (AB#7914) on the difference of the direct roles: a caller cannot add a direct role
///         to their own user (<c>self-grant</c>), cannot grant a built-in role they do not hold (<c>role-not-held</c>) and
///         cannot remove the last user that effectively holds <c>UserManagement</c> (<c>last-administrator</c>). A refusal is
///         <c>METHOD_FORBIDDEN</c> with the parameter <c>reason</c> (and <c>roleNames</c> for <c>role-not-held</c>); no
///         declared error code, so the System.Identity model is unchanged. The gateway checks the declared role before
///         dispatch; the handler checks the same rule again on the principal the host validated from the forwarded access
///         token, so a forged bus message is refused here (<c>METHOD_FORBIDDEN</c> / <c>role-required</c>).
///     </para>
///     <para>
///         <b>Only direct roles</b> are read and written (<c>AssignedRole</c> association of the user); roles inherited from
///         groups are untouched, as in REST. Nothing is revoked: like REST, a role change shows in the next token.
///     </para>
///     <para>
///         <b>Audit.</b> One <c>Identity.Method</c> event per call (success and every refusal) with actor, target, outcome and
///         the direct roles before and after the call.
///     </para>
/// </remarks>
internal abstract class UserRoleMethodHandlerBase<TParameters>(IServiceProvider services)
    : ICkMethodHandler<TParameters> where TParameters : class
{
    public async Task<CkMethodOutcome> HandleAsync(CkMethodContext<TParameters> context,
        CancellationToken cancellationToken)
    {
        var change = new UserRoleChange
        {
            Caller = new RoleChangeCaller(context.CallerPrincipal?.SubjectId, context.CallerPrincipal?.ClientId,
                context.CallerPrincipal?.Roles ?? [])
        };
        CkMethodOutcome outcome;
        try
        {
            outcome = await RunAsync(context, change, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await AuditAsync(context, "METHOD_HANDLER_FAILED", change).ConfigureAwait(false);
            throw;
        }

        await AuditAsync(context, outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome, change)
            .ConfigureAwait(false);
        return outcome;
    }

    /// <summary>Applies the change of the method on <paramref name="user" />.</summary>
    protected abstract Task<CkMethodOutcome> ApplyAsync(UserRoleScope scope, TParameters parameters, RtUser user,
        UserRoleChange change, CancellationToken cancellationToken);

    /// <summary>
    ///     Runs the role change guard (AB#7914) on the change of <c>change.Before</c> to <paramref name="rolesAfter" />.
    ///     Returns the <c>METHOD_FORBIDDEN</c> answer, or <c>null</c> when the change is allowed. Call it after every other
    ///     validation and before the first write.
    /// </summary>
    protected static async Task<CkMethodOutcome?> GuardAsync(UserRoleScope scope, RtUser user, UserRoleChange change,
        IReadOnlyCollection<string> rolesAfter)
    {
        var decision = await scope.Guard.EvaluateAsync(new RoleChangeRequest(change.Caller, user, change.Before, rolesAfter))
            .ConfigureAwait(false);
        if (decision.IsAllowed)
        {
            return null;
        }

        change.RefusalReason = decision.Reason;
        change.RefusedRoleNames = decision.RoleNames;
        var parameters = new Dictionary<string, string> { ["reason"] = decision.Reason! };
        if (decision.Reason == RoleChangeReasons.RoleNotHeld)
        {
            parameters["roleNames"] = string.Join(",", decision.RoleNames);
        }

        return CkMethodOutcome.Fail(new CkMethodFailure(CkMethodErrorCodes.MethodForbidden, parameters));
    }

    private async Task<CkMethodOutcome> RunAsync(CkMethodContext<TParameters> context, UserRoleChange change,
        CancellationToken cancellationToken)
    {
        if (!IdentityMethodCallerRules.IsAdministrator(context.CallerPrincipal))
        {
            return CkMethodOutcome.Forbidden("role-required");
        }

        // A target that is not an object id cannot exist (the user store would throw on it).
        if (string.IsNullOrWhiteSpace(context.TargetRtId) || !OctoObjectId.TryParse(context.TargetRtId, out _))
        {
            return CkMethodOutcome.TargetNotFound();
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

        var scope = new UserRoleScope(userManager, services.GetRequiredService<RoleManager<RtRole>>(),
            services.GetRequiredService<IUserStore<RtUser>>() as OctoUserStore ??
            throw new InvalidOperationException("The user store of the identity service is not the OctoUserStore."),
            services.GetRequiredService<IRoleChangeGuard>());
        change.Before = await scope.GetDirectRolesAsync(user).ConfigureAwait(false);
        change.After = change.Before;
        change.Loaded = true;
        var outcome = await ApplyAsync(scope, context.Parameters, user, change, cancellationToken)
            .ConfigureAwait(false);
        if (outcome.IsSuccess)
        {
            change.After = await scope.GetDirectRolesAsync(user).ConfigureAwait(false);
        }

        return outcome;
    }

    private async Task AuditAsync(CkMethodContext<TParameters> context, string outcome, UserRoleChange change)
    {
        var audit = services.GetRequiredService<IIdentityMethodAuditWriter>();
        await audit.RecordAsync(context.TenantId, context.MethodId, context.InvocationId, context.TargetRtId,
            context.CallerPrincipal?.Subject, outcome, change.ToAuditDetails()).ConfigureAwait(false);
    }

    internal static CkMethodOutcome RoleNotFound(string roleName) =>
        CkMethodOutcome.Fail(new CkMethodFailure(UserRoleMethodErrors.RoleNotFound,
            new Dictionary<string, string> { [UserRoleMethodErrors.RoleNameParameter] = roleName }));
}

/// <summary>The direct roles of the target before and after the call, for the audit record.</summary>
internal sealed class UserRoleChange
{
    /// <summary>The direct roles before the call; empty until the target was loaded.</summary>
    public IReadOnlyList<string> Before { get; set; } = [];

    /// <summary>The direct roles after the call; empty until the target was loaded.</summary>
    public IReadOnlyList<string> After { get; set; } = [];

    /// <summary><c>true</c> once the target was loaded, so the roles are known (a refused caller never sees them).</summary>
    public bool Loaded { get; set; }

    /// <summary>The validated caller (subject, client id, roles), for the role change guard.</summary>
    public RoleChangeCaller Caller { get; init; } = new(null, null, []);

    /// <summary>Reason of a refusal by the role change guard (<c>self-grant</c>, <c>role-not-held</c>, <c>last-administrator</c>).</summary>
    public string? RefusalReason { get; set; }

    /// <summary>The roles a refusal is about (<c>role-not-held</c>: the roles the caller does not hold).</summary>
    public IReadOnlyList<string> RefusedRoleNames { get; set; } = [];

    public IReadOnlyDictionary<string, string>? ToAuditDetails()
    {
        if (!Loaded)
        {
            return null;
        }

        var details = new Dictionary<string, string>
        {
            ["rolesBefore"] = string.Join(",", Before.Order(StringComparer.OrdinalIgnoreCase)),
            ["rolesAfter"] = string.Join(",", After.Order(StringComparer.OrdinalIgnoreCase))
        };
        if (RefusalReason != null)
        {
            details["reason"] = RefusalReason;
            if (RefusedRoleNames.Count > 0)
            {
                details["roleNames"] = string.Join(",", RefusedRoleNames);
            }
        }

        return details;
    }
}

/// <summary>The identity services of one invocation (resolved after the tenant is bound).</summary>
internal sealed class UserRoleScope(
    UserManager<RtUser> userManager,
    RoleManager<RtRole> roleManager,
    OctoUserStore userStore,
    IRoleChangeGuard guard)
{
    public UserManager<RtUser> UserManager { get; } = userManager;

    /// <summary>The guard shared with the REST endpoints (AB#7914).</summary>
    public IRoleChangeGuard Guard { get; } = guard;

    public async Task<IReadOnlyList<string>> GetDirectRolesAsync(RtUser user) =>
        (await userStore.GetDirectRolesAsync(user).ConfigureAwait(false)).ToList();

    /// <summary>The role by name (the lookup of the REST endpoints), or <c>null</c>.</summary>
    public Task<RtRole?> FindRoleAsync(string roleName) => roleManager.FindByNameAsync(roleName);

    /// <summary>The same normalization REST applies to the names of the direct roles.</summary>
    public static string Normalize(string roleName) => roleName.ToUpperInvariant();
}
