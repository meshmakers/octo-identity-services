using IdentityServerPersistence.SystemStores;
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
///         cannot be added and a role that is not assigned cannot be removed. It has no further rule: no limit on the roles a
///         caller may grant and no protection of the last administrator (<c>UserManagement</c> holders may grant every role,
///         to everyone including themselves). The methods implement exactly this list. The gateway checks the declared role
///         before dispatch; the handler checks the same rule again on the principal the host validated from the forwarded
///         access token, so a forged bus message is refused here (<c>METHOD_FORBIDDEN</c> / <c>role-required</c>).
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
    /// <summary>Scope that the REST write policy requires (<c>CommonConstants.OctoApiFullAccess</c>).</summary>
    private const string RequiredScope = CommonConstants.OctoApiFullAccess;

    public async Task<CkMethodOutcome> HandleAsync(CkMethodContext<TParameters> context,
        CancellationToken cancellationToken)
    {
        var change = new UserRoleChange();
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

    private async Task<CkMethodOutcome> RunAsync(CkMethodContext<TParameters> context, UserRoleChange change,
        CancellationToken cancellationToken)
    {
        if (!IsAdministrator(context.CallerPrincipal))
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
            throw new InvalidOperationException("The user store of the identity service is not the OctoUserStore."));
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

    /// <summary>
    ///     The same rule as the REST write policy: scope <c>octo_api</c> and tenant role <c>UserManagement</c> on the principal
    ///     the host validated (never the informational <c>Caller</c> of the request).
    /// </summary>
    private static bool IsAdministrator(CkMethodPrincipal? principal) =>
        principal != null &&
        principal.Scopes.Contains(RequiredScope, StringComparer.Ordinal) &&
        principal.Roles.Contains(CommonConstants.UserManagementRole, StringComparer.OrdinalIgnoreCase);

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

    public IReadOnlyDictionary<string, string>? ToAuditDetails() => !Loaded
        ? null
        : new Dictionary<string, string>
        {
            ["rolesBefore"] = string.Join(",", Before.Order(StringComparer.OrdinalIgnoreCase)),
            ["rolesAfter"] = string.Join(",", After.Order(StringComparer.OrdinalIgnoreCase))
        };
}

/// <summary>The identity services of one invocation (resolved after the tenant is bound).</summary>
internal sealed class UserRoleScope(
    UserManager<RtUser> userManager,
    RoleManager<RtRole> roleManager,
    OctoUserStore userStore)
{
    public UserManager<RtUser> UserManager { get; } = userManager;

    public async Task<IReadOnlyList<string>> GetDirectRolesAsync(RtUser user) =>
        (await userStore.GetDirectRolesAsync(user).ConfigureAwait(false)).ToList();

    /// <summary>The role by name (the lookup of the REST endpoints), or <c>null</c>.</summary>
    public Task<RtRole?> FindRoleAsync(string roleName) => roleManager.FindByNameAsync(roleName);

    /// <summary>The same normalization REST applies to the names of the direct roles.</summary>
    public static string Normalize(string roleName) => roleName.ToUpperInvariant();
}
