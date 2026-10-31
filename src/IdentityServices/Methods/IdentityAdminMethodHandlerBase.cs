using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     The rule every administrative identity method repeats on the validated caller: the same as the REST write policy
///     (<c>IdentityUserAdministrationWritePolicy</c>): scope <c>octo_api</c> and tenant role <c>UserManagement</c>. The
///     gateway checks the declared role before dispatch; the handler checks again on the principal the host validated from the
///     forwarded access token, so a forged bus message is refused here (AB#7776, AB#7779).
/// </summary>
internal static class IdentityMethodCallerRules
{
    private const string RequiredScope = CommonConstants.OctoApiFullAccess;

    /// <summary><c>true</c> when the validated principal may use the administrative identity methods.</summary>
    public static bool IsAdministrator(CkMethodPrincipal? principal) =>
        principal != null &&
        principal.Scopes.Contains(RequiredScope, StringComparer.Ordinal) &&
        principal.Roles.Contains(CommonConstants.UserManagementRole, StringComparer.OrdinalIgnoreCase);

    /// <summary>The caller as the role change guard and the data-permission evaluator see it.</summary>
    public static RoleChangeCaller ToRoleChangeCaller(CkMethodPrincipal? principal) =>
        new(principal?.SubjectId, principal?.ClientId, principal?.Roles ?? []);

    /// <summary>The same security context a repository session of this caller would carry.</summary>
    public static RtSecurityContext ToSecurityContext(CkMethodPrincipal principal) =>
        RtSecurityContext.ForUser(principal.SubjectId ?? principal.ClientId, principal.Roles);
}

/// <summary>The state of one call of an administrative identity method, shared by the handler and its audit record.</summary>
internal sealed class IdentityMethodCall(IServiceProvider services, CkMethodPrincipal principal)
{
    /// <summary>The services of the invocation scope (resolved after the tenant is bound).</summary>
    public IServiceProvider Services { get; } = services;

    /// <summary>The validated caller.</summary>
    public CkMethodPrincipal Principal { get; } = principal;

    /// <summary>The caller for the role change guard.</summary>
    public RoleChangeCaller Caller { get; } = IdentityMethodCallerRules.ToRoleChangeCaller(principal);

    /// <summary>Non-secret facts of the call for the <c>Identity.Method</c> event (identifiers, role names, reason).</summary>
    public Dictionary<string, string> Details { get; } = new(StringComparer.Ordinal);

    /// <summary>Records the refusal of the role change guard and returns the <c>METHOD_FORBIDDEN</c> answer.</summary>
    public CkMethodOutcome Refuse(RoleChangeDecision decision)
    {
        Details["reason"] = decision.Reason!;
        var parameters = new Dictionary<string, string> { ["reason"] = decision.Reason! };
        if (decision.Reason == RoleChangeReasons.RoleNotHeld)
        {
            var names = string.Join(",", decision.RoleNames);
            parameters["roleNames"] = names;
            Details["roleNames"] = names;
        }

        return CkMethodOutcome.Fail(new CkMethodFailure(CkMethodErrorCodes.MethodForbidden, parameters));
    }

    /// <summary>
    ///     Asks the engine (AB#7035) whether the caller may perform <paramref name="action" /> on an entity the method
    ///     touches besides its target (a member, a role). Not visible answers like a missing entity, not permitted like a refusal.
    /// </summary>
    public async Task<RtDataPermissionVerdict> EvaluateAsync(RtEntityId entity, RtDataAction action,
        CancellationToken cancellationToken)
    {
        var repository = Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        return await Services.GetRequiredService<IRtDataPermissionEvaluator>()
            .EvaluateAsync(repository, IdentityMethodCallerRules.ToSecurityContext(Principal), entity, action,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>The <c>METHOD_FORBIDDEN</c> answer for a referenced entity the caller may see but not change.</summary>
    public CkMethodOutcome NotPermitted()
    {
        Details["reason"] = "data-permission";
        return CkMethodOutcome.Fail(new CkMethodFailure(CkMethodErrorCodes.MethodForbidden,
            new Dictionary<string, string> { ["reason"] = "data-permission" }));
    }
}

/// <summary>
///     Shared flow of the administrative identity methods that are not about one user's roles (<c>Group.*</c>,
///     <c>DataPermission.*</c>; AB#7779): caller check, target id, tenant binding, the handler's own rules, and exactly one
///     <c>Identity.Method</c> event per call (success and every refusal; <c>METHOD_HANDLER_FAILED</c> for an exception).
/// </summary>
internal abstract class IdentityAdminMethodHandlerBase<TParameters>(IServiceProvider services)
    : ICkMethodHandler<TParameters> where TParameters : class
{
    public async Task<CkMethodOutcome> HandleAsync(CkMethodContext<TParameters> context,
        CancellationToken cancellationToken)
    {
        var principal = context.CallerPrincipal;
        var call = principal == null ? null : new IdentityMethodCall(services, principal);
        CkMethodOutcome outcome;
        try
        {
            outcome = await RunAsync(context, call, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await AuditAsync(context, "METHOD_HANDLER_FAILED", call).ConfigureAwait(false);
            throw;
        }

        await AuditAsync(context, outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome, call)
            .ConfigureAwait(false);
        return outcome;
    }

    /// <summary>Applies the method on the target (<paramref name="targetRtId" />); the caller is an administrator and the tenant is bound.</summary>
    protected abstract Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        TParameters parameters, CancellationToken cancellationToken);

    private async Task<CkMethodOutcome> RunAsync(CkMethodContext<TParameters> context, IdentityMethodCall? call,
        CancellationToken cancellationToken)
    {
        if (call == null || !IdentityMethodCallerRules.IsAdministrator(call.Principal))
        {
            return CkMethodOutcome.Forbidden("role-required");
        }

        // A target that is not an object id cannot exist (the stores would throw on it).
        if (string.IsNullOrWhiteSpace(context.TargetRtId) || !OctoObjectId.TryParse(context.TargetRtId, out var target))
        {
            return CkMethodOutcome.TargetNotFound();
        }

        if (!await services.GetRequiredService<IMethodTenantAccessor>().BindAsync(context.TenantId)
                .ConfigureAwait(false))
        {
            return CkMethodOutcome.TargetNotFound();
        }

        return await ApplyAsync(call, target, context.Parameters, cancellationToken).ConfigureAwait(false);
    }

    private async Task AuditAsync(CkMethodContext<TParameters> context, string outcome, IdentityMethodCall? call)
    {
        var audit = services.GetRequiredService<IIdentityMethodAuditWriter>();
        await audit.RecordAsync(context.TenantId, context.MethodId, context.InvocationId, context.TargetRtId,
            context.CallerPrincipal?.Subject, outcome, call?.Details.Count > 0 ? call.Details : null)
            .ConfigureAwait(false);
    }
}
