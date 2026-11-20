using Meshmakers.Octo.Backend.IdentityServices.Authorization;
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

    /// <summary>
    ///     <c>true</c> when the validated principal may use the client administration methods: scope <c>octo_api</c> and one of
    ///     the roles of <c>IdentityTenantAdministrationWritePolicy</c> (<c>TenantManagement</c> or <c>UserManagement</c>), the
    ///     REST policy of the client endpoints.
    /// </summary>
    public static bool IsTenantAdministrator(CkMethodPrincipal? principal) =>
        principal != null &&
        principal.Scopes.Contains(RequiredScope, StringComparer.Ordinal) &&
        IdentityApiAuthorizationPolicies.TenantAdministrationRoles.Any(role =>
            principal.Roles.Contains(role, StringComparer.OrdinalIgnoreCase));

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

    /// <summary>
    ///     The CK type id the request names (<see cref="CkMethodRequest.CkTypeId" />: the mutation the method was called on, or
    ///     the type a REST facade passes). Set by the CRUD handler bases; a handler of a method inherited by several concrete
    ///     types (the identity provider methods, System.Identity 3.8.0) reads the concrete type from it and validates it.
    /// </summary>
    public string? RequestedCkTypeId { get; init; }

    /// <summary>Records the refusal of the role change guard and returns the <c>METHOD_FORBIDDEN</c> answer.</summary>
    public CkMethodOutcome Refuse(RoleChangeDecision decision)
    {
        Details["reason"] = decision.Reason!;
        var parameters = new Dictionary<string, string> { ["reason"] = decision.Reason! };
        if (decision.Reason is RoleChangeReasons.RoleNotHeld or RoleChangeReasons.BuiltInRole)
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

    /// <summary>
    ///     The data permission of the call's target itself: <c>null</c> when the caller may write it, else the answer
    ///     - <c>METHOD_TARGET_NOT_FOUND</c> for a target the caller cannot read (its existence is not told), <c>METHOD_FORBIDDEN</c>
    ///     (<c>reason</c> = <c>data-permission</c>) for one they may read but not write. The GraphQL gateway checks the declared
    ///     <c>dataAccess: Write</c> before dispatch; a REST facade calls in-process, where only the handler can check it.
    /// </summary>
    public async Task<CkMethodOutcome?> CheckTargetWritableAsync(RtEntityId target, CancellationToken cancellationToken)
    {
        var verdict = await EvaluateAsync(target, RtDataAction.Write, cancellationToken).ConfigureAwait(false);
        return verdict.Decision switch
        {
            RtDataPermissionDecision.Allowed => null,
            RtDataPermissionDecision.NotVisible => CkMethodOutcome.TargetNotFound(),
            _ => NotPermitted()
        };
    }

    /// <summary>
    ///     The data permission of a static method's declaring type, as the GraphQL gateway evaluates it before it dispatches
    ///     a static method with <c>dataAccess: Write</c>: <c>null</c> when the caller may write entities of
    ///     <paramref name="ckTypeId" /> in the tenant of the call, else <c>METHOD_TARGET_NOT_FOUND</c> (type not visible) or
    ///     <c>METHOD_FORBIDDEN</c> (<c>reason</c> = <c>data-permission</c>). A REST facade calls in-process, where only the
    ///     handler can check it.
    /// </summary>
    public async Task<CkMethodFailure?> CheckTypeWritableAsync(RtCkId<CkTypeId> ckTypeId,
        CancellationToken cancellationToken)
    {
        var repository = Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        var verdict = await Services.GetRequiredService<IRtDataPermissionEvaluator>()
            .EvaluateTypeAsync(repository, IdentityMethodCallerRules.ToSecurityContext(Principal), ckTypeId,
                RtDataAction.Write, publishAudit: true, cancellationToken)
            .ConfigureAwait(false);
        return verdict.Decision switch
        {
            RtDataPermissionDecision.Allowed => null,
            RtDataPermissionDecision.NotVisible => CkMethodOutcome.TargetNotFound().Failure,
            // Anything else, also a value a later engine adds, refuses.
            _ => NotPermitted().Failure
        };
    }

    /// <summary>
    ///     The target entity of an instance method: the declaring CK type of <paramref name="methodId" /> (the qualified id
    ///     the handler is registered for, <c>System.Identity/Group.AddMember-1</c> -> <c>System.Identity/Group</c>) and the
    ///     target rtId. Taken from the method id, never from the CK type id a request names.
    /// </summary>
    public static RtEntityId TargetOf(string methodId, OctoObjectId targetRtId)
    {
        var typeEnd = methodId.LastIndexOf('.');
        if (typeEnd <= 0)
        {
            throw new ArgumentException($"'{methodId}' is not a qualified method id.", nameof(methodId));
        }

        return new RtEntityId($"{methodId[..typeEnd]}@{targetRtId}");
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
        var call = principal == null
            ? null
            : new IdentityMethodCall(services, principal) { RequestedCkTypeId = context.Request.CkTypeId };
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

    /// <summary>
    ///     The caller rule of the method, checked on the validated principal before the target is looked up. Default: the user
    ///     administration rule (<see cref="IdentityMethodCallerRules.IsAdministrator" />); the client methods use the tenant
    ///     administration rule of their REST policy.
    /// </summary>
    protected virtual bool IsAdmitted(CkMethodPrincipal principal) => IdentityMethodCallerRules.IsAdministrator(principal);

    /// <summary>Applies the method on the target (<paramref name="targetRtId" />); the caller is an administrator and the tenant is bound.</summary>
    protected abstract Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        TParameters parameters, CancellationToken cancellationToken);

    /// <summary>
    ///     The target entity whose data permission the caller needs. Default: the declaring CK type of the method id
    ///     (<see cref="IdentityMethodCall.TargetOf" />). A method inherited by several concrete types answers the concrete type
    ///     of the call; <c>null</c> is <c>METHOD_TARGET_NOT_FOUND</c> (the type of the call has no such target).
    /// </summary>
    protected virtual RtEntityId? TargetEntityOf(IdentityMethodCall call, string methodId, OctoObjectId targetRtId) =>
        IdentityMethodCall.TargetOf(methodId, targetRtId);

    private async Task<CkMethodOutcome> RunAsync(CkMethodContext<TParameters> context, IdentityMethodCall? call,
        CancellationToken cancellationToken)
    {
        if (call == null || !IsAdmitted(call.Principal))
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

        // CWE-863: the caller must be able to read and write the target itself, whatever the transport. The GraphQL gateway
        // checks the declared dataAccess before dispatch; a REST facade calls in-process, where only the handler can check
        // it. Same answers as the gateway: not readable = METHOD_TARGET_NOT_FOUND, read only = METHOD_FORBIDDEN
        // (reason data-permission).
        if (TargetEntityOf(call, context.MethodId, target) is not { } targetEntity)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        if (await call.CheckTargetWritableAsync(targetEntity, cancellationToken)
                .ConfigureAwait(false) is { } denied)
        {
            return denied;
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
