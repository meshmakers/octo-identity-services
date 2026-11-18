using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Shared flow of the static create methods of the identity administration types (<c>Role.CreateRole</c>,
///     <c>Group.CreateGroup</c>, <c>ApiScope.CreateApiScope</c>, <c>ApiResource.CreateApiResource</c>; System.Identity 3.7.0):
///     caller rule on the validated principal, tenant binding, the caller's <c>Write</c> permission on the declaring type (the
///     GraphQL gateway checks it before it dispatches a static method; a REST facade calls in-process, where only the handler
///     can check it), the create itself, and exactly one <c>Identity.Method</c> event per call with the new entity's rtId as
///     target (success, every refusal, <c>METHOD_HANDLER_FAILED</c> for an exception).
/// </summary>
/// <typeparam name="TParameters">The generated parameters of the method.</typeparam>
/// <typeparam name="TResult">The generated result of the method: the rtId of the new entity.</typeparam>
internal abstract class IdentityCreateMethodHandlerBase<TParameters, TResult>(IServiceProvider services)
    : ICkMethodHandler<TParameters, TResult> where TParameters : class where TResult : class
{
    /// <summary>The declaring CK type of the method (the type whose <c>Write</c> permission the caller needs).</summary>
    protected abstract RtCkId<CkTypeId> DeclaringType { get; }

    public async Task<CkMethodOutcome<TResult>> HandleAsync(CkMethodContext<TParameters> context,
        CancellationToken cancellationToken)
    {
        var principal = context.CallerPrincipal;
        var call = principal == null ? null : new IdentityMethodCall(services, principal);
        string? createdRtId = null;
        var outcomeCode = CkMethodErrorCodes.MethodHandlerFailed;
        try
        {
            var outcome = await RunAsync(context, call, cancellationToken).ConfigureAwait(false);
            outcomeCode = outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome;
            createdRtId = outcome.Failure == null && outcome.Value != null ? CreatedRtIdOf(outcome.Value) : null;
            return outcome;
        }
        finally
        {
            // One audit record per call, also when the call throws (the host answers METHOD_HANDLER_FAILED then).
            await services.GetRequiredService<IIdentityMethodAuditWriter>().RecordAsync(context.TenantId,
                    context.MethodId, context.InvocationId, createdRtId, principal?.Subject, outcomeCode,
                    call?.Details.Count > 0 ? call.Details : null)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    ///     The caller rule of the method on the validated principal. Default: the user administration rule
    ///     (<see cref="IdentityMethodCallerRules.IsAdministrator" />); the resource methods use the tenant administration rule.
    /// </summary>
    protected virtual bool IsAdmitted(CkMethodPrincipal principal) => IdentityMethodCallerRules.IsAdministrator(principal);

    /// <summary>Creates the entity; the caller is admitted, the tenant is bound and the caller may write the type.</summary>
    protected abstract Task<CkMethodOutcome<TResult>> CreateAsync(IdentityMethodCall call, TParameters parameters,
        CancellationToken cancellationToken);

    /// <summary>The rtId of the new entity in the result (the audit target).</summary>
    protected abstract string? CreatedRtIdOf(TResult result);

    private async Task<CkMethodOutcome<TResult>> RunAsync(CkMethodContext<TParameters> context, IdentityMethodCall? call,
        CancellationToken cancellationToken)
    {
        if (call == null || !IsAdmitted(call.Principal))
        {
            return CkMethodOutcome<TResult>.Forbidden("role-required");
        }

        if (!await services.GetRequiredService<IMethodTenantAccessor>().BindAsync(context.TenantId)
                .ConfigureAwait(false))
        {
            return CkMethodOutcome<TResult>.TargetNotFound();
        }

        if (await call.CheckTypeWritableAsync(DeclaringType, cancellationToken).ConfigureAwait(false) is { } denied)
        {
            return CkMethodOutcome<TResult>.Fail(denied);
        }

        return await CreateAsync(call, context.Parameters, cancellationToken).ConfigureAwait(false);
    }
}
