using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the client mirror methods (declared in <c>ck-client.yaml</c>, System.Identity 3.5.0).</summary>
internal static class ClientMirrorMethodErrors
{
    public const string AutoProvisionDisabled = "AUTO_PROVISION_DISABLED";
    public const string BackfillNotStarted = "BACKFILL_NOT_STARTED";
    public const string MirrorNotFound = "MIRROR_NOT_FOUND";
    public const string ClientSecretNotRequired = "CLIENT_SECRET_NOT_REQUIRED";
    public const string ConcurrentChange = "CONCURRENT_CHANGE";

    /// <summary>Audit detail and error parameter: the child tenant of the call.</summary>
    public const string ChildTenantIdDetail = "childTenantId";
}

/// <summary>
///     Runs one call of an identity method and writes exactly one <c>Identity.Method</c> event for it: success, every refusal,
///     and <c>METHOD_HANDLER_FAILED</c> when the call throws.
/// </summary>
internal static class IdentityMethodAudit
{
    public static async Task<TOutcome> RunAsync<TParameters, TOutcome>(IServiceProvider services,
        CkMethodContext<TParameters> context, IdentityMethodCall? call, Func<Task<TOutcome>> run,
        Func<TOutcome, string?> failureCode) where TParameters : class
    {
        var outcomeCode = "METHOD_HANDLER_FAILED";
        try
        {
            var outcome = await run().ConfigureAwait(false);
            outcomeCode = failureCode(outcome) ?? IdentityMethodAuditWriter.SuccessOutcome;
            return outcome;
        }
        finally
        {
            await services.GetRequiredService<IIdentityMethodAuditWriter>().RecordAsync(context.TenantId,
                context.MethodId, context.InvocationId, context.TargetRtId, context.CallerPrincipal?.Subject, outcomeCode,
                call?.Details.Count > 0 ? call.Details : null).ConfigureAwait(false);
        }
    }
}

/// <summary>
///     Shared flow of the client mirror methods (System.Identity 3.5.0) on the parent client, the rules of the REST
///     endpoints of <c>ClientMirrorController</c> and <c>ClientAutoProvisionFlagController</c>, which are their facades.
/// </summary>
/// <remarks>
///     <para>
///         <b>Caller.</b> Scope <c>octo_api</c> and the REST role rule: <c>TenantManagement</c> or <c>UserManagement</c>
///         (<see cref="IdentityMethodCallerRules.IsTenantAdministrator" />); the secret rotation overrides it with the secret
///         rule of the REST policy (<c>SecretManagement</c>, staged).
///     </para>
///     <para>
///         <b>Target.</b> The parent client in the tenant of the call. A client the caller cannot read is
///         <c>METHOD_TARGET_NOT_FOUND</c>, one they may read but not write <c>METHOD_FORBIDDEN</c> (<c>reason</c> =
///         <c>data-permission</c>), before anything is written in either tenant.
///     </para>
///     <para>
///         <b>Child tenant.</b> A method that names a child tenant checks it twice before any write: against the caller's
///         token tenant (<see cref="CrossTenantMethodSupport.CheckTargetTenantAsync" />, the rule of the REST filter) and,
///         in <see cref="IClientMirrorProvisioningService" />, against the parent tenant's subtree. Either refusal is
///         <c>METHOD_FORBIDDEN</c> with <c>reason</c> = <c>tenant-out-of-scope</c>; nothing is written in the child tenant.
///     </para>
///     <para>
///         <b>Audit.</b> One <c>Identity.Method</c> event per call with <c>clientId</c> and <c>childTenantId</c>; never a
///         secret or hash.
///     </para>
/// </remarks>
internal abstract class ClientMirrorMethodHandlerBase<TParameters, TOutcome>(IServiceProvider services)
    where TParameters : class
{
    protected IServiceProvider Services { get; } = services;

    /// <summary>The caller rule; <c>null</c> when admitted, else the refusal.</summary>
    protected virtual CkMethodFailure? Admit(CkMethodPrincipal? principal, string tenantId) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal)
            ? null
            : CkMethodOutcome.Forbidden("role-required").Failure;

    /// <summary>Turns a failure into the outcome of the method.</summary>
    protected abstract TOutcome Failed(CkMethodFailure failure);

    /// <summary>The failure code of an outcome (for the audit record); <c>null</c> on success.</summary>
    protected abstract string? FailureCode(TOutcome outcome);

    /// <summary>Applies the method; the caller is admitted, the tenant bound and the client readable and writable.</summary>
    protected abstract Task<TOutcome> ApplyAsync(IdentityMethodCall call, RtClient client, TParameters parameters,
        string tenantId, CancellationToken cancellationToken);

    protected Task<TOutcome> RunAsync(CkMethodContext<TParameters> context, CancellationToken cancellationToken)
    {
        var call = context.CallerPrincipal == null ? null : new IdentityMethodCall(Services, context.CallerPrincipal);
        return IdentityMethodAudit.RunAsync(Services, context, call, () => RunCoreAsync(context, call, cancellationToken),
            FailureCode);
    }

    private async Task<TOutcome> RunCoreAsync(CkMethodContext<TParameters> context, IdentityMethodCall? call,
        CancellationToken cancellationToken)
    {
        if (call == null)
        {
            return Failed(CkMethodOutcome.Forbidden("role-required").Failure!);
        }

        if (Admit(call.Principal, context.TenantId) is { } refused)
        {
            return Failed(refused);
        }

        if (string.IsNullOrWhiteSpace(context.TargetRtId) || !OctoObjectId.TryParse(context.TargetRtId, out var target) ||
            !await Services.GetRequiredService<IMethodTenantAccessor>().BindAsync(context.TenantId).ConfigureAwait(false))
        {
            return Failed(CkMethodOutcome.TargetNotFound().Failure!);
        }

        var client = await ClientRoleMethodHandlerBase<TParameters>.LoadClientAsync(Services, target)
            .ConfigureAwait(false);
        if (client == null || string.IsNullOrWhiteSpace(client.ClientId))
        {
            return Failed(CkMethodOutcome.TargetNotFound().Failure!);
        }

        // CWE-863: the caller must be able to read and write the parent client before anything changes in either tenant.
        if (await call.CheckTargetWritableAsync(client.ToRtEntityId(), cancellationToken).ConfigureAwait(false) is
            { } notWritable)
        {
            return Failed(notWritable.Failure!);
        }

        call.Details[ClientSecretMethodHandlerBase.ClientIdDetail] = client.ClientId;
        return await ApplyAsync(call, client, context.Parameters, context.TenantId, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    ///     Validates <paramref name="childTenantId" /> and checks it against the caller's tenant subtree; the failure, or
    ///     <c>null</c>.
    /// </summary>
    protected static async Task<CkMethodFailure?> CheckChildTenantAsync(IdentityMethodCall call, string methodId,
        string? childTenantId)
    {
        if (string.IsNullOrWhiteSpace(childTenantId))
        {
            return CrossTenantMethodSupport.ValidationFailed(ClientMirrorMethodErrors.ChildTenantIdDetail);
        }

        call.Details[ClientMirrorMethodErrors.ChildTenantIdDetail] = childTenantId;
        return await CrossTenantMethodSupport.CheckTargetTenantAsync(call, methodId, childTenantId).ConfigureAwait(false);
    }

    protected IClientMirrorProvisioningService MirrorService =>
        Services.GetRequiredService<IClientMirrorProvisioningService>();
}

/// <summary>Base of the mirror methods with a result record or value.</summary>
internal abstract class ClientMirrorResultHandlerBase<TParameters, TResult>(IServiceProvider services)
    : ClientMirrorMethodHandlerBase<TParameters, CkMethodOutcome<TResult>>(services),
        ICkMethodHandler<TParameters, TResult> where TParameters : class where TResult : class
{
    public Task<CkMethodOutcome<TResult>> HandleAsync(CkMethodContext<TParameters> context,
        CancellationToken cancellationToken) => RunAsync(context, cancellationToken);

    protected sealed override CkMethodOutcome<TResult> Failed(CkMethodFailure failure) =>
        CkMethodOutcome<TResult>.Fail(failure);

    protected sealed override string? FailureCode(CkMethodOutcome<TResult> outcome) => outcome.Failure?.Code;
}

/// <summary>Base of the mirror methods without a result.</summary>
internal abstract class ClientMirrorVoidHandlerBase<TParameters>(IServiceProvider services)
    : ClientMirrorMethodHandlerBase<TParameters, CkMethodOutcome>(services), ICkMethodHandler<TParameters>
    where TParameters : class
{
    public Task<CkMethodOutcome> HandleAsync(CkMethodContext<TParameters> context, CancellationToken cancellationToken) =>
        RunAsync(context, cancellationToken);

    protected sealed override CkMethodOutcome Failed(CkMethodFailure failure) => CkMethodOutcome.Fail(failure);

    protected sealed override string? FailureCode(CkMethodOutcome outcome) => outcome.Failure?.Code;
}

/// <summary>
///     Handler of <c>System.Identity/Client.ProvisionMirrors-1</c>: the backfill of every flagged client of the tenant into
///     every existing child tenant. REST facade: <c>POST {tenant}/v1/clients/{clientId}/mirrors/provisionInExistingTenants</c>.
///     The target client must carry <c>AutoProvisionInChildTenants</c> (<c>AUTO_PROVISION_DISABLED</c>). The child tenants
///     come from the tenant registry (direct children; every tenant for the system tenant). The tenant of the call itself must
///     lie in the caller's tenant subtree (the target rule of <see cref="CrossTenantMethodSupport.CheckTargetTenantAsync" />).
/// </summary>
internal sealed class ClientProvisionMirrorsHandler(IServiceProvider services)
    : ClientMirrorResultHandlerBase<ClientProvisionMirrorsParameters, ClientProvisionMirrorsResult>(services)
{
    protected override async Task<CkMethodOutcome<ClientProvisionMirrorsResult>> ApplyAsync(IdentityMethodCall call,
        RtClient client, ClientProvisionMirrorsParameters parameters, string tenantId, CancellationToken cancellationToken)
    {
        // The backfill writes into the children of the tenant of the call: an allow-listed cross-tenant service client may
        // call in a tenant outside its own subtree, so that tenant is judged by the target rule like a named child tenant.
        if (await CrossTenantMethodSupport.CheckTargetTenantAsync(call, SystemIdentityCkIds.ClientProvisionMirrorsMethodId,
                tenantId).ConfigureAwait(false) is { } outOfScope)
        {
            return outOfScope;
        }

        if (!client.AutoProvisionInChildTenants)
        {
            return new CkMethodFailure(ClientMirrorMethodErrors.AutoProvisionDisabled);
        }

        var result = await MirrorService.ProvisionForAllChildTenantsAsync(tenantId, client.ClientId!)
            .ConfigureAwait(false);
        if (result == null)
        {
            return new CkMethodFailure(ClientMirrorMethodErrors.BackfillNotStarted);
        }

        call.Details["newlyProvisioned"] = result.NewlyProvisioned.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return new ClientProvisionMirrorsResult
        {
            Value = new RtClientMirrorBackfillResultRecord
            {
                ChildTenantsConsidered = result.ChildTenantsConsidered,
                NewlyProvisioned = result.NewlyProvisioned,
                AlreadyPresent = result.AlreadyPresent
            }
        };
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.ProvisionMirrorInTenant-1</c>: provisions the flagged clients of the tenant into
///     one child tenant. REST facade: <c>POST {tenant}/v1/clients/{clientId}/mirrors/provisionInTenant?childTenantId=</c>.
/// </summary>
internal sealed class ClientProvisionMirrorInTenantHandler(IServiceProvider services)
    : ClientMirrorResultHandlerBase<ClientProvisionMirrorInTenantParameters, ClientProvisionMirrorInTenantResult>(services)
{
    protected override async Task<CkMethodOutcome<ClientProvisionMirrorInTenantResult>> ApplyAsync(
        IdentityMethodCall call, RtClient client, ClientProvisionMirrorInTenantParameters parameters, string tenantId,
        CancellationToken cancellationToken)
    {
        if (await CheckChildTenantAsync(call, SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
                parameters.ChildTenantId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (!client.AutoProvisionInChildTenants)
        {
            return new CkMethodFailure(ClientMirrorMethodErrors.AutoProvisionDisabled);
        }

        ClientMirrorProvisioningResult result;
        try
        {
            result = await MirrorService.ProvisionInTenantAsync(tenantId, client.ClientId!, parameters.ChildTenantId)
                .ConfigureAwait(false);
        }
        catch (ClientMirrorScopeException)
        {
            return CrossTenantMethodSupport.OutOfScope(call);
        }

        return new ClientProvisionMirrorInTenantResult
        {
            Value = new RtClientMirrorProvisionResultRecord
            {
                FlaggedClientsConsidered = result.FlaggedClientsConsidered,
                NewlyProvisioned = result.NewlyProvisioned,
                AlreadyPresent = result.AlreadyPresent
            }
        };
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.RotateMirrorSecret-1</c>: issues a fresh own secret for the mirror of the client
///     in one child tenant and returns it once as the sensitive result. REST facade:
///     <c>POST {tenant}/v1/clients/{clientId}/mirrors/{childTenantId}/secret</c>.
/// </summary>
/// <remarks>
///     Caller rule of the REST policy <c>IdentitySecretAdministrationPolicy</c>: <c>SecretManagement</c>, staged by
///     <c>SecretManagementRoleEnforcement</c> (as the secret methods) - for a call of its REST facade only; a call over the
///     bus or the GraphQL gateway is never staged. The mirror is identified by its tracking row; an
///     untracked pair is <c>MIRROR_NOT_FOUND</c>, a public client <c>CLIENT_SECRET_NOT_REQUIRED</c>. The secret is minted,
///     hashed and stored by <see cref="IClientMirrorProvisioningService.RotateMirrorSecretAsync" /> (marked as the mirror's
///     own secret, so the mirror sync keeps it); the clear text goes only into the result, never into a log, audit detail or
///     trace. Carries a secret: offered on the bus only with <c>EnablePasswordMethods</c>, else local only for its facade.
/// </remarks>
internal sealed class ClientRotateMirrorSecretHandler(IServiceProvider services)
    : ClientMirrorResultHandlerBase<ClientRotateMirrorSecretParameters, ClientRotateMirrorSecretResult>(services)
{
    protected override CkMethodFailure? Admit(CkMethodPrincipal? principal, string tenantId)
    {
        var decision = SecretOwnerMethodHandlerBase<RtClient>.DecideSecretCaller(principal,
            Services.GetRequiredService<IOptionsMonitor<IdentityApiAuthorizationOptions>>().CurrentValue);
        // The staged Warn exists for existing REST callers. A call that did not come from a REST facade of this process
        // (the GraphQL gateway, the bus) is a new path and is never staged: decided by the transport, not by the principal.
        if (decision == IdentityApiRoleDecision.AllowedByStagedWarn &&
            (principal == null || !CrossTenantMethodSupport.IsRestFacadeCall(principal)))
        {
            decision = IdentityApiRoleDecision.Denied;
        }

        if (decision == IdentityApiRoleDecision.AllowedByStagedWarn)
        {
            Services.GetRequiredService<ILogger<ClientRotateMirrorSecretHandler>>().LogWarning(
                "Identity client secret method without required role allowed by SecretManagementRoleEnforcement=Warn in tenant {TenantId} by subject {Subject} / client {ClientId}, required any of [{RequiredRoles}]. " +
                "This would be denied with SecretManagementRoleEnforcement=Enforce",
                tenantId, principal?.SubjectId, principal?.ClientId, CommonConstants.SecretManagementRole);
        }

        return decision == IdentityApiRoleDecision.Denied
            ? SecretOwnerMethodHandlerBase<RtClient>.CallerForbidden()
            : null;
    }

    protected override async Task<CkMethodOutcome<ClientRotateMirrorSecretResult>> ApplyAsync(IdentityMethodCall call,
        RtClient client, ClientRotateMirrorSecretParameters parameters, string tenantId,
        CancellationToken cancellationToken)
    {
        if (await CheckChildTenantAsync(call, SystemIdentityCkIds.ClientRotateMirrorSecretMethodId,
                parameters.ChildTenantId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        MirrorSecretRotationResult? result;
        try
        {
            result = await MirrorService.RotateMirrorSecretAsync(tenantId, client.ClientId!, parameters.ChildTenantId)
                .ConfigureAwait(false);
        }
        catch (ClientMirrorScopeException)
        {
            return CrossTenantMethodSupport.OutOfScope(call);
        }

        if (result == null)
        {
            return new CkMethodFailure(ClientMirrorMethodErrors.MirrorNotFound);
        }

        if (result.NotApplicable || string.IsNullOrEmpty(result.Secret))
        {
            return new CkMethodFailure(ClientMirrorMethodErrors.ClientSecretNotRequired);
        }

        return new ClientRotateMirrorSecretResult { Value = result.Secret };
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.RemoveMirror-1</c>: removes the mirror of the client in one child tenant (the
///     client there and the tracking row). REST facade: <c>DELETE {tenant}/v1/clients/{clientId}/mirrors/{childTenantId}</c>.
///     An untracked pair is <c>MIRROR_NOT_FOUND</c>.
/// </summary>
internal sealed class ClientRemoveMirrorHandler(IServiceProvider services)
    : ClientMirrorVoidHandlerBase<ClientRemoveMirrorParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, RtClient client,
        ClientRemoveMirrorParameters parameters, string tenantId, CancellationToken cancellationToken)
    {
        if (await CheckChildTenantAsync(call, SystemIdentityCkIds.ClientRemoveMirrorMethodId, parameters.ChildTenantId)
                .ConfigureAwait(false) is { } refused)
        {
            return CkMethodOutcome.Fail(refused);
        }

        bool removed;
        try
        {
            removed = await MirrorService.RemoveMirrorAsync(tenantId, client.ClientId!, parameters.ChildTenantId)
                .ConfigureAwait(false);
        }
        catch (ClientMirrorScopeException)
        {
            return CkMethodOutcome.Fail(CrossTenantMethodSupport.OutOfScope(call));
        }

        return removed
            ? CkMethodOutcome.Ok()
            : CkMethodOutcome.Fail(new CkMethodFailure(ClientMirrorMethodErrors.MirrorNotFound));
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.SetMirrorAutoProvision-1</c>: sets <c>AutoProvisionInChildTenants</c> of the
///     client with a version-checked read-modify-write; the store's update hook propagates the state to existing mirrors.
///     Switching it off leaves the mirrors in place. REST facade:
///     <c>PATCH {tenant}/v1/clients/{clientId}/autoProvisionInChildTenants</c>. A lost concurrent write is
///     <c>CONCURRENT_CHANGE</c>.
/// </summary>
internal sealed class ClientSetMirrorAutoProvisionHandler(IServiceProvider services)
    : ClientMirrorVoidHandlerBase<ClientSetMirrorAutoProvisionParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, RtClient client,
        ClientSetMirrorAutoProvisionParameters parameters, string tenantId, CancellationToken cancellationToken)
    {
        call.Details["enabled"] = parameters.Enabled ? "true" : "false";
        RtClient? stored;
        try
        {
            stored = await Services.GetRequiredService<IOctoClientStore>().MutateAsync(client.ClientId!, current =>
            {
                current.AutoProvisionInChildTenants = parameters.Enabled;
                return true;
            }).ConfigureAwait(false);
        }
        catch (RtVersionConflictException)
        {
            return CkMethodOutcome.Fail(new CkMethodFailure(ClientMirrorMethodErrors.ConcurrentChange));
        }

        return stored == null ? CkMethodOutcome.TargetNotFound() : CkMethodOutcome.Ok();
    }
}
