using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Declared errors and helpers of the data permission and data policy CRUD methods (System.Identity 3.8.0).</summary>
internal static class DataPermissionCrudSupport
{
    /// <summary>A permission with this id exists.</summary>
    public const string DataPermissionAlreadyExists = "DATA_PERMISSION_ALREADY_EXISTS";

    /// <summary>Audit detail: the permission id.</summary>
    public const string PermissionIdDetail = "permissionId";
}

/// <summary>System reads of the identity CRUD methods (System.Identity 3.8.0), in the tenant bound to the call.</summary>
internal static class IdentityMethodReads
{
    /// <summary>Reads one entity of <typeparamref name="T" /> by rtId (system read, in the tenant bound to the call).</summary>
    public static async Task<T?> FindAsync<T>(IdentityMethodCall call, OctoObjectId rtId) where T : RtEntity, new()
    {
        var repository = call.Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        using var session = await repository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();
        var entity = await repository.GetRtEntityByRtIdAsync<T>(session, rtId).ConfigureAwait(false);
        await session.CommitTransactionAsync().ConfigureAwait(false);
        return entity;
    }
}

/// <summary>
///     Handler of the static <c>System.Identity/DataPermission.CreateDataPermission-1</c> (System.Identity 3.8.0): creates a
///     permission, as <c>POST system/v1/dataPermissions</c> did. A second permission with the same id is
///     <c>DATA_PERMISSION_ALREADY_EXISTS</c> (REST answered 500 before).
/// </summary>
internal sealed class DataPermissionCreateDataPermissionHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<DataPermissionCreateDataPermissionParameters,
        DataPermissionCreateDataPermissionResult>(services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtDataPermission>();

    protected override async Task<CkMethodOutcome<DataPermissionCreateDataPermissionResult>> CreateAsync(
        IdentityMethodCall call, DataPermissionCreateDataPermissionParameters p, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(p.PermissionId))
        {
            return CkMethodOutcome<DataPermissionCreateDataPermissionResult>.ValidationFailed("permissionId", "required");
        }

        call.Details[DataPermissionCrudSupport.PermissionIdDetail] = p.PermissionId;
        var store = call.Services.GetRequiredService<IDataPermissionStore>();
        if (await store.FindByPermissionIdAsync(p.PermissionId).ConfigureAwait(false) != null)
        {
            return new CkMethodFailure(DataPermissionCrudSupport.DataPermissionAlreadyExists);
        }

        var rtId = await store.CreateAsync(p.PermissionId, p.Description).ConfigureAwait(false);
        return new DataPermissionCreateDataPermissionResult { Value = rtId.ToString() };
    }

    protected override string? CreatedRtIdOf(DataPermissionCreateDataPermissionResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/DataPermission.DeleteDataPermission-1</c> (System.Identity 3.8.0): deletes a permission with
///     its policies, as <c>DELETE system/v1/dataPermissions/{permissionId}</c> did.
/// </summary>
internal sealed class DataPermissionDeleteDataPermissionHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<DataPermissionDeleteDataPermissionParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        DataPermissionDeleteDataPermissionParameters parameters, CancellationToken cancellationToken)
    {
        var permission = await IdentityMethodReads.FindAsync<RtDataPermission>(call, targetRtId)
            .ConfigureAwait(false);
        if (permission?.PermissionId == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[DataPermissionCrudSupport.PermissionIdDetail] = permission.PermissionId;
        await call.Services.GetRequiredService<IDataPermissionStore>().RemoveAsync(permission.PermissionId)
            .ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/DataPermission.CreatePolicy-1</c> (System.Identity 3.8.0): creates a policy bound to the
///     permission, as <c>POST system/v1/dataPermissions/{permissionId}/policies</c> did; the result is the policy's rtId.
///     The same flow as the other instance methods (caller rule, tenant binding, the caller may write the target permission,
///     one <c>Identity.Method</c> event per call) plus the write permission on the type <c>DataPolicy</c>, as on a create.
/// </summary>
/// <remarks>
///     A policy changes what every caller of the tenant sees of its target CK types; that is why the method needs
///     <c>UserManagement</c>, the REST policy. The scope and the enforcement mode are typed enums, so the REST
///     "All|OwnedOnly" / "Enforce|AuditOnly" check is the parameter binding of the method.
/// </remarks>
internal sealed class DataPermissionCreatePolicyHandler(IServiceProvider services)
    : ICkMethodHandler<DataPermissionCreatePolicyParameters, DataPermissionCreatePolicyResult>
{
    public Task<CkMethodOutcome<DataPermissionCreatePolicyResult>> HandleAsync(
        CkMethodContext<DataPermissionCreatePolicyParameters> context, CancellationToken cancellationToken)
    {
        var call = context.CallerPrincipal == null ? null : new IdentityMethodCall(services, context.CallerPrincipal);
        return IdentityMethodAudit.RunAsync(services, context, call, () => RunAsync(context, call, cancellationToken),
            outcome => outcome.Failure?.Code);
    }

    private async Task<CkMethodOutcome<DataPermissionCreatePolicyResult>> RunAsync(
        CkMethodContext<DataPermissionCreatePolicyParameters> context, IdentityMethodCall? call,
        CancellationToken cancellationToken)
    {
        if (call == null || !IdentityMethodCallerRules.IsAdministrator(call.Principal))
        {
            return CkMethodOutcome<DataPermissionCreatePolicyResult>.Forbidden("role-required");
        }

        if (string.IsNullOrWhiteSpace(context.TargetRtId) || !OctoObjectId.TryParse(context.TargetRtId, out var target))
        {
            return CkMethodOutcome<DataPermissionCreatePolicyResult>.TargetNotFound();
        }

        if (!await services.GetRequiredService<IMethodTenantAccessor>().BindAsync(context.TenantId).ConfigureAwait(false))
        {
            return CkMethodOutcome<DataPermissionCreatePolicyResult>.TargetNotFound();
        }

        if (await call.CheckTargetWritableAsync(IdentityMethodCall.TargetOf(context.MethodId, target), cancellationToken)
                .ConfigureAwait(false) is { } denied)
        {
            return CkMethodOutcome<DataPermissionCreatePolicyResult>.Fail(denied.Failure!);
        }

        if (await call.CheckTypeWritableAsync(RtEntityExtensions.GetRtCkTypeId<RtDataPolicy>(), cancellationToken)
                .ConfigureAwait(false) is { } typeDenied)
        {
            return CkMethodOutcome<DataPermissionCreatePolicyResult>.Fail(typeDenied);
        }

        var p = context.Parameters;
        if (p.TargetCkTypeIds == null || p.TargetCkTypeIds.Count == 0 ||
            p.TargetCkTypeIds.Any(string.IsNullOrWhiteSpace))
        {
            return CkMethodOutcome<DataPermissionCreatePolicyResult>.ValidationFailed("targetCkTypeIds", "required");
        }

        var permission = await IdentityMethodReads.FindAsync<RtDataPermission>(call, target).ConfigureAwait(false);
        if (permission?.PermissionId == null)
        {
            return CkMethodOutcome<DataPermissionCreatePolicyResult>.TargetNotFound();
        }

        call.Details[DataPermissionCrudSupport.PermissionIdDetail] = permission.PermissionId;
        call.Details["targetCkTypeIds"] = string.Join(",", p.TargetCkTypeIds);
        call.Details["enforcementMode"] = p.EnforcementMode.ToString();
        var policyRtId = await services.GetRequiredService<IDataPermissionStore>().CreatePolicyAsync(
            permission.PermissionId, p.TargetCkTypeIds, p.Actions ?? [], p.Scope, p.EnforcementMode).ConfigureAwait(false);
        call.Details["policyRtId"] = policyRtId.ToString();
        return new DataPermissionCreatePolicyResult { Value = policyRtId.ToString() };
    }
}

/// <summary>
///     Handler of <c>System.Identity/DataPolicy.DeleteDataPolicy-1</c> (System.Identity 3.8.0): deletes a policy, as
///     <c>DELETE system/v1/dataPermissions/policies/{policyRtId}</c> did.
/// </summary>
internal sealed class DataPolicyDeleteDataPolicyHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<DataPolicyDeleteDataPolicyParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        DataPolicyDeleteDataPolicyParameters parameters, CancellationToken cancellationToken)
    {
        var policy = await IdentityMethodReads.FindAsync<RtDataPolicy>(call, targetRtId).ConfigureAwait(false);
        if (policy == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details["targetCkTypeIds"] = string.Join(",", policy.TargetCkTypeIds?.ToList() ?? []);
        await call.Services.GetRequiredService<IDataPermissionStore>().RemovePolicyAsync(targetRtId)
            .ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
