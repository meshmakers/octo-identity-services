using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the data-permission methods (declared in <c>ck-dataPermission.yaml</c>).</summary>
internal static class DataPermissionMethodErrors
{
    public const string PermissionAlreadyGranted = "PERMISSION_ALREADY_GRANTED";
    public const string PermissionNotGranted = "PERMISSION_NOT_GRANTED";
}

/// <summary>
///     Shared flow of <c>DataPermission.GrantToRole</c> and <c>DataPermission.RevokeFromRole</c> (AB#7779): the same rules as
///     <c>POST/DELETE system/v1/dataPermissions/{permissionId}/roles/{roleName}</c> of <c>DataPermissionsController</c>, never more.
/// </summary>
/// <remarks>
///     <para>
///         <b>Parity with REST.</b> REST needs scope <c>octo_api</c> and role <c>UserManagement</c> and then calls the store;
///         there is no role change guard on data permissions (they grant data access, not roles). REST answers an unknown
///         permission or role with an unhandled exception and is silent about duplicates; the methods answer
///         <c>METHOD_TARGET_NOT_FOUND</c> (the permission is the call's target), <c>ROLE_NOT_FOUND</c>,
///         <c>PERMISSION_ALREADY_GRANTED</c> and <c>PERMISSION_NOT_GRANTED</c>.
///     </para>
///     <para>
///         <b>Referenced role (AB#7035).</b> The role is read through <see cref="IRtDataPermissionEvaluator" /> with the caller's
///         roles: a role the caller cannot read is <c>ROLE_NOT_FOUND</c>, and one they may not write (the grant is stored on the
///         role) is <c>METHOD_FORBIDDEN</c> with <c>reason</c> = <c>data-permission</c>. Without enforcing policies on the role
///         type (the default) both are open, as in REST.
///     </para>
///     <para><b>Audit.</b> One <c>Identity.Method</c> event per call with <c>permissionId</c> and <c>roleName</c>.</para>
/// </remarks>
internal abstract class DataPermissionRoleMethodHandlerBase<TParameters>(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<TParameters>(services) where TParameters : class
{
    protected abstract string? RoleName(TParameters parameters);

    /// <summary>Applies the change; the permission and the role exist and the caller may use them.</summary>
    protected abstract Task<CkMethodOutcome> ApplyGrantAsync(IdentityMethodCall call, RtDataPermission permission,
        RtRole role, bool granted, CancellationToken cancellationToken);

    protected sealed override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        TParameters parameters, CancellationToken cancellationToken)
    {
        var repository = call.Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        RtDataPermission? permission;
        using (var session = await repository.GetSessionAsync().ConfigureAwait(false))
        {
            session.StartTransaction();
            permission = await repository.GetRtEntityByRtIdAsync<RtDataPermission>(session, targetRtId)
                .ConfigureAwait(false);
            await session.CommitTransactionAsync().ConfigureAwait(false);
        }

        if (permission == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details["permissionId"] = permission.PermissionId ?? string.Empty;
        var roleName = RoleName(parameters);
        call.Details["roleName"] = roleName ?? string.Empty;
        var role = string.IsNullOrWhiteSpace(roleName)
            ? null
            : await call.Services.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(roleName)
                .ConfigureAwait(false);
        var roleEntity = role == null
            ? default
            : new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role.RtId);
        if (role == null ||
            !(await call.EvaluateAsync(roleEntity, RtDataAction.Read, cancellationToken).ConfigureAwait(false)).IsAllowed)
        {
            return CkMethodOutcome.Fail(new CkMethodFailure(UserRoleMethodErrors.RoleNotFound,
                new Dictionary<string, string> { [UserRoleMethodErrors.RoleNameParameter] = roleName ?? string.Empty }));
        }

        if (!(await call.EvaluateAsync(roleEntity, RtDataAction.Write, cancellationToken).ConfigureAwait(false)).IsAllowed)
        {
            return call.NotPermitted();
        }

        var grantedNames = await call.Services.GetRequiredService<IDataPermissionStore>()
            .GetGrantedRoleNamesAsync(permission.RtId).ConfigureAwait(false);
        var granted = grantedNames.Contains(role.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        return await ApplyGrantAsync(call, permission, role, granted, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Handler of <c>System.Identity/DataPermission.GrantToRole-1</c> (AB#7779), see <see cref="DataPermissionRoleMethodHandlerBase{T}" />.</summary>
internal sealed class DataPermissionGrantToRoleHandler(IServiceProvider services)
    : DataPermissionRoleMethodHandlerBase<DataPermissionGrantToRoleParameters>(services)
{
    protected override string? RoleName(DataPermissionGrantToRoleParameters parameters) => parameters.RoleName;

    protected override async Task<CkMethodOutcome> ApplyGrantAsync(IdentityMethodCall call, RtDataPermission permission,
        RtRole role, bool granted, CancellationToken cancellationToken)
    {
        if (granted)
        {
            return CkMethodOutcome.Fail(DataPermissionMethodErrors.PermissionAlreadyGranted);
        }

        await call.Services.GetRequiredService<IDataPermissionStore>()
            .GrantToRoleAsync(permission.PermissionId!, role.Name!).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>Handler of <c>System.Identity/DataPermission.RevokeFromRole-1</c> (AB#7779), see <see cref="DataPermissionRoleMethodHandlerBase{T}" />.</summary>
internal sealed class DataPermissionRevokeFromRoleHandler(IServiceProvider services)
    : DataPermissionRoleMethodHandlerBase<DataPermissionRevokeFromRoleParameters>(services)
{
    protected override string? RoleName(DataPermissionRevokeFromRoleParameters parameters) => parameters.RoleName;

    protected override async Task<CkMethodOutcome> ApplyGrantAsync(IdentityMethodCall call, RtDataPermission permission,
        RtRole role, bool granted, CancellationToken cancellationToken)
    {
        if (!granted)
        {
            return CkMethodOutcome.Fail(DataPermissionMethodErrors.PermissionNotGranted);
        }

        await call.Services.GetRequiredService<IDataPermissionStore>()
            .RevokeFromRoleAsync(permission.PermissionId!, role.Name!).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
