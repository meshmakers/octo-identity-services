using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the data-permission methods (declared in <c>ck-dataPermission.yaml</c>).</summary>
internal static class DataPermissionMethodErrors
{
    public const string PermissionAlreadyGranted = "PERMISSION_ALREADY_GRANTED";
    public const string PermissionNotGranted = "PERMISSION_NOT_GRANTED";
}

/// <summary>
///     Shared flow of <c>DataPermission.GrantToRole</c> and <c>DataPermission.RevokeFromRole</c> (AB#7779): the same rules as
///     <c>POST/DELETE system/v1/dataPermissions/{permissionId}/roles/{roleName}</c> of <c>DataPermissionsController</c>, which
///     are their facades, never more.
/// </summary>
/// <remarks>
///     <para>
///         <b>Parity with REST.</b> REST needs scope <c>octo_api</c> and role <c>UserManagement</c>; there is no role change
///         guard on data permissions (they grant data access, not roles). The methods answer <c>METHOD_TARGET_NOT_FOUND</c>
///         (the permission is the call's target), <c>ROLE_NOT_FOUND</c>, <c>PERMISSION_ALREADY_GRANTED</c> and
///         <c>PERMISSION_NOT_GRANTED</c>; the facade maps the last two back to REST's silent <c>200</c>.
///     </para>
///     <para>
///         <b>Data permissions.</b> The permission itself is evaluated for <c>Write</c> first
///         (<see cref="IdentityMethodCall.CheckTargetWritableAsync" />). The role is read through
///         <see cref="IRtDataPermissionEvaluator" /> with the caller's roles: a role the caller cannot read is
///         <c>ROLE_NOT_FOUND</c>, except that revoking it while it holds the permission is <c>METHOD_FORBIDDEN</c>
///         (<c>reason</c> = <c>data-permission</c>): the grant is visible through the permission, so a success would mislead
///         and a silent change behind the caller's back is what the check prevents (CWE-863). A role the caller may read but not
///         write (the grant is stored on the role) is <c>METHOD_FORBIDDEN</c> as well. Without enforcing policies (the
///         default) all of this is open, as in REST.
///     </para>
///     <para><b>Audit.</b> One <c>Identity.Method</c> event per call with <c>permissionId</c> and <c>roleName</c>.</para>
/// </remarks>
internal abstract class DataPermissionRoleMethodHandlerBase<TParameters>(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<TParameters>(services) where TParameters : class
{
    protected abstract string? RoleName(TParameters parameters);

    /// <summary>
    ///     <c>true</c> for the revoke: a held role the caller cannot read is refused (<c>METHOD_FORBIDDEN</c>) instead of being
    ///     answered as unknown.
    /// </summary>
    protected virtual bool RefusesHeldUnreadableRole => false;

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

        if (await call.CheckTargetWritableAsync(permission.ToRtEntityId(), cancellationToken).ConfigureAwait(false) is
            { } refused)
        {
            return refused;
        }

        call.Details["permissionId"] = permission.PermissionId ?? string.Empty;
        var roleName = RoleName(parameters);
        call.Details["roleName"] = roleName ?? string.Empty;
        var role = string.IsNullOrWhiteSpace(roleName)
            ? null
            : await call.Services.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(roleName)
                .ConfigureAwait(false);
        if (role == null)
        {
            return RoleNotFound(roleName);
        }

        var roleEntity = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role.RtId);
        var grantedNames = await call.Services.GetRequiredService<IDataPermissionStore>()
            .GetGrantedRoleNamesAsync(permission.RtId).ConfigureAwait(false);
        var granted = grantedNames.Contains(role.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        if (!(await call.EvaluateAsync(roleEntity, RtDataAction.Read, cancellationToken).ConfigureAwait(false)).IsAllowed)
        {
            return granted && RefusesHeldUnreadableRole ? call.NotPermitted() : RoleNotFound(roleName);
        }

        if (!(await call.EvaluateAsync(roleEntity, RtDataAction.Write, cancellationToken).ConfigureAwait(false)).IsAllowed)
        {
            return call.NotPermitted();
        }

        return await ApplyGrantAsync(call, permission, role, granted, cancellationToken).ConfigureAwait(false);
    }

    private static CkMethodOutcome RoleNotFound(string? roleName) =>
        CkMethodOutcome.Fail(new CkMethodFailure(UserRoleMethodErrors.RoleNotFound,
            new Dictionary<string, string> { [UserRoleMethodErrors.RoleNameParameter] = roleName ?? string.Empty }));
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

    protected override bool RefusesHeldUnreadableRole => true;

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

/// <summary>
///     Handler of <c>System.Identity/DataPolicy.SetEnforcementMode-1</c> (System.Identity 3.4.0): switches a data
///     policy between <c>Enforce</c> and <c>AuditOnly</c>. REST facade: <c>PUT system/v1/dataPermissions/policies/{policyRtId}/enforcementMode</c>.
/// </summary>
/// <remarks>
///     Caller rule of REST (<c>IdentityUserAdministrationWritePolicy</c>: scope <c>octo_api</c> and <c>UserManagement</c>). The
///     policy is the target and is evaluated for <c>Write</c> first, then the data permission it is bound to (the mode decides
///     whether that permission is enforced at all). The before value of the audit is the mode read before the write. The mode the policy already has is a success without a
///     write. The mode changes data visibility tenant-wide, so the <c>Identity.Method</c> event names the policy (target)
///     and both modes (<c>enforcementModeBefore</c>, <c>enforcementModeAfter</c>). The write goes through
///     <see cref="IDataPermissionStore.SetPolicyEnforcementModeAsync" />, as REST did. After every
///     successful call (also a no-op) the cached policy table of this process is invalidated, so this replica applies the
///     stored mode at once (REST waited for the cache TTL of 60 s); other replicas and services still wait for their TTL.
/// </remarks>
internal sealed class DataPolicySetEnforcementModeHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<DataPolicySetEnforcementModeParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        DataPolicySetEnforcementModeParameters parameters, CancellationToken cancellationToken)
    {
        var repository = call.Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        RtDataPolicy? policy;
        using (var session = await repository.GetSessionAsync().ConfigureAwait(false))
        {
            session.StartTransaction();
            policy = await repository.GetRtEntityByRtIdAsync<RtDataPolicy>(session, targetRtId).ConfigureAwait(false);
            await session.CommitTransactionAsync().ConfigureAwait(false);
        }

        if (policy == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        if (await call.CheckTargetWritableAsync(policy.ToRtEntityId(), cancellationToken).ConfigureAwait(false) is
            { } refused)
        {
            return refused;
        }

        // The mode decides whether the policy's data permission is enforced at all: switching it off is a change of that
        // permission too, so the caller must be allowed to write the permission as well (as GrantToRole / RevokeFromRole).
        foreach (var permissionId in await PermissionsOfAsync(repository, policy).ConfigureAwait(false))
        {
            if (await call.CheckTargetWritableAsync(
                        new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtDataPermission>(), permissionId), cancellationToken)
                    .ConfigureAwait(false) is { } permissionRefused)
            {
                // a permission the caller cannot see makes its policy count as not found, not as forbidden
                return permissionRefused;
            }
        }

        var mode = parameters.EnforcementMode;
        if (!Enum.IsDefined(mode))
        {
            return CkMethodOutcome.ValidationFailed("enforcementMode", "unknown");
        }

        call.Details["enforcementModeBefore"] = policy.EnforcementMode.ToString();
        call.Details["enforcementModeAfter"] = mode.ToString();
        if (policy.EnforcementMode != mode)
        {
            await call.Services.GetRequiredService<IDataPermissionStore>()
                .SetPolicyEnforcementModeAsync(policy.RtId, mode).ConfigureAwait(false);
        }

        // The policy table of this process is cached (TTL); drop it after every successful call - also when the stored mode
        // already matched, because this replica's table may still hold a mode another replica changed - so the stored mode
        // applies here at once. Other identity replicas and other services (asset repository, mesh adapter, ...) pick it up
        // when their own table expires (60 s, no invalidation event), as with REST before.
        call.Services.GetService<IDataPermissionResolver>()?.Invalidate(repository.TenantId);

        return CkMethodOutcome.Ok();
    }

    /// <summary>The rtIds of the data permission(s) the policy is bound to (<c>PolicyPermission</c>, multiplicity one).</summary>
    private static async Task<IReadOnlyList<OctoObjectId>> PermissionsOfAsync(ITenantRepository repository,
        RtDataPolicy policy)
    {
        using var session = await repository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();
        var associations = await repository.GetRtAssociationsAsync(session, policy.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Any, IdentityAssociationConstants.PolicyPermissionId))
            .ConfigureAwait(false);
        await session.CommitTransactionAsync().ConfigureAwait(false);
        return associations.Items.Select(a => a.OriginRtId == policy.RtId ? a.TargetRtId : a.OriginRtId).Distinct().ToList();
    }
}
