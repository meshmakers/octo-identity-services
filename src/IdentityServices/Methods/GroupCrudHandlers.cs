using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of the static <c>System.Identity/Group.CreateGroup-1</c> (System.Identity 3.7.0): creates a group, as
///     <c>POST system/v1/groups</c> did (the normalized name is derived here, never a parameter), optionally with initial roles.
/// </summary>
/// <remarks>
///     The initial roles are named by role name and resolved first; one unknown role, or one the caller cannot read, refuses the
///     call with <c>ROLE_NOT_FOUND</c> before anything is written. They pass the grant rule of the role change guard
///     (<see cref="IRoleChangeGuard.EvaluateGrantAsync" />): a built-in role the caller does not hold is refused
///     (<c>METHOD_FORBIDDEN</c>, <c>role-not-held</c>), as for <c>Group.SetRoles</c>. A new group has no members, so the
///     self-grant and last-administrator rules cannot apply. Before this method the REST create wrote the initial roles without
///     the guard: a group with a role the caller does not hold could be created and joined later.
/// </remarks>
internal sealed class GroupCreateGroupHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<GroupCreateGroupParameters, GroupCreateGroupResult>(services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtGroup>();

    protected override async Task<CkMethodOutcome<GroupCreateGroupResult>> CreateAsync(IdentityMethodCall call,
        GroupCreateGroupParameters parameters, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(parameters.GroupName))
        {
            return CkMethodOutcome<GroupCreateGroupResult>.ValidationFailed("groupName", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = parameters.GroupName;
        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        var normalized = parameters.GroupName.ToUpperInvariant();
        if (await groupStore.FindByNameAsync(normalized).ConfigureAwait(false) != null)
        {
            return CkMethodOutcome<GroupCreateGroupResult>.Fail(IdentityCrudErrors.GroupAlreadyExists);
        }

        var roleManager = call.Services.GetRequiredService<RoleManager<RtRole>>();
        var roles = new Dictionary<string, RtRole>(StringComparer.OrdinalIgnoreCase); // role rtId -> role
        foreach (var name in parameters.RoleNames ?? [])
        {
            var role = string.IsNullOrWhiteSpace(name)
                ? null
                : await roleManager.FindByNameAsync(name).ConfigureAwait(false);
            if (role == null || !(await call.EvaluateAsync(
                    new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role.RtId), RtDataAction.Read,
                    cancellationToken).ConfigureAwait(false)).IsAllowed)
            {
                return CkMethodOutcome<GroupCreateGroupResult>.Fail(UserRoleMethodErrors.RoleNotFound,
                    (UserRoleMethodErrors.RoleNameParameter, name ?? string.Empty));
            }

            roles[role.RtId.ToString()] = role;
        }

        if (roles.Count > 0)
        {
            var decision = await call.Services.GetRequiredService<IRoleChangeGuard>().EvaluateGrantAsync(call.Caller,
                roles.Values.Select(r => r.Name ?? r.RtId.ToString()), cancellationToken,
                $"new group {parameters.GroupName}").ConfigureAwait(false);
            if (!decision.IsAllowed)
            {
                return CkMethodOutcome<GroupCreateGroupResult>.Fail(call.Refuse(decision).Failure!);
            }
        }

        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(),
            GroupName = parameters.GroupName,
            NormalizedGroupName = normalized,
            GroupDescription = parameters.GroupDescription
        };
        await groupStore.StoreAsync(group).ConfigureAwait(false);
        if (roles.Count > 0)
        {
            await groupStore.SetRoleIdsAsync(group.RtId, roles.Keys.ToList()).ConfigureAwait(false);
            call.Details["rolesAfter"] = string.Join(",",
                roles.Values.Select(r => r.Name ?? r.RtId.ToString()).Order(StringComparer.OrdinalIgnoreCase));
        }

        return new GroupCreateGroupResult { Value = group.RtId.ToString() };
    }

    protected override string? CreatedRtIdOf(GroupCreateGroupResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/Group.UpdateGroup-1</c> (System.Identity 3.7.0): replaces name and description of a group,
///     as <c>PUT system/v1/groups/{rtId}</c> did; the normalized name is derived here. A name another group has is refused
///     (<c>GROUP_ALREADY_EXISTS</c>).
/// </summary>
internal sealed class GroupUpdateGroupHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<GroupUpdateGroupParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        GroupUpdateGroupParameters parameters, CancellationToken cancellationToken)
    {
        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        var group = await groupStore.FindByIdAsync(targetRtId).ConfigureAwait(false);
        if (group == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = group.GroupName ?? string.Empty;
        if (string.IsNullOrEmpty(parameters.GroupName))
        {
            return CkMethodOutcome.ValidationFailed("groupName", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = parameters.GroupName;
        var normalized = parameters.GroupName.ToUpperInvariant();
        if (normalized != group.NormalizedGroupName &&
            await groupStore.FindByNameAsync(normalized).ConfigureAwait(false) != null)
        {
            return CkMethodOutcome.Fail(IdentityCrudErrors.GroupAlreadyExists);
        }

        group.GroupName = parameters.GroupName;
        group.NormalizedGroupName = normalized;
        group.GroupDescription = parameters.GroupDescription;
        await groupStore.StoreAsync(group).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/Group.DeleteGroup-1</c> (System.Identity 3.7.0): deletes a group, as
///     <c>DELETE system/v1/groups/{rtId}</c> did, after the role change guard (the last user administrator stays).
/// </summary>
internal sealed class GroupDeleteGroupHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<GroupDeleteGroupParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        GroupDeleteGroupParameters parameters, CancellationToken cancellationToken)
    {
        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        var group = await groupStore.FindByIdAsync(targetRtId).ConfigureAwait(false);
        if (group == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = group.GroupName ?? string.Empty;
        var decision = await call.Services.GetRequiredService<IRoleChangeGuard>().EvaluateAsync(call.Caller,
            new RoleGraphChange.GroupDeleted(group.RtId.ToString()), cancellationToken).ConfigureAwait(false);
        if (!decision.IsAllowed)
        {
            return call.Refuse(decision);
        }

        await groupStore.RemoveAsync(group.RtId).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
