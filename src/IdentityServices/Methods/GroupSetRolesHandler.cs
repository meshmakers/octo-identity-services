using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/Group.SetRoles-1</c> (AB#7779): replaces the roles of a group by the given role names,
///     with the rules of <c>PUT system/v1/groups/{group}/roles</c> of <c>GroupsController</c>.
/// </summary>
/// <remarks>
///     REST takes role ids; the method takes role names (the model's parameter) and resolves them first, so the
///     <see cref="IRoleChangeGuard" /> judges the same role ids (<see cref="RoleGraphChange.GroupRoles" />: self-grant,
///     <c>role-not-held</c> for built-in roles, last administrator through groups, AB#7927). REST writes any id it is given;
///     the method checks all names first and one unknown (or, AB#7035, unreadable) role changes nothing (<c>ROLE_NOT_FOUND</c>),
///     which is stricter and never grants more. The end state of a successful call is the same. The audit event carries
///     <c>rolesBefore</c> and <c>rolesAfter</c> (role names).
/// </remarks>
internal sealed class GroupSetRolesHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<GroupSetRolesParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        GroupSetRolesParameters parameters, CancellationToken cancellationToken)
    {
        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        var group = await groupStore.FindByIdAsync(targetRtId).ConfigureAwait(false);
        if (group == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var roleManager = call.Services.GetRequiredService<RoleManager<RtRole>>();
        var wanted = new Dictionary<string, RtRole>(StringComparer.OrdinalIgnoreCase); // role rtId -> role
        foreach (var name in parameters.RoleNames ?? [])
        {
            var role = string.IsNullOrWhiteSpace(name) ? null : await roleManager.FindByNameAsync(name).ConfigureAwait(false);
            if (role == null)
            {
                return RoleNotFound(name ?? string.Empty);
            }

            var verdict = await call.EvaluateAsync(new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role.RtId),
                RtDataAction.Read, cancellationToken).ConfigureAwait(false);
            if (!verdict.IsAllowed)
            {
                return RoleNotFound(name ?? string.Empty);
            }

            wanted[role.RtId.ToString()] = role;
        }

        var before = await groupStore.GetRoleIdsAsync(group.RtId).ConfigureAwait(false);
        call.Details["rolesBefore"] = await NamesAsync(roleManager, before).ConfigureAwait(false);
        call.Details["rolesAfter"] = call.Details["rolesBefore"];

        var decision = await call.Services.GetRequiredService<IRoleChangeGuard>().EvaluateAsync(call.Caller,
            new RoleGraphChange.GroupRoles(group.RtId.ToString(), wanted.Keys.ToList()), cancellationToken)
            .ConfigureAwait(false);
        if (!decision.IsAllowed)
        {
            return call.Refuse(decision);
        }

        await groupStore.SetRoleIdsAsync(group.RtId, wanted.Keys.ToList()).ConfigureAwait(false);
        call.Details["rolesAfter"] = await NamesAsync(roleManager, wanted.Keys).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }

    private static CkMethodOutcome RoleNotFound(string roleName) =>
        CkMethodOutcome.Fail(new CkMethodFailure(UserRoleMethodErrors.RoleNotFound,
            new Dictionary<string, string> { [UserRoleMethodErrors.RoleNameParameter] = roleName }));

    private static async Task<string> NamesAsync(RoleManager<RtRole> roleManager, IEnumerable<string> roleIds)
    {
        var names = new List<string>();
        foreach (var id in roleIds)
        {
            var role = await roleManager.FindByIdAsync(id).ConfigureAwait(false);
            names.Add(role?.Name ?? id);
        }

        return string.Join(",", names.Order(StringComparer.OrdinalIgnoreCase));
    }
}
