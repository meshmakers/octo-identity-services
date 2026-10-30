using System.Security.Claims;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;

/// <summary>Why a role change is refused (AB#7914). The strings are the stable codes of both transports.</summary>
public static class RoleChangeReasons
{
    /// <summary>The caller tried to add a direct role to their own user.</summary>
    public const string SelfGrant = "self-grant";

    /// <summary>The caller tried to grant a built-in role they do not hold themselves.</summary>
    public const string RoleNotHeld = "role-not-held";

    /// <summary>The change would leave the tenant without a user that effectively holds <c>UserManagement</c>.</summary>
    public const string LastAdministrator = "last-administrator";
}

/// <summary>
///     The caller of a role change, from the validated token (REST) or the validated principal of the method host.
///     A client-credentials caller has no subject, so it is never "self".
/// </summary>
/// <param name="Subject">User id (<c>sub</c>), <c>null</c> for a client-credentials token.</param>
/// <param name="ClientId">Client id of the token, if any.</param>
/// <param name="Roles">The effective role names of the token (<c>role</c> claims).</param>
public sealed record RoleChangeCaller(string? Subject, string? ClientId, IReadOnlyCollection<string> Roles)
{
    /// <summary>The caller of a REST request: the <c>sub</c>, <c>client_id</c> and role claims of the bearer token.</summary>
    public static RoleChangeCaller FromPrincipal(ClaimsPrincipal principal) => new(
        principal.FindFirst("sub")?.Value,
        principal.FindFirst("client_id")?.Value,
        principal.Claims.Where(c => c.Type == "role" || c.Type == ClaimTypes.Role).Select(c => c.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList());
}

/// <summary>The direct roles of a user before and after a change, together with the caller.</summary>
/// <param name="Caller">Who changes the roles.</param>
/// <param name="Target">The user whose direct roles change.</param>
/// <param name="DirectRolesBefore">Names of the direct roles before the change.</param>
/// <param name="DirectRolesAfter">Names of the direct roles after the change; <c>null</c> when the user is deleted.</param>
public sealed record RoleChangeRequest(
    RoleChangeCaller Caller,
    RtUser Target,
    IReadOnlyCollection<string> DirectRolesBefore,
    IReadOnlyCollection<string>? DirectRolesAfter);

/// <summary>Answer of the guard: allowed, or the reason (and the refused role names).</summary>
public sealed record RoleChangeDecision(string? Reason, IReadOnlyList<string> RoleNames)
{
    /// <summary>The change may be applied.</summary>
    public static RoleChangeDecision Allowed { get; } = new(null, []);

    /// <summary><c>true</c> when the change may be applied.</summary>
    public bool IsAllowed => Reason == null;

    /// <summary>A readable sentence for the refusal (Studio shows the <c>title</c> of the REST problem as it is).</summary>
    public string Title => Reason switch
    {
        RoleChangeReasons.SelfGrant => "You cannot grant additional roles to your own user.",
        RoleChangeReasons.RoleNotHeld =>
            $"You cannot grant built-in roles you do not hold yourself: {string.Join(", ", RoleNames)}.",
        RoleChangeReasons.LastAdministrator =>
            "This change would leave the tenant without a user administrator (a user who holds UserManagement).",
        _ => "The role change is allowed."
    };
}

/// <summary>
///     The one rule set for changes of the direct roles of a user (AB#7914), shared by the REST endpoints
///     (<c>UsersController</c>) and the methods <c>User.SetRoles</c> / <c>AddRole</c> / <c>RemoveRole</c>; group, mapping,
///     role-definition and client paths call the same guard (AB#7927, AB#7928).
/// </summary>
/// <remarks>
///     Lives in the API layer only. Setup, blueprint seeds, one-time grants, cross-tenant provisioning and the login group rules
///     assign roles through the user store and never call it.
/// </remarks>
public interface IRoleChangeGuard
{
    /// <summary>
    ///     Checks a change of the direct roles (or the deletion) of a user, in this order: self-grant, built-in roles
    ///     the caller does not hold, last user administrator. Only the difference of before and after is judged.
    /// </summary>
    Task<RoleChangeDecision> EvaluateAsync(RoleChangeRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Checks only that the caller may grant <paramref name="addedRoleNames" />: every built-in role (a role with an
    ///     <c>rtWellKnownName</c>) must be one the caller holds; custom roles are free.
    /// </summary>
    Task<RoleChangeDecision> EvaluateGrantAsync(RoleChangeCaller caller, IEnumerable<string> addedRoleNames,
        CancellationToken cancellationToken = default);
}

internal sealed class RoleChangeGuard(
    UserManager<RtUser> userManager,
    RoleManager<RtRole> roleManager,
    IGroupStore groupStore,
    IGroupRoleResolver groupRoleResolver,
    IUserStore<RtUser> userStore) : IRoleChangeGuard
{
    private const int MaxGroupDepth = 10;

    public async Task<RoleChangeDecision> EvaluateAsync(RoleChangeRequest request,
        CancellationToken cancellationToken = default)
    {
        var before = ToSet(request.DirectRolesBefore);
        var after = request.DirectRolesAfter == null ? null : ToSet(request.DirectRolesAfter);
        var added = after == null ? [] : after.Except(before, StringComparer.OrdinalIgnoreCase).ToList();

        if (added.Count > 0 && request.Caller.Subject != null &&
            string.Equals(request.Caller.Subject, request.Target.RtId.ToString(), StringComparison.Ordinal))
        {
            return new RoleChangeDecision(RoleChangeReasons.SelfGrant, added);
        }

        var grant = await EvaluateGrantAsync(request.Caller, added, cancellationToken).ConfigureAwait(false);
        if (!grant.IsAllowed)
        {
            return grant;
        }

        var userManagement = CommonConstants.UserManagementRole;
        var removesUserManagement = after == null
            ? before.Contains(userManagement)
            : before.Contains(userManagement) && !after.Contains(userManagement);
        // A deletion always has to be checked: the target may hold UserManagement only through a group or mapping.
        if ((after == null || removesUserManagement) && await WouldLeaveNoAdministratorAsync(request.Target,
                before.Contains(userManagement), after?.Contains(userManagement) ?? false).ConfigureAwait(false))
        {
            return new RoleChangeDecision(RoleChangeReasons.LastAdministrator, [userManagement]);
        }

        return RoleChangeDecision.Allowed;
    }

    public async Task<RoleChangeDecision> EvaluateGrantAsync(RoleChangeCaller caller,
        IEnumerable<string> addedRoleNames, CancellationToken cancellationToken = default)
    {
        var refused = new List<string>();
        foreach (var name in addedRoleNames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var role = await roleManager.FindByNameAsync(name).ConfigureAwait(false);
            // A role that does not exist is the caller's 404/ROLE_NOT_FOUND; a custom role has no well-known name.
            if (role == null || string.IsNullOrEmpty(role.RtWellKnownName))
            {
                continue;
            }

            var roleName = role.Name ?? name;
            if (!caller.Roles.Contains(roleName, StringComparer.OrdinalIgnoreCase))
            {
                refused.Add(roleName);
            }
        }

        return refused.Count == 0
            ? RoleChangeDecision.Allowed
            : new RoleChangeDecision(RoleChangeReasons.RoleNotHeld, refused);
    }

    /// <summary>
    ///     <c>true</c> when the target effectively holds <c>UserManagement</c> now, does not after the change and no other
    ///     user holds it. A tenant that has no holder at all is not blocked (the change creates no lockout).
    /// </summary>
    private async Task<bool> WouldLeaveNoAdministratorAsync(RtUser target, bool directBefore, bool directAfter)
    {
        var role = await roleManager.FindByNameAsync(CommonConstants.UserManagementRole).ConfigureAwait(false);
        if (role == null)
        {
            return false;
        }

        var roleId = role.RtId.ToString();
        var targetId = target.RtId.ToString();
        var inherited = (await groupRoleResolver.ResolveEffectiveUserRoleIdsAsync(targetId, target.UserName)
            .ConfigureAwait(false)).Contains(roleId);
        var holdsBefore = directBefore || inherited;
        var holdsAfter = directAfter || inherited;
        if (!holdsBefore || holdsAfter)
        {
            return false;
        }

        return !await AnotherUserHoldsAsync(role, roleId, targetId).ConfigureAwait(false);
    }

    private async Task<bool> AnotherUserHoldsAsync(RtRole role, string roleId, string excludedUserId)
    {
        // 1. direct holders
        var normalized = role.NormalizedName ?? role.Name?.ToUpperInvariant() ?? string.Empty;
        foreach (var holder in await ((IUserRoleStore<RtUser>)userStore).GetUsersInRoleAsync(normalized,
                     CancellationToken.None).ConfigureAwait(false))
        {
            if (holder.RtId.ToString() != excludedUserId)
            {
                return true;
            }
        }

        // 2. members of a group that grants the role directly or through a nested group
        foreach (var group in await groupStore.GetAllAsync().ConfigureAwait(false))
        {
            if (!await GroupGrantsAsync(group.RtId, roleId, [], 0).ConfigureAwait(false))
            {
                continue;
            }

            foreach (var memberId in await groupStore.GetMemberUserIdsAsync(group.RtId).ConfigureAwait(false))
            {
                if (memberId != excludedUserId && await userManager.FindByIdAsync(memberId).ConfigureAwait(false) != null)
                {
                    return true;
                }
            }
        }

        // 3. cross-tenant shadow users (xt_...): their roles come from external tenant user mappings and the groups of those
        foreach (var shadow in userManager.Users.AsEnumerable()
                     .Where(u => CrossTenantShadowUserName.IsShadowUserName(u.UserName))
                     .ToList())
        {
            var id = shadow.RtId.ToString();
            if (id != excludedUserId &&
                (await groupRoleResolver.ResolveEffectiveUserRoleIdsAsync(id, shadow.UserName).ConfigureAwait(false))
                .Contains(roleId))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Whether membership of the group carries the role: the group itself or one of its nested groups holds it.</summary>
    private async Task<bool> GroupGrantsAsync(Meshmakers.Octo.ConstructionKit.Contracts.OctoObjectId groupId,
        string roleId, HashSet<string> visited, int depth)
    {
        if (depth >= MaxGroupDepth || !visited.Add(groupId.ToString()))
        {
            return false;
        }

        if ((await groupStore.GetRoleIdsAsync(groupId).ConfigureAwait(false)).Contains(roleId))
        {
            return true;
        }

        foreach (var child in await groupStore.GetMemberGroupIdsAsync(groupId).ConfigureAwait(false))
        {
            if (await GroupGrantsAsync(new Meshmakers.Octo.ConstructionKit.Contracts.OctoObjectId(child), roleId,
                    visited, depth + 1).ConfigureAwait(false))
            {
                return true;
            }
        }

        return false;
    }

    private static HashSet<string> ToSet(IEnumerable<string> names) =>
        names.ToHashSet(StringComparer.OrdinalIgnoreCase);
}
