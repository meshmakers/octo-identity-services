using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.SetRoles-1</c> (AB#7776): replaces the direct roles of a user by the given role
///     names, with the rules of <c>PUT system/v1/users/{user}/roles</c> (see <see cref="UserRoleMethodHandlerBase{T}" />).
/// </summary>
/// <remarks>
///     REST removes every direct role first and refuses an unknown role afterwards, so a request with an unknown role leaves the
///     user without roles. The method checks all names first: one unknown role changes nothing (<c>ROLE_NOT_FOUND</c>), which is
///     stricter than REST and never grants more. The end state of a successful call is the same; only the difference is
///     written (a role that stays is not removed and added again).
/// </remarks>
internal sealed class UserSetRolesHandler(IServiceProvider services)
    : UserRoleMethodHandlerBase<UserSetRolesParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(UserRoleScope scope, UserSetRolesParameters parameters,
        RtUser user, UserRoleChange change, CancellationToken cancellationToken)
    {
        var wanted = new Dictionary<string, string>(StringComparer.Ordinal); // normalized name -> normalized name
        foreach (var name in parameters.RoleNames ?? [])
        {
            var role = string.IsNullOrWhiteSpace(name) ? null : await scope.FindRoleAsync(name).ConfigureAwait(false);
            if (role?.NormalizedName == null)
            {
                return RoleNotFound(name ?? string.Empty);
            }

            wanted[role.NormalizedName] = role.NormalizedName;
        }

        var guarded = await GuardAsync(scope, user, change, wanted.Values.ToList()).ConfigureAwait(false);
        if (guarded != null)
        {
            return guarded;
        }

        var current = change.Before.Select(UserRoleScope.Normalize).ToHashSet(StringComparer.Ordinal);
        foreach (var normalized in current.Where(c => !wanted.ContainsKey(c)))
        {
            await scope.UserManager.RemoveFromRoleAsync(user, normalized).ConfigureAwait(false);
        }

        foreach (var normalized in wanted.Keys.Where(w => !current.Contains(w)))
        {
            await scope.UserManager.AddToRoleAsync(user, normalized).ConfigureAwait(false);
        }

        return CkMethodOutcome.Ok();
    }
}
