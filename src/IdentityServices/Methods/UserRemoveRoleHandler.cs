using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.RemoveRole-1</c> (AB#7776): removes one direct role, with the rules of
///     <c>DELETE system/v1/users/{user}/roles/{role}</c> (see <see cref="UserRoleMethodHandlerBase{T}" />).
/// </summary>
internal sealed class UserRemoveRoleHandler(IServiceProvider services)
    : UserRoleMethodHandlerBase<UserRemoveRoleParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(UserRoleScope scope,
        UserRemoveRoleParameters parameters, RtUser user, UserRoleChange change, CancellationToken cancellationToken)
    {
        var role = string.IsNullOrWhiteSpace(parameters.RoleName)
            ? null
            : await scope.FindRoleAsync(parameters.RoleName).ConfigureAwait(false);
        if (role?.NormalizedName == null)
        {
            return RoleNotFound(parameters.RoleName ?? string.Empty);
        }

        if (!change.Before.Any(r => UserRoleScope.Normalize(r) == role.NormalizedName))
        {
            return CkMethodOutcome.Fail(UserRoleMethodErrors.RoleNotAssigned);
        }

        var guarded = await GuardAsync(scope, user, change,
            change.Before.Where(r => UserRoleScope.Normalize(r) != role.NormalizedName).ToList()).ConfigureAwait(false);
        if (guarded != null)
        {
            return guarded;
        }

        await scope.UserManager.RemoveFromRoleAsync(user, role.NormalizedName).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
