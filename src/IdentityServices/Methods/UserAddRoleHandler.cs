using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.AddRole-1</c> (AB#7776): adds one direct role, with the rules of
///     <c>PUT system/v1/users/{user}/roles/{role}</c> (see <see cref="UserRoleMethodHandlerBase{T}" />).
/// </summary>
internal sealed class UserAddRoleHandler(IServiceProvider services)
    : UserRoleMethodHandlerBase<UserAddRoleParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(UserRoleScope scope, UserAddRoleParameters parameters,
        RtUser user, UserRoleChange change, CancellationToken cancellationToken)
    {
        var role = string.IsNullOrWhiteSpace(parameters.RoleName)
            ? null
            : await scope.FindRoleAsync(parameters.RoleName).ConfigureAwait(false);
        if (role?.NormalizedName == null)
        {
            return RoleNotFound(parameters.RoleName ?? string.Empty);
        }

        if (change.Before.Any(r => UserRoleScope.Normalize(r) == role.NormalizedName))
        {
            return CkMethodOutcome.Fail(UserRoleMethodErrors.RoleAlreadyAssigned);
        }

        await scope.UserManager.AddToRoleAsync(user, role.NormalizedName).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
