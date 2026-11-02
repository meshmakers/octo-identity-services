using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Refuses every password for users carrying the reserved cross-tenant shadow user prefix
///     (<c>xt_</c>, AB#5708).
/// </summary>
/// <remarks>
///     <para>
///         A shadow user is the projection of an identity that authenticates in its home tenant; it never
///         has a local credential (<see cref="CrossTenantUserProvisioningService" /> creates it without a
///         password and treats an <c>xt_</c> user WITH a password as an impostor it must not hand out). A
///         password would add a second, local way into the tenant that bypasses the home tenant's login,
///         MFA and account lifecycle.
///     </para>
///     <para>
///         Registered as an Identity password validator, so it covers every <see cref="UserManager{TUser}" />
///         path that stores a password — create with password, admin reset, self-service change/set and the
///         e-mail reset — regardless of which endpoint calls it. Endpoints may check
///         <see cref="CrossTenantShadowUserName.IsShadowUserName" /> earlier for a clearer response.
///     </para>
/// </remarks>
public sealed class ShadowUserPasswordValidator : IPasswordValidator<RtUser>
{
    /// <summary>Error code of the refusal.</summary>
    public const string ErrorCode = "ShadowUserPasswordNotAllowed";

    /// <summary>Human-readable refusal message, also used by endpoints that check up front.</summary>
    public const string ErrorMessage =
        "Cross-tenant users (user names starting with 'xt_') sign in through their home tenant and cannot have a password.";

    /// <inheritdoc />
    public Task<IdentityResult> ValidateAsync(UserManager<RtUser> manager, RtUser user, string? password)
    {
        ArgumentNullException.ThrowIfNull(user);

        return Task.FromResult(CrossTenantShadowUserName.IsShadowUserName(user.UserName)
            ? IdentityResult.Failed(new IdentityError { Code = ErrorCode, Description = ErrorMessage })
            : IdentityResult.Success);
    }
}
