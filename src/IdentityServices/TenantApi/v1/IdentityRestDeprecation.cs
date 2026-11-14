namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1;

/// <summary>
///     Waves and documentation links of the deprecated identity REST endpoints (AB#8415, AB#8860, F5.1).
/// </summary>
/// <remarks>
///     <para>
///         The dates of a wave are not in the code: Gerald's rule (2026-11-11) deprecates an endpoint from the delivery of
///         the release that contains it; the sunset date is to be announced (Gerald decides it once the migration functions
///         are implemented), so both are only known at rollout. They come from the configuration <c>RestDeprecation:Waves:&lt;wave&gt;:Since|Sunset</c>
///         (Helm values <c>restDeprecation.waves</c> of the octo-mesh chart); see <c>docs/rest-deprecation.md</c> in
///         octo-common-services.
///     </para>
/// </remarks>
internal static class IdentityRestDeprecation
{
    /// <summary>
    ///     Identity wave 1, user endpoints without a password: <c>PUT users/{userName}/roles</c>,
    ///     <c>PUT|DELETE users/{userName}/roles/{roleName}</c> and <c>POST users/{userName}/merge</c>.
    /// </summary>
    public const string UsersWave1 = "IdentityUsers1";

    /// <summary>
    ///     Identity wave of the user endpoints that carry a password (AB#8860): <c>POST users</c> and
    ///     <c>POST users/ResetPassword</c>. A wave of its own because it starts with another release than wave 1: the
    ///     release that delivers AB#8418 (the first-party clients call <c>User.CreateUser</c> / <c>User.ResetPassword</c>).
    /// </summary>
    public const string UsersPasswordWave = "IdentityUsersPassword";

    /// <summary>Documentation of <c>User.SetRoles</c>, <c>User.AddRole</c> and <c>User.RemoveRole</c>.</summary>
    public const string UserRoleMethodsLink =
        "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#user-roles";

    /// <summary>Documentation of <c>User.Merge</c>.</summary>
    public const string UserMergeMethodLink =
        "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#usermerge";

    /// <summary>Documentation of <c>User.CreateUser</c>.</summary>
    public const string UserCreateUserMethodLink =
        "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#usercreateuser";

    /// <summary>Documentation of <c>User.ResetPassword</c>.</summary>
    public const string UserResetPasswordMethodLink =
        "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#userresetpassword";
}
