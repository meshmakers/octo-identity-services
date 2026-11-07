namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1;

/// <summary>
///     Waves and documentation links of the deprecated identity REST endpoints (AB#8415, F5.1).
/// </summary>
/// <remarks>
///     <para>
///         The dates of a wave are not in the code: Gerald's rule (2026-11-07) deprecates an endpoint from the delivery of
///         the release that contains it and sets the sunset one week after that release runs on prod-1 and prod-2, so both
///         are only known at rollout. They come from the configuration <c>RestDeprecation:Waves:&lt;wave&gt;:Since|Sunset</c>
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

    /// <summary>Documentation of <c>User.SetRoles</c>, <c>User.AddRole</c> and <c>User.RemoveRole</c>.</summary>
    public const string UserRoleMethodsLink =
        "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#user-roles";

    /// <summary>Documentation of <c>User.Merge</c>.</summary>
    public const string UserMergeMethodLink =
        "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#usermerge";
}
