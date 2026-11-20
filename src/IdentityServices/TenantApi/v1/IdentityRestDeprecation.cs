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

    /// <summary>
    ///     Identity wave 2: the REST write endpoints that are facades of the group, client, secret, client mirror, data
    ///     permission, admin provisioning and CRUD methods (System.Identity 3.3.0 to 3.8.0). No <c>Sunset</c> until the
    ///     sunset date is decided; the endpoints that stay REST carry no attribute (list with the reasons:
    ///     <c>docs/identity-rest-facades.md</c>, "Deprecation of the identity wave 2 endpoints").
    /// </summary>
    public const string Wave2 = "IdentityWave2";

    private const string MethodsPage = "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods";

    /// <summary>Documentation of the group role and membership methods (<c>Group.SetRoles</c>, <c>AddMember</c>, ...).</summary>
    public const string GroupMethodsLink = MethodsPage + "#groups";

    /// <summary>Documentation of the client role and overlay methods (<c>Client.SetRoles</c>, <c>ApplyOverlayUris</c>, ...).</summary>
    public const string ClientRoleMethodsLink = MethodsPage + "#client-roles";

    /// <summary>Documentation of the client and API resource secret methods (<c>AddSecret</c>, <c>UpdateSecret</c>, <c>RemoveSecret</c>).</summary>
    public const string SecretMethodsLink = MethodsPage + "#client-secrets";

    /// <summary>Documentation of <c>DataPermission.GrantToRole</c>, <c>RevokeFromRole</c> and <c>DataPolicy.SetEnforcementMode</c>.</summary>
    public const string DataPermissionMethodsLink = MethodsPage + "#data-permissions";

    /// <summary>Documentation of the client mirror methods (<c>Client.ProvisionMirrors</c>, <c>RotateMirrorSecret</c>, ...).</summary>
    public const string ClientMirrorMethodsLink = MethodsPage + "#client-mirrors";

    /// <summary>Documentation of the admin provisioning methods and <c>ExternalTenantUserMapping.CreateMapping</c>.</summary>
    public const string AdminProvisioningMethodsLink = MethodsPage + "#admin-provisioning";

    /// <summary>Documentation of the role, group, API scope and API resource create, update and delete methods.</summary>
    public const string CrudMethodsLink = MethodsPage + "#crud";

    /// <summary>
    ///     Documentation of the identity provider, e-mail domain group rule, mapping, data permission and policy and client
    ///     create, update and delete methods.
    /// </summary>
    public const string CrudWave2MethodsLink = MethodsPage + "#crud-wave-2";

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
