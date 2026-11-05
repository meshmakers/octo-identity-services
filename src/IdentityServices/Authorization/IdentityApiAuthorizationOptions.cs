// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization;

/// <summary>
///     How the tenant role requirement of the identity tenant REST API is applied (AB#5859).
/// </summary>
public enum IdentityApiRoleEnforcementMode
{
    /// <summary>
    ///     A caller without the required tenant role is let through, but every such call is logged as a
    ///     warning ("would be denied"). Transition mode to find callers that need a role before switching
    ///     to <see cref="Enforce" />.
    /// </summary>
    Warn = 0,

    /// <summary>
    ///     A caller without the required tenant role gets <c>403</c>. The default.
    /// </summary>
    Enforce = 1
}

/// <summary>
///     Options of the role-based authorization of the identity tenant REST API (AB#5859). Bound from the
///     <c>"IdentityApiAuthorization"</c> configuration section, i.e.
///     <c>OCTO_IDENTITYAPIAUTHORIZATION__ROLEENFORCEMENT=Warn|Enforce</c>.
/// </summary>
public class IdentityApiAuthorizationOptions
{
    /// <summary>
    ///     The configuration section name.
    /// </summary>
    public const string SectionName = "IdentityApiAuthorization";

    /// <summary>
    ///     Whether a missing tenant role is denied (<see cref="IdentityApiRoleEnforcementMode.Enforce" />,
    ///     default) or only logged (<see cref="IdentityApiRoleEnforcementMode.Warn" />). The scope
    ///     requirement (<c>octo_api.*</c>) is always enforced, independent of this switch.
    /// </summary>
    public IdentityApiRoleEnforcementMode RoleEnforcement { get; set; } = IdentityApiRoleEnforcementMode.Enforce;

    /// <summary>
    ///     AB#5861: staged rollout of the <c>SecretManagement</c> requirement on the API secret writes (REST
    ///     <c>IdentitySecretAdministrationPolicy</c>, client create/update with a secret, the <c>Client.AddSecret</c> /
    ///     <c>Client.RemoveSecret</c> methods). Env <c>OCTO_IDENTITYAPIAUTHORIZATION__SECRETMANAGEMENTROLEENFORCEMENT</c>.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <see cref="IdentityApiRoleEnforcementMode.Warn" /> (default): a caller without <c>SecretManagement</c> who
    ///         holds the previous roles (<c>TenantManagement</c> or <c>UserManagement</c>) is let through and logged
    ///         ("would be denied with SecretManagementRoleEnforcement=Enforce (AB#5861)"); a caller without any of these
    ///         roles is denied as before. So <c>Warn</c> never allows less than the rule before AB#5861.
    ///     </para>
    ///     <para>
    ///         <see cref="IdentityApiRoleEnforcementMode.Enforce" />: only <c>SecretManagement</c> is accepted. Switch per
    ///         cluster after the precheck (<c>scripts/identity-rest-role-precheck.sh</c>) shows that every caller of the
    ///         warn log holds the role.
    ///     </para>
    ///     <para>
    ///         Why its own switch with the safe default: the cluster-wide <see cref="RoleEnforcement" /> is
    ///         <c>Enforce</c>, and <c>SecretManagement</c> was granted only once, to local human administrators
    ///         (AB#5544). Cross-tenant administrators, clients and administrators added later do not hold it, so
    ///         enforcing it with the release would lock them out without warning. <see cref="RoleEnforcement" /> =
    ///         <c>Warn</c> stays the emergency exit and also relaxes this requirement.
    ///     </para>
    /// </remarks>
    public IdentityApiRoleEnforcementMode SecretManagementRoleEnforcement { get; set; } =
        IdentityApiRoleEnforcementMode.Warn;
}
