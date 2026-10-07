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
}
