using Meshmakers.Octo.ConstructionKit.Contracts;

using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Store for the data-permission model (AB#4972): DataPermission entities, their DataPolicies
///     and the GrantsPermission edges to roles.
/// </summary>
public interface IDataPermissionStore
{
    /// <summary>Returns all data permissions.</summary>
    Task<IReadOnlyList<RtDataPermission>> GetAllAsync();

    /// <summary>Finds a data permission by its dot-namespaced permission id.</summary>
    Task<RtDataPermission?> FindByPermissionIdAsync(string permissionId);

    /// <summary>Creates a data permission; fails when the permission id already exists.</summary>
    Task<OctoObjectId> CreateAsync(string permissionId, string? description);

    /// <summary>Removes a data permission including its policies.</summary>
    Task RemoveAsync(string permissionId);

    /// <summary>Returns the policies bound to a permission.</summary>
    Task<IReadOnlyList<RtDataPolicy>> GetPoliciesAsync(OctoObjectId permissionRtId);

    /// <summary>Creates a policy bound to the permission.</summary>
    Task<OctoObjectId> CreatePolicyAsync(string permissionId, IReadOnlyList<string> targetCkTypeIds,
        IReadOnlyList<string> actions, RtDataPolicyScopeEnum scope,
        RtDataPolicyEnforcementModeEnum enforcementMode);

    /// <summary>Removes a policy.</summary>
    Task RemovePolicyAsync(OctoObjectId policyRtId);

    /// <summary>Switches a policy between Enforce and AuditOnly (the operator flip, AB#4974).</summary>
    Task SetPolicyEnforcementModeAsync(OctoObjectId policyRtId, RtDataPolicyEnforcementModeEnum enforcementMode);

    /// <summary>Returns the names of the roles the permission is granted to.</summary>
    Task<IReadOnlyList<string>> GetGrantedRoleNamesAsync(OctoObjectId permissionRtId);

    /// <summary>Grants the permission to a role (by role name).</summary>
    Task GrantToRoleAsync(string permissionId, string roleName);

    /// <summary>Revokes the permission from a role (by role name).</summary>
    Task RevokeFromRoleAsync(string permissionId, string roleName);
}
