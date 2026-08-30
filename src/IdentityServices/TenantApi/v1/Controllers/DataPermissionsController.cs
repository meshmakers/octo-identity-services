using Asp.Versioning;

using IdentityModel;

using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;

using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST controller for the data-permission model (AB#4972): DataPermissions, their DataPolicies
/// and the role grants.
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class DataPermissionsController(IDataPermissionStore dataPermissionStore) : ControllerBase
{
    /// <summary>
    /// Returns all data permissions with their policies and role grants.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all data permissions with their policies and role grants.")]
    [ProducesResponseType(typeof(IEnumerable<DataPermissionDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<DataPermissionDto>>> GetAll()
    {
        var permissions = await dataPermissionStore.GetAllAsync();
        var dtos = new List<DataPermissionDto>();
        foreach (var permission in permissions)
        {
            dtos.Add(await MapToDtoAsync(permission));
        }

        return Ok(dtos);
    }

    /// <summary>
    /// Creates a data permission.
    /// </summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a data permission.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> Create([FromBody] DataPermissionDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.PermissionId))
        {
            return BadRequest("PermissionId is required.");
        }

        await dataPermissionStore.CreateAsync(dto.PermissionId, dto.Description);
        return Ok();
    }

    /// <summary>
    /// Removes a data permission including its policies.
    /// </summary>
    [HttpDelete("{permissionId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Removes a data permission including its policies.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> Delete([FromRoute] string permissionId)
    {
        await dataPermissionStore.RemoveAsync(permissionId);
        return Ok();
    }

    /// <summary>
    /// Creates a policy bound to a data permission.
    /// </summary>
    [HttpPost("{permissionId}/policies")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a policy bound to a data permission.")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    public async Task<ActionResult<string>> CreatePolicy([FromRoute] string permissionId,
        [FromBody] DataPolicyDto dto)
    {
        if (dto.TargetCkTypeIds.Count == 0)
        {
            return BadRequest("TargetCkTypeIds must not be empty.");
        }

        if (!TryParseScope(dto.Scope, out var scope) ||
            !TryParseEnforcementMode(dto.EnforcementMode, out var enforcementMode))
        {
            return BadRequest("Scope must be All|OwnedOnly, EnforcementMode must be Enforce|AuditOnly.");
        }

        var rtId = await dataPermissionStore.CreatePolicyAsync(permissionId, dto.TargetCkTypeIds, dto.Actions,
            scope, enforcementMode);
        return Ok(rtId.ToString());
    }

    /// <summary>
    /// Removes a policy.
    /// </summary>
    [HttpDelete("policies/{policyRtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Removes a policy.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> DeletePolicy([FromRoute] string policyRtId)
    {
        await dataPermissionStore.RemovePolicyAsync(OctoObjectId.Parse(policyRtId));
        return Ok();
    }

    /// <summary>
    /// Switches a policy between Enforce and AuditOnly (the operator flip after the audit review).
    /// </summary>
    [HttpPut("policies/{policyRtId}/enforcementMode")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Switches a policy between Enforce and AuditOnly.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> SetEnforcementMode([FromRoute] string policyRtId,
        [FromBody] string enforcementMode)
    {
        if (!TryParseEnforcementMode(enforcementMode, out var mode))
        {
            return BadRequest("EnforcementMode must be Enforce|AuditOnly.");
        }

        await dataPermissionStore.SetPolicyEnforcementModeAsync(OctoObjectId.Parse(policyRtId), mode);
        return Ok();
    }

    /// <summary>
    /// Grants the permission to a role.
    /// </summary>
    [HttpPost("{permissionId}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Grants the permission to a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> GrantToRole([FromRoute] string permissionId, [FromRoute] string roleName)
    {
        await dataPermissionStore.GrantToRoleAsync(permissionId, roleName);
        return Ok();
    }

    /// <summary>
    /// Revokes the permission from a role.
    /// </summary>
    [HttpDelete("{permissionId}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Revokes the permission from a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> RevokeFromRole([FromRoute] string permissionId, [FromRoute] string roleName)
    {
        await dataPermissionStore.RevokeFromRoleAsync(permissionId, roleName);
        return Ok();
    }

    private async Task<DataPermissionDto> MapToDtoAsync(RtDataPermission permission)
    {
        var policies = await dataPermissionStore.GetPoliciesAsync(permission.RtId);
        var roleNames = await dataPermissionStore.GetGrantedRoleNamesAsync(permission.RtId);

        return new DataPermissionDto
        {
            Id = permission.RtId,
            PermissionId = permission.PermissionId ?? string.Empty,
            Description = permission.Description,
            GrantedRoleNames = roleNames.ToList(),
            Policies = policies.Select(p => new DataPolicyDto
            {
                Id = p.RtId,
                TargetCkTypeIds = p.TargetCkTypeIds?.ToList() ?? [],
                Actions = p.Actions?.ToList() ?? [],
                Scope = p.Scope.ToString(),
                EnforcementMode = p.EnforcementMode.ToString()
            }).ToList()
        };
    }

    private static bool TryParseScope(string value, out RtDataPolicyScopeEnum scope)
    {
        return Enum.TryParse(value, true, out scope);
    }

    private static bool TryParseEnforcementMode(string value, out RtDataPolicyEnforcementModeEnum mode)
    {
        return Enum.TryParse(value, true, out mode);
    }
}
