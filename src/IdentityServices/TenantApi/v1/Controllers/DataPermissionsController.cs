using Asp.Versioning;

using Duende.IdentityModel;

using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;

using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods.Facades;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST controller for the data-permission model (AB#4972): DataPermissions, their DataPolicies
/// and the role grants. The grant, revoke and enforcement-mode endpoints are facades of the CK methods
/// <c>DataPermission.GrantToRole-1</c>, <c>DataPermission.RevokeFromRole-1</c> and <c>DataPolicy.SetEnforcementMode-1</c>
/// (AB#9039, docs/identity-rest-facades.md); create and delete stay REST (generic CRUD story of Feature F5.2).
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class DataPermissionsController(IDataPermissionStore dataPermissionStore, IIdentityMethodFacade methodFacade)
    : ControllerBase
{
    /// <summary>
    /// Returns all data permissions with their policies and role grants.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Removes a policy.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> DeletePolicy([FromRoute] string policyRtId)
    {
        await dataPermissionStore.RemovePolicyAsync(OctoObjectId.Parse(policyRtId));
        return Ok();
    }

    /// <summary>
    /// Switches a policy between Enforce and AuditOnly (the operator flip after the audit review). Facade of the CK method
    /// <c>DataPolicy.SetEnforcementMode-1</c> (AB#9039).
    /// </summary>
    [HttpPut("policies/{policyRtId}/enforcementMode")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Switches a policy between Enforce and AuditOnly.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> SetEnforcementMode([FromRoute] string policyRtId,
        [FromBody] string enforcementMode)
    {
        if (!TryParseEnforcementMode(enforcementMode, out var mode))
        {
            return BadRequest("EnforcementMode must be Enforce|AuditOnly.");
        }

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.DataPolicyCkTypeId,
            SystemIdentityCkIds.DataPolicySetEnforcementModeMethodId, policyRtId,
            new DataPolicySetEnforcementModeParameters { EnforcementMode = mode }, User, HttpContext.RequestAborted);
        return ToActionResult(response, new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodTargetNotFound,
                _ => NotFound(new NotFoundErrorDto($"Data policy '{policyRtId}' not found."))));
    }

    /// <summary>
    /// Grants the permission to a role. Facade of the CK method <c>DataPermission.GrantToRole-1</c> (AB#9039); a grant the
    /// role already holds is <c>200</c> without a change, as before.
    /// </summary>
    [HttpPost("{permissionId}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Grants the permission to a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GrantToRole([FromRoute] string permissionId, [FromRoute] string roleName)
    {
        var permission = await dataPermissionStore.FindByPermissionIdAsync(permissionId);
        if (permission == null)
        {
            return PermissionNotFound(permissionId);
        }

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.DataPermissionCkTypeId,
            SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, permission.RtId.ToString(),
            new DataPermissionGrantToRoleParameters { RoleName = roleName }, User, HttpContext.RequestAborted);
        return ToActionResult(response, RoleGrantOptions(permissionId, roleName)
            .MapError(DataPermissionMethodErrors.PermissionAlreadyGranted, _ => Ok()));
    }

    /// <summary>
    /// Revokes the permission from a role. Facade of the CK method <c>DataPermission.RevokeFromRole-1</c> (AB#9039); a role
    /// that does not hold the permission is <c>200</c> without a change, as before.
    /// </summary>
    [HttpDelete("{permissionId}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Revokes the permission from a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RevokeFromRole([FromRoute] string permissionId, [FromRoute] string roleName)
    {
        var permission = await dataPermissionStore.FindByPermissionIdAsync(permissionId);
        if (permission == null)
        {
            return PermissionNotFound(permissionId);
        }

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.DataPermissionCkTypeId,
            SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId, permission.RtId.ToString(),
            new DataPermissionRevokeFromRoleParameters { RoleName = roleName }, User, HttpContext.RequestAborted);
        return ToActionResult(response, RoleGrantOptions(permissionId, roleName)
            .MapError(DataPermissionMethodErrors.PermissionNotGranted, _ => Ok()));
    }

    /// <summary>The mappings grant and revoke share: <c>200</c> empty, unknown (or unreadable) permission or role <c>404</c>.</summary>
    private CkMethodFacadeOptions RoleGrantOptions(string permissionId, string roleName) =>
        new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => PermissionNotFound(permissionId))
            .MapError(UserRoleMethodErrors.RoleNotFound,
                _ => NotFound(new NotFoundErrorDto($"Role '{roleName}' not found.")));

    private NotFoundObjectResult PermissionNotFound(string permissionId) =>
        NotFound(new NotFoundErrorDto($"Data permission '{permissionId}' not found."));

    /// <summary>
    /// The REST answer of a facade: <c>200</c> empty on success, the endpoint's mappings, refusals as the default
    /// <c>403</c> problem, and an unexpected failure as <c>500</c> problem <c>METHOD_HANDLER_FAILED</c> (no exception text).
    /// </summary>
    private static IActionResult ToActionResult(CkMethodResponse response, CkMethodFacadeOptions options) =>
        response.ToActionResult(options.MapSuccess(_ => new OkResult()));

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
