using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using MongoDB.Bson;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST Controller for role management
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class RolesController : ControllerBase
{
    private readonly IMultiTenancyResolverService _multiTenancyResolverService;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly IRoleChangeGuard _roleChangeGuard;
    private readonly IRoleChangeRefusals _roleChangeRefusals;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="roleManager">The storage service of roles</param>
    /// <param name="multiTenancyResolverService">Multi-tenancy resolver service</param>
    /// <param name="roleChangeGuard">Built-in roles cannot be renamed or deleted (AB#7927)</param>
    /// <param name="roleChangeRefusals">Audit and answer of a refused change</param>
    public RolesController(RoleManager<RtRole> roleManager, IMultiTenancyResolverService multiTenancyResolverService,
        IRoleChangeGuard roleChangeGuard, IRoleChangeRefusals roleChangeRefusals)
    {
        _roleChangeGuard = roleChangeGuard;
        _roleChangeRefusals = roleChangeRefusals;
        _multiTenancyResolverService = multiTenancyResolverService;
        _roleManager = roleManager;
    }

    // GET system/v1/roles
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityDirectoryReadPolicy)]
    [EndpointSummary("Returns all existing roles.")]
    [ProducesResponseType(typeof(IEnumerable<RoleDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public IActionResult Get()
    {
        try
        {
            var list = _roleManager.Roles.AsEnumerable().Select(role => role.ToDto()).ToList();
            return Ok(list);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // GET system/v1/roles
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityDirectoryReadPolicy)]
    [EndpointSummary("Returns all existing roles.")]
    [ProducesResponseType(typeof(PagedResult<RoleDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get([Required][FromQuery] PagingParams pagingParams)
    {
        try
        {
            var tenantRepository = _multiTenancyResolverService.GetTenantRepository();

            using var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            var queryOptions = RtEntityQueryOptions.Create();
            if (!string.IsNullOrWhiteSpace(pagingParams.Filter))
            {
                queryOptions.FieldLike(nameof(RtRole.Name), pagingParams.Filter);
            }

            var resultSet =
                await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, queryOptions, pagingParams.Skip,
                    pagingParams.Take);
            var list = resultSet.Items.Select(role => role.ToDto()).ToList();

            var pagedResult = new PagedResult<RoleDto>(list, pagingParams.Skip, pagingParams.Take, resultSet.TotalCount);

            var header = pagedResult.GetHeader();
            if (header != null)
            {
                Response.Headers.Append("X-Pagination", header.ToJson());
            }

            return Ok(pagedResult);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // GET system/v1/roles/names/{roleName}
    [HttpGet("names/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityDirectoryReadPolicy)]
    [EndpointSummary("Returns role information based on it's name")]
    [ProducesResponseType(typeof(RoleDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get([Required][Description("Name of the role")] string roleName)
    {
        try
        {
            var rtRole = await _roleManager.FindByNameAsync(roleName);
            if (rtRole == null)
            {
                return NotFound();
            }

            var roleDto = rtRole.ToDto();
            return Ok(roleDto);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // POST system/v1/roles
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Creates a new role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Post(
        [Required][FromBody][Description("The role data transfer object instance")] RoleDto roleDto)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var rtRole = roleDto.ToEntity();

            var result = await _roleManager.CreateAsync(rtRole);
            if (result.Succeeded)
            {
                return Ok();
            }

            return BadRequest(new OperationFailedErrorDto("Creation of role failed",
                result.Errors.Select(x => new FailedDetailsDto { Code = x.Code, Description = x.Description })));
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // PUT system/v1/role/5
    [HttpPut("{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Updates a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Put(
        [Required][Description("The role name")] string roleName,
        [Required][FromBody][Description("The role data transfer object instance")] RoleDto roleDto)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var rtRole = await _roleManager.FindByNameAsync(roleName);
            if (rtRole == null)
            {
                return NotFound(new NotFoundErrorDto($"Role '{roleName}' not found."));
            }

            var refusal = _roleChangeGuard.EvaluateRoleDefinition(rtRole, roleDto.Name);
            if (!refusal.IsAllowed)
            {
                return await _roleChangeRefusals.RefuseAsync(HttpContext, RoleChangeCaller.FromPrincipal(User), refusal,
                    $"role {roleName}");
            }

            roleDto.ApplyTo(rtRole);

            var result = await _roleManager.UpdateAsync(rtRole);
            if (result.Succeeded)
            {
                return Ok();
            }

            return BadRequest(new OperationFailedErrorDto("Update of role failed",
                result.Errors.Select(x => new FailedDetailsDto { Code = x.Code, Description = x.Description })));
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // DELETE system/v1/role/5
    [HttpDelete("{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Deletes a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Delete([Required][Description("The role name")] string roleName)
    {
        try
        {
            var octoRole = await _roleManager.FindByNameAsync(roleName);
            if (octoRole == null)
            {
                return NotFound(new NotFoundErrorDto($"Role '{roleName}' not found."));
            }

            var refusal = _roleChangeGuard.EvaluateRoleDefinition(octoRole, null);
            if (!refusal.IsAllowed)
            {
                return await _roleChangeRefusals.RefuseAsync(HttpContext, RoleChangeCaller.FromPrincipal(User), refusal,
                    $"role {roleName}");
            }

            var result = await _roleManager.DeleteAsync(octoRole);
            if (result.Succeeded)
            {
                return Ok();
            }

            return BadRequest(new OperationFailedErrorDto("Delete of role failed",
                result.Errors.Select(x => new FailedDetailsDto { Code = x.Code, Description = x.Description })));
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }
}