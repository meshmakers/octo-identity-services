using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using AutoMapper;
using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using MongoDB.Bson;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

/// <summary>
///     REST Controller for role management
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class RolesController : ControllerBase
{
    private readonly ISystemContext _systemContext;
    private readonly IMapper _mapper;
    private readonly RoleManager<RtRole> _roleManager;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="roleManager">The storage service of roles</param>
    /// <param name="systemContext">System context</param>
    /// <param name="mapper">Automapper</param>
    public RolesController(RoleManager<RtRole> roleManager, ISystemContext systemContext, IMapper mapper)
    {
        _systemContext = systemContext;
        _mapper = mapper;
        _roleManager = roleManager;
    }

    // GET system/v1/roles
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all existing roles.")]
    [ProducesResponseType(typeof(IEnumerable<RoleDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public IActionResult Get()
    {
        try
        {
            var list = _mapper.Map<List<RoleDto>>(_roleManager.Roles);
            return Ok(list);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // GET system/v1/roles
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all existing roles.")]
    [ProducesResponseType(typeof(PagedResult<RoleDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get([Required][FromQuery] PagingParams pagingParams)
    {
        try
        {
            var tenantRepository = _systemContext.GetSystemTenantRepository();

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
            var list = _mapper.Map<List<RoleDto>>(resultSet.Items);

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
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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

            var roleDto = _mapper.Map<RoleDto>(rtRole);
            return Ok(roleDto);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // POST system/v1/roles
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
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

            var rtRole = _mapper.Map<RtRole>(roleDto);

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
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
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

            _mapper.Map(roleDto, rtRole);

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
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes a role.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
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