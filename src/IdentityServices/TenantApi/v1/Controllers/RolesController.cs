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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Facades;

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
    private readonly IRoleChangeRefusals _roleChangeRefusals;
    private readonly IIdentityMethodFacade _methodFacade;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="roleManager">The storage service of roles</param>
    /// <param name="multiTenancyResolverService">Multi-tenancy resolver service</param>
    /// <param name="roleChangeRefusals">Audit and answer of a change the role change guard refused</param>
    /// <param name="methodFacade">Runs the <c>Role.*</c> methods the write endpoints are facades of</param>
    public RolesController(RoleManager<RtRole> roleManager, IMultiTenancyResolverService multiTenancyResolverService,
        IRoleChangeRefusals roleChangeRefusals, IIdentityMethodFacade methodFacade)
    {
        _methodFacade = methodFacade;
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
    /// <summary>Creates a new role. Facade of the static CK method <c>Role.CreateRole-1</c>.</summary>
    /// <remarks>
    ///     The method creates the role through the role manager (normalized name derived, one <c>Identity.Method</c> event); the
    ///     endpoint keeps the earlier answers: a duplicate or invalid name is <c>400</c> <c>OperationFailedErrorDto</c> with the
    ///     role manager's code and description.
    /// </remarks>
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
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        const string operation = "Creation of role failed";
        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.RoleCkTypeId,
            SystemIdentityCkIds.RoleCreateRoleMethodId, null,
            new RoleCreateRoleParameters { Name = roleDto.Name ?? string.Empty }, User, HttpContext.RequestAborted);
        return response.ToActionResult(RoleFailures(operation, roleDto.Name)
            .MapSuccess(_ => Ok()));
    }

    // PUT system/v1/role/5
    /// <summary>Renames a role. Facade of the CK method <c>Role.UpdateRole-1</c>.</summary>
    /// <remarks>
    ///     The endpoint resolves the role name to the rtId (<c>404</c> as before); a built-in role is the audited <c>409</c>
    ///     problem of the role change guard, as before.
    /// </remarks>
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
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var rtRole = await _roleManager.FindByNameAsync(roleName);
        if (rtRole == null)
        {
            return NotFound(new NotFoundErrorDto($"Role '{roleName}' not found."));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.RoleCkTypeId,
            SystemIdentityCkIds.RoleUpdateRoleMethodId, rtRole.RtId.ToString(),
            new RoleUpdateRoleParameters { Name = roleDto.Name ?? string.Empty }, User, HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, roleName, RoleFailures("Update of role failed", roleDto.Name));
    }

    // DELETE system/v1/role/5
    /// <summary>Deletes a role. Facade of the CK method <c>Role.DeleteRole-1</c>.</summary>
    /// <remarks>A built-in role is the audited <c>409</c> problem of the role change guard, as before.</remarks>
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
        var octoRole = await _roleManager.FindByNameAsync(roleName);
        if (octoRole == null)
        {
            return NotFound(new NotFoundErrorDto($"Role '{roleName}' not found."));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.RoleCkTypeId,
            SystemIdentityCkIds.RoleDeleteRoleMethodId, octoRole.RtId.ToString(), new RoleDeleteRoleParameters(), User,
            HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, roleName, new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => StatusCode(StatusCodes.Status500InternalServerError,
                new InternalServerErrorDto("Delete of role failed."))));
    }

    /// <summary>
    ///     The REST answers of a failed role create or rename: a duplicate or invalid name is <c>400</c>
    ///     <c>OperationFailedErrorDto</c> with the role manager's code and description (rebuilt from the method's code), an
    ///     unexpected failure <c>500</c> with a fixed message.
    /// </summary>
    private CkMethodFacadeOptions RoleFailures(string operation, string? roleName) => new CkMethodFacadeOptions()
        .MapError(IdentityCrudErrors.RoleAlreadyExists,
            _ => RoleFailed(operation, _roleManager.ErrorDescriber.DuplicateRoleName(roleName ?? string.Empty)))
        .MapError(CkMethodErrorCodes.MethodValidationFailed,
            _ => RoleFailed(operation, _roleManager.ErrorDescriber.InvalidRoleName(roleName)))
        .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => StatusCode(StatusCodes.Status500InternalServerError,
            new InternalServerErrorDto(operation + ".")));

    private BadRequestObjectResult RoleFailed(string operation, IdentityError error) =>
        BadRequest(new OperationFailedErrorDto(operation,
            [new FailedDetailsDto { Code = error.Code, Description = error.Description }]));

    /// <summary>
    ///     The REST answer of a role method on an existing role: <c>200</c> on success, the audited 409 problem of the role
    ///     change guard (WARN log and <c>Identity.RoleChangeRefused</c>) for a built-in role, a role removed in between as the
    ///     earlier <c>404</c>, the endpoint's own mappings, else the facade defaults.
    /// </summary>
    private async Task<IActionResult> ToFacadeResultAsync(CkMethodResponse response, string roleName,
        CkMethodFacadeOptions options)
    {
        if (RoleChangeProblems.RefusalOf(response) is { } decision)
        {
            return await _roleChangeRefusals.RefuseAsync(HttpContext, RoleChangeCaller.FromPrincipal(User), decision,
                $"role {roleName}");
        }

        return response.ToActionResult(options
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound,
                _ => NotFound(new NotFoundErrorDto($"Role '{roleName}' not found."))));
    }
}
