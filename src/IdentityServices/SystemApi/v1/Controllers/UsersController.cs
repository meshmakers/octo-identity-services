using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using AutoMapper;
using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

/// <summary>
///     REST Controller for user management
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class UsersController : ControllerBase
{
    private readonly ILogger<UsersController> _logger;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly IMapper _mapper;
    private readonly IOptions<OctoSystemConfiguration> _options;
    private readonly IUserEmailInteractionService _userEmailInteractionService;
    private readonly UserManager<RtUser> _userManager;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="userManager">The storage service of users</param>
    /// <param name="roleManager">The storage service of roles</param>
    /// <param name="mapper"></param>
    /// <param name="options"></param>
    /// <param name="userEmailInteractionService"></param>
    /// <param name="logger">Logger</param>
    public UsersController(
        UserManager<RtUser> userManager,
        RoleManager<RtRole> roleManager,
        IMapper mapper,
        IOptions<OctoSystemConfiguration> options,
        IUserEmailInteractionService userEmailInteractionService,
        ILogger<UsersController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _mapper = mapper;
        _options = options;
        _userEmailInteractionService = userEmailInteractionService;
        _logger = logger;
    }

    // GET system/v1/users
    /// <summary>
    ///     Returns all existing users
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all existing users.")]
    [ProducesResponseType(typeof(IEnumerable<UserDto>), StatusCodes.Status200OK)]
    public IEnumerable<UserDto> Get()
    {
        var list = _mapper.Map<List<UserDto>>(_userManager.Users);

        return list;
    }

    // GET system/v1/users/getPaged
    /// <summary>
    ///     Returns all existing users
    /// </summary>
    /// <returns></returns>
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all existing users.")]
    [ProducesResponseType(typeof(IEnumerable<UserDto>), StatusCodes.Status200OK)]
    public PagedResult<UserDto> Get([Required] [FromQuery] PagingParams pagingParams)
    {
        var list = new List<UserDto>();
        foreach (var rtUser in _userManager.Users.Skip(pagingParams.Skip).Take(pagingParams.Take))
        {
            var userDto = _mapper.Map<UserDto>(rtUser);
            list.Add(userDto);
        }

        var pagedResult =
            new PagedResult<UserDto>(list, pagingParams.Skip, pagingParams.Take, _userManager.Users.Count());

        var header = pagedResult.GetHeader();
        if (header != null)
        {
            Response.Headers.Append("X-Pagination", header.ToJson());
        }

        return pagedResult;
    }

    // GET system/v1/users/{userName}
    [HttpGet("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns user information based on it's userName, email or id")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get([Required] [Description("Name of the user")] string userName)
    {
        var rtUser = await _userManager.FindByNameAsync(userName) ??
                     await _userManager.FindByEmailAsync(userName) ??
                     await _userManager.FindByIdAsync(userName);
        if (rtUser == null)
        {
            return NotFound();
        }

        var userDto = _mapper.Map<UserDto>(rtUser);
        return Ok(userDto);
    }

    // GET system/v1/users/{userName}
    [HttpGet("{userName}/roles")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns user roles based on it's userName, email or id")]
    [ProducesResponseType(typeof(IEnumerable<RoleDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetUserRoles([Required] [Description("Name of the user")] string userName)
    {
        var octoUser = await _userManager.FindByNameAsync(userName) ??
                       await _userManager.FindByEmailAsync(userName) ??
                       await _userManager.FindByIdAsync(userName);
        if (octoUser == null)
        {
            return NotFound();
        }


        List<RoleDto> roles = new();
        if (octoUser.RoleIds != null)
        {
            foreach (var octoUserRoleId in octoUser.RoleIds)
            {
                var role = await _roleManager.FindByIdAsync(octoUserRoleId);
                if (role != null)
                {
                    roles.Add(_mapper.Map<RoleDto>(role));
                }
            }
        }

        return Ok(roles);
    }


    // POST system/v1/users
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post(
        [Required] [FromBody] [Description("The user data transfer object instance")]
        RegisterUserDto userDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var rtUser = _mapper.Map<RtUser>(userDto);

        try
        {
            var result = await _userManager.CreateAsync(rtUser);

            if (!result.Succeeded)
            {
                LogIdentityError("Create user", result.Errors);

                return GetBadRequestResultWithErrorDescription("Creation of user failed", result.Errors);
            }

            if (!string.IsNullOrWhiteSpace(userDto.Password))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(rtUser);
                result = await _userManager.ResetPasswordAsync(rtUser, token, userDto.Password);

                if (!result.Succeeded)
                {
                    LogIdentityError("Reset Password", result.Errors);
                    return GetBadRequestResultWithErrorDescription("Creation of user failed", result.Errors);
                }

                await _userEmailInteractionService.SendWelcomeNotificationAsync(_options.Value.SystemTenantId, rtUser);
            }
            else
            {
                await _userEmailInteractionService.SendWelcomeNotificationWithoutPasswordAsync(
                    _options.Value.SystemTenantId, rtUser);
            }

            return Ok();
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // PUT system/v1/users/5
    [HttpPut("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates a user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Put(
        [Required] [Description("The username")]
        string userName,
        [Required] [FromBody] [Description("The client data transfer object instance")]
        UserDto userDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var rtUser = await _userManager.FindByNameAsync(userName);
        if (rtUser == null)
        {
            return NotFound(new NotFoundErrorDto($"User name '{userName}' not found."));
        }

        _mapper.Map(userDto, rtUser);

        try
        {
            var result = await _userManager.UpdateAsync(rtUser);
            if (result.Succeeded)
            {
                return Ok();
            }

            return GetBadRequestResultWithErrorDescription("Update of user failed", result.Errors);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // POST: system/v1/users/resetPassword
    [HttpPost]
    [Route("ResetPassword")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Resets the password of an user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ResetPassword([Required] [Description("The username")] string userName,
        [Required] [Description("The new password")]
        string password)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        try
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
            {
                return NotFound(new NotFoundErrorDto($"User '{userName}' not found."));
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var result = await _userManager.ResetPasswordAsync(user, token, password);
            if (result.Succeeded)
            {
                await _userEmailInteractionService.SendPasswordResetNotificationAsync(_options.Value.SystemTenantId,
                    user);
                return Ok();
            }

            return GetBadRequestResultWithErrorDescription("Reset of password failed.", result.Errors);
        }
        catch (InvalidOperationException e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // DELETE system/v1/users/5
    [HttpDelete("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes an user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Delete([Required] [Description("The username")] string userName)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var applicationUser = await _userManager.FindByNameAsync(userName);
        if (applicationUser == null)
        {
            return NotFound(new NotFoundErrorDto($"User name '{userName}' not found."));
        }

        try
        {
            var result = await _userManager.DeleteAsync(applicationUser);
            if (result.Succeeded)
            {
                return Ok();
            }

            return GetBadRequestResultWithErrorDescription("Delete of user failed", result.Errors);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // PUT system/v1/users/demo/roles/users
    [HttpPut("{userName}/roles")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Adds roles to an user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> UpdateUserRoles([Required] [Description("The username")] string userName,
        [Required] [FromBody] [Description("The role ids")]
        IEnumerable<OctoObjectId> roleIds)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User with name '{userName}' not found."));
        }

        user.RoleIds ??= new AttributeStringValueList();
        user.RoleIds.Clear();

        foreach (var roleId in roleIds)
        {
            var role = await _roleManager.FindByIdAsync(roleId.ToString());
            if (role == null)
            {
                return NotFound(new NotFoundErrorDto($"Role with id '{roleId}' not found."));
            }

            user.RoleIds?.Add(role.RtId.ToString());
        }

        await _userManager.UpdateAsync(user);
        return Ok();
    }

    // PUT system/v1/users/demo/roles/users
    [HttpPut("{userName}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Adds a role to a user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> AddUserToRole([Required] [Description("The username")] string userName,
        [Required] [Description("The role name")]
        string roleName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User with name '{userName}' not found."));
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found."));
        }

        if (user.RoleIds?.Contains(role.RtId.ToString()) ?? false)
        {
            return BadRequest(new OperationFailedErrorDto($"User '{user.UserName}' already has role '{role.Name}'"));
        }

        user.RoleIds ??= new AttributeStringValueList();
        user.RoleIds.Add(role.RtId.ToString());
        await _userManager.UpdateAsync(user);
        return Ok();
    }

    // DELETE system/v1/users/demo/roles/Users
    [HttpDelete("{userName}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Removes a role from a user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> RemoveRoleFromUser([Required] [Description("The username")] string userName,
        [Required] [Description("The role name")]
        string roleName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User with name '{userName}' not found."));
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found."));
        }

        if (!user.RoleIds?.Contains(role.RtId.ToString()) ?? false)
        {
            return BadRequest(new OperationFailedErrorDto($"User '{user.UserName}' doesn't have role '{role.Name}'"));
        }

        user.RoleIds?.Remove(role.RtId.ToString());
        await _userManager.UpdateAsync(user);
        return Ok();
    }

    private void LogIdentityError(string operation, IEnumerable<IdentityError> errors)
    {
        var identityErrors = errors as IdentityError[] ?? errors.ToArray();
        _logger.LogError("{Operation} failed with errors: '{Errors}' and codes '{Codes}'",
            operation,
            string.Join(", ", identityErrors.Select(x => x.Description)),
            string.Join(", ", identityErrors.Select(x => x.Code)));
    }

    private IActionResult GetBadRequestResultWithErrorDescription(string operation, IEnumerable<IdentityError> errors)
    {
        return BadRequest(new OperationFailedErrorDto(operation,
            errors.Select(x => new FailedDetailsDto { Code = x.Code, Description = x.Description })));
    }
}