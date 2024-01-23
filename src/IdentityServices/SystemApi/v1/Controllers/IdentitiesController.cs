using System.ComponentModel.DataAnnotations;
using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Common.ApiErrors;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

/// <summary>
///     REST Controller for user management
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class IdentitiesController : ControllerBase
{
    private readonly ILogger<IdentitiesController> _logger;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly IUserEmailInteractionService _userEmailInteractionService;
    private readonly UserManager<RtUser> _userManager;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="userManager">The storage service of users</param>
    /// <param name="roleManager">The storage service of roles</param>
    /// <param name="userEmailInteractionService"></param>
    /// <param name="logger">Logger</param>
    public IdentitiesController(
        UserManager<RtUser> userManager,
        RoleManager<RtRole> roleManager,
        IUserEmailInteractionService userEmailInteractionService,
        ILogger<IdentitiesController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _userEmailInteractionService = userEmailInteractionService;
        _logger = logger;
    }

    // GET system/v1/identities
    /// <summary>
    ///     Returns all existing users
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public IEnumerable<UserDto> Get()
    {
        var list = new List<UserDto>();
        foreach (var applicationUser in _userManager.Users)
        {
            var userDto = CreateUserDto(applicationUser);
            list.Add(userDto);
        }

        return list;
    }

    // GET system/v1/identities/getPaged
    /// <summary>
    ///     Returns all existing users
    /// </summary>
    /// <returns></returns>
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public PagedResult<UserDto> Get([Required] [FromQuery] PagingParams pagingParams)
    {
        var list = new List<UserDto>();
        foreach (var applicationUser in _userManager.Users.Skip(pagingParams.Skip).Take(pagingParams.Take))
        {
            var userDto = CreateUserDto(applicationUser);
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

    // GET system/v1/identities/{userName}
    /// <summary>
    ///     Returns user information based on it's userName, email or id
    /// </summary>
    /// <param name="userName">Name of the user</param>
    /// <returns>An Object that describes the user.</returns>
    [HttpGet("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IActionResult> Get([Required] string userName)
    {
        var octoUser = await _userManager.FindByNameAsync(userName) ??
                       await _userManager.FindByEmailAsync(userName) ??
                       await _userManager.FindByIdAsync(userName);
        if (octoUser == null)
        {
            return NotFound();
        }

        return Ok(CreateUserDto(octoUser));
    }


    // POST system/v1/identities
    /// <summary>
    ///     Creates a new user
    /// </summary>
    /// <param name="userDto">The user data transfer object instance</param>
    /// <returns></returns>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Post([Required] [FromBody] RegisterUserDto userDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var applicationUser = new RtUser();

        try
        {
            await ApplyRegisterUserToUser(applicationUser, userDto);
        }
        catch (RoleNotFoundException e)
        {
            return BadRequest(new OperationFailedError(e.Message));
        }

        try
        {
            var result = await _userManager.CreateAsync(applicationUser);

            if (!result.Succeeded)
            {
                LogIdentityError("Create user", result.Errors);

                return GetBadRequestResultWithErrorDescription("Creation of user failed", result.Errors);
            }

            if (!string.IsNullOrWhiteSpace(userDto.Password))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(applicationUser);
                result = await _userManager.ResetPasswordAsync(applicationUser, token, userDto.Password);

                if (!result.Succeeded)
                {
                    LogIdentityError("Reset Password", result.Errors);
                    return GetBadRequestResultWithErrorDescription("Creation of user failed", result.Errors);
                }

                await _userEmailInteractionService.SendWelcomeNotificationAsync(applicationUser);
            }
            else
            {
                await _userEmailInteractionService.SendWelcomeNotificationWithoutPasswordAsync(applicationUser);
            }

            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // PUT system/v1/identities/5
    /// <summary>
    ///     Updates an user
    /// </summary>
    /// <param name="userName">The user name</param>
    /// <param name="userDto">The client data transfer object instance</param>
    /// <returns></returns>
    [HttpPut("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Put([Required] string userName, [Required] [FromBody] UserDto userDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var applicationUser = await _userManager.FindByNameAsync(userName);
        if (applicationUser == null)
        {
            return NotFound(new NotFoundError($"User name '{userName}' not found."));
        }

        try
        {
            ApplyUserToUserDto(applicationUser, userDto);
        }
        catch (RoleNotFoundException e)
        {
            return BadRequest(new OperationFailedError(e.Message));
        }

        try
        {
            var result = await _userManager.UpdateAsync(applicationUser);
            if (result.Succeeded)
            {
                return Ok();
            }

            return GetBadRequestResultWithErrorDescription("Update of user failed", result.Errors);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // POST: system/v1/identities/resetPassword
    /// <summary>
    ///     Resets the password of an user
    /// </summary>
    /// <param name="userName">The user name</param>
    /// <param name="password">The new password</param>
    /// <returns></returns>
    [HttpPost]
    [Route("ResetPassword")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> ResetPassword([Required] string userName, [Required] string password)
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
                return NotFound(new NotFoundError($"User '{userName}' not found."));
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var result = await _userManager.ResetPasswordAsync(user, token, password);
            if (result.Succeeded)
            {
                await _userEmailInteractionService.SendPasswordResetNotificationAsync(user);
                return Ok();
            }

            return GetBadRequestResultWithErrorDescription("Reset of password failed.", result.Errors);
        }
        catch (InvalidOperationException e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // DELETE system/v1/identities/5
    /// <summary>
    ///     Deletes an user
    /// </summary>
    /// <param name="userName">The user name</param>
    /// <returns></returns>
    [HttpDelete("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Delete([Required] string userName)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var applicationUser = await _userManager.FindByNameAsync(userName);
        if (applicationUser == null)
        {
            return NotFound(new NotFoundError($"User name '{userName}' not found."));
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
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // PUT system/v1/identities/demo/roles/users
    /// <summary>
    ///     adds a role from an user
    /// </summary>
    /// <param name="userName">The user name</param>
    /// <param name="roleName">the role name</param>
    /// <returns></returns>
    [HttpPut("{userName}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> AddUserToRole([Required] string userName, [Required] string roleName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundError($"User with name '{userName}' not found."));
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound(new NotFoundError($"Role with name '{roleName}' not found."));
        }

        if (user.RoleIds?.Contains(role.RtId.ToString()) ?? false)
        {
            return BadRequest(new OperationFailedError($"User '{user.UserName}' already has role '{role.Name}'"));
        }

        user.RoleIds ??= new AttributeStringValueList();
        user.RoleIds.Add(role.RtId.ToString());
        await _userManager.UpdateAsync(user);
        return Ok();
    }

    // DELETE system/v1/identities/demo/roles/Users
    /// <summary>
    ///     removes a role from an user
    /// </summary>
    /// <param name="userName">The user id</param>
    /// <param name="roleName">the role id</param>
    /// <returns></returns>
    [HttpDelete("{userName}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> RemoveRoleFromUser([Required] string userName, [Required] string roleName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundError($"User with name '{userName}' not found."));
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound(new NotFoundError($"Role with name '{roleName}' not found."));
        }

        if (!user.RoleIds?.Contains(role.RtId.ToString()) ?? false)
        {
            return BadRequest(new OperationFailedError($"User '{user.UserName}' doesn't have role '{role.Name}'"));
        }

        user.RoleIds?.Remove(role.RtId.ToString());
        await _userManager.UpdateAsync(user);
        return Ok();
    }

    private UserDto CreateUserDto(RtUser applicationUser)
    {
        var userDto = new UserDto
        {
            UserId = applicationUser.RtId.ToString(),
            FirstName = applicationUser.FirstName,
            LastName = applicationUser.LastName,
            Email = applicationUser.Email ??
                    applicationUser.Claims?.FirstOrDefault(x => x.ClaimType == JwtClaimTypes.Email)?.ClaimValue,
            Name = applicationUser.UserName ??
                   applicationUser.Claims?.FirstOrDefault(x => x.ClaimType == JwtClaimTypes.Name)?.ClaimValue
        };

        return userDto;
    }
    
    private async Task ApplyRegisterUserToUser(RtUser octoUser, RegisterUserDto userDto)
    {
        var roleIds = new List<string>();

        if (userDto.Roles != null)
        {
            foreach (var roleDto in userDto.Roles)
            {
                if (roleDto.Id == null)
                {
                    continue;
                }

                var role = await _roleManager.FindByIdAsync(roleDto.Id);
                if (role == null)
                {
                    throw new RoleNotFoundException($"Role '{roleDto.Name}' does not exist.");
                }

                roleIds.Add(role.RtId.ToString());
            }
        }

        ApplyUserToUserDto(octoUser, userDto);

        octoUser.RoleIds ??= new AttributeStringValueList();
        octoUser.RoleIds?.Clear();
        octoUser.RoleIds?.AddRange(roleIds);
    }

    private void ApplyUserToUserDto(RtUser octoUser, UserDto userDto)
    {
        if (!string.IsNullOrWhiteSpace(userDto.Name))
        {
            octoUser.UserName = userDto.Name;
        }

        octoUser.Email = userDto.Email;
        octoUser.FirstName = userDto.FirstName;
        octoUser.LastName = userDto.LastName;
        octoUser.ResetPasswordOnLogin = userDto.ResetPasswordOnLogin;
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
        return BadRequest(new OperationFailedError(operation,
            errors.Select(x => new FailedDetails { Code = x.Code, Description = x.Description })));
    }
}