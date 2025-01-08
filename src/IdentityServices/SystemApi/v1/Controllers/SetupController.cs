using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class SetupController(ILogger<SetupController> logger, IUserManagementService userManagementService)
    : ControllerBase
{
    /// <summary>
    ///     Configures identity services in the case no user is existing.
    /// </summary>
    /// <param name="adminUserDto">The client to be added. A client with the same client id must not exist.</param>
    /// <response code="200">Returns the created client.</response>
    /// <response code="400">
    ///     The client could not be created due to either invalid input or failure to replace
    ///     the client when another client with the same clientId already exists.
    /// </response>
    /// <response code="404">Not Found. The setting of the admin user is allowed only during installation.</response>
    [HttpPost]
    public async Task<IActionResult> AddAdminUser([FromBody] AdminUserDto adminUserDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        try
        {
            await userManagementService.CreateAdminUserAsync(adminUserDto);
            return Ok();
        }
        catch (UsersAlreadyConfiguredException)
        {
            return NotFound(IdentityTexts.Backend_Identity_Setup_Status_UsersAlreadyConfigured);
        }
        catch (UserManagementException e)
        {
            logger.LogError(e, "{Message}", e.Message);
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }
    }
}