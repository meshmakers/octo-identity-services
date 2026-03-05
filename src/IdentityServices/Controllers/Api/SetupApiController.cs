using System.ComponentModel.DataAnnotations;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for initial system setup from the Angular SPA.
/// All endpoints return 404 when users already exist, making the controller
/// effectively invisible after setup is complete.
/// </summary>
[ApiController]
[Route("{tenantId}/api/setup")]
[AllowAnonymous]
public class SetupApiController(
    UserManager<RtUser> userManager,
    IUserManagementService userManagementService,
    ILogger<SetupApiController> logger)
    : ControllerBase
{
    /// <summary>
    /// Returns setup status. Returns 404 if users already exist.
    /// </summary>
    [HttpGet("status")]
    [ProducesResponseType(typeof(SetupStatusDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult GetStatus()
    {
        if (userManager.Users.Any())
        {
            return NotFound();
        }

        return Ok(new SetupStatusDto { SetupRequired = true });
    }

    /// <summary>
    /// Creates the initial admin user. Returns 404 if users already exist.
    /// </summary>
    [HttpPost("create-admin")]
    [ProducesResponseType(typeof(SetupResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> CreateAdmin([FromBody] SetupAdminRequestDto request)
    {
        if (userManager.Users.Any())
        {
            return NotFound();
        }

        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        if (request.Password != request.ConfirmPassword)
        {
            return Ok(new SetupResultDto
            {
                Success = false,
                ErrorMessage = "Passwords do not match"
            });
        }

        try
        {
            var adminUserDto = new AdminUserDto
            {
                EMail = request.Email,
                Password = request.Password
            };

            await userManagementService.CreateAdminUserAsync(adminUserDto);
            return Ok(new SetupResultDto { Success = true });
        }
        catch (UsersAlreadyConfiguredException)
        {
            return NotFound();
        }
        catch (UserManagementException e)
        {
            logger.LogError(e, "{Message}", e.Message);
            return Ok(new SetupResultDto { Success = false, ErrorMessage = e.Message });
        }
    }
}

#region DTOs

public record SetupStatusDto
{
    public bool SetupRequired { get; init; }
}

public record SetupAdminRequestDto
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;

    [Required]
    public string Password { get; init; } = string.Empty;

    [Required]
    public string ConfirmPassword { get; init; } = string.Empty;
}

public record SetupResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

#endregion
