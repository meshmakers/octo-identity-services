using System.ComponentModel.DataAnnotations;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for initial system setup from the Angular SPA.
/// Setup is only allowed on the system tenant. Child tenants must be provisioned
/// via cross-tenant authentication instead.
/// All endpoints return 404 when users already exist, making the controller
/// effectively invisible after setup is complete.
/// </summary>
[ApiController]
[Route("{tenantId}/api/setup")]
[AllowAnonymous]
public class SetupApiController(
    UserManager<RtUser> userManager,
    IExternalTenantUserMappingStore externalTenantUserMappingStore,
    IUserManagementService userManagementService,
    IOptions<OctoSystemConfiguration> systemConfiguration,
    ILogger<SetupApiController> logger)
    : ControllerBase
{
    private bool IsSystemTenant()
    {
        var tenantId = HttpContext.GetRouteValue("tenantId") as string;
        return string.Equals(tenantId, systemConfiguration.Value.SystemTenantId,
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns setup status. Returns 404 if not the system tenant or if users already exist.
    /// </summary>
    [HttpGet("status")]
    [ProducesResponseType(typeof(SetupStatusDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetStatus()
    {
        if (!IsSystemTenant())
        {
            return NotFound();
        }

        if (userManager.Users.Any())
        {
            return NotFound();
        }

        // Cross-tenant provisioning creates ExternalTenantUserMappings without local users.
        // If mappings exist, the tenant is ready for cross-tenant login — no setup needed.
        var mappings = await externalTenantUserMappingStore.GetAllAsync(take: 1);
        if (mappings.Any())
        {
            return NotFound();
        }

        return Ok(new SetupStatusDto { SetupRequired = true });
    }

    /// <summary>
    /// Creates the initial admin user. Returns 404 if not the system tenant or if users already exist.
    /// </summary>
    [HttpPost("create-admin")]
    [ProducesResponseType(typeof(SetupResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> CreateAdmin([FromBody] SetupAdminRequestDto request)
    {
        if (!IsSystemTenant())
        {
            return NotFound();
        }

        if (userManager.Users.Any())
        {
            return NotFound();
        }

        var mappings = await externalTenantUserMappingStore.GetAllAsync(take: 1);
        if (mappings.Any())
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
