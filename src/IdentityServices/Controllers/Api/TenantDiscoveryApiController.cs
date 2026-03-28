using System.Threading.RateLimiting;
using IdentityServerPersistence.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for tenant discovery. Allows unauthenticated users to find which tenants
/// they belong to by email or username. This endpoint has no {tenantId} route prefix because
/// the user does not know their tenant yet.
/// </summary>
[ApiController]
[Route("api/tenant-discovery")]
[AllowAnonymous]
[EnableRateLimiting("tenant-discovery")]
public class TenantDiscoveryApiController(
    ITenantDiscoveryService discoveryService,
    ILogger<TenantDiscoveryApiController> logger) : ControllerBase
{
    /// <summary>
    /// Look up which tenants a user belongs to by email address or username.
    /// Returns only the tenants where the user actually exists -- never the full tenant list.
    /// Enforces constant-time response to prevent timing-based enumeration.
    /// </summary>
    [HttpPost("lookup")]
    public async Task<ActionResult<TenantDiscoveryResultDto>> Lookup(
        [FromBody] TenantDiscoveryRequestDto request)
    {
        // Enforce minimum response time to prevent timing attacks
        var minDelay = Task.Delay(TimeSpan.FromMilliseconds(500));

        if (string.IsNullOrWhiteSpace(request.EmailOrUsername))
        {
            await minDelay;
            return Ok(new TenantDiscoveryResultDto
            {
                Found = false,
                Message = "Please enter your email address or username."
            });
        }

        logger.LogDebug("Tenant discovery lookup for identifier '{Identifier}'",
            request.EmailOrUsername);

        var tenants = await discoveryService.FindTenantsForUserAsync(request.EmailOrUsername);

        await minDelay;

        if (tenants.Count == 0)
        {
            return Ok(new TenantDiscoveryResultDto
            {
                Found = false,
                Message = "Unable to determine your organization. Please contact your administrator."
            });
        }

        return Ok(new TenantDiscoveryResultDto
        {
            Found = true,
            Tenants = tenants.Select(t => new DiscoveredTenantDto { TenantId = t }).ToList()
        });
    }
}

public record TenantDiscoveryRequestDto
{
    public string EmailOrUsername { get; init; } = string.Empty;
}

public record TenantDiscoveryResultDto
{
    public bool Found { get; init; }
    public List<DiscoveredTenantDto> Tenants { get; init; } = [];
    public string? Message { get; init; }
}

public record DiscoveredTenantDto
{
    public string TenantId { get; init; } = string.Empty;
}
