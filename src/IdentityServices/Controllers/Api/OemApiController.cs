using Meshmakers.Octo.Backend.IdentityServices.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for OEM configuration
/// </summary>
[ApiController]
[Route("{tenantId}/api/oem")]
[AllowAnonymous]
public class OemApiController : ControllerBase
{
    private readonly IOemService _oemService;

    public OemApiController(IOemService oemService)
    {
        _oemService = oemService;
    }

    /// <summary>
    /// Get OEM configuration for the Angular SPA
    /// </summary>
    [HttpGet("config")]
    [ResponseCache(Duration = 300)] // Cache for 5 minutes
    public ActionResult<OemConfigDto> GetOemConfig()
    {
        // Use defaults for now - can be extended with tenant-specific configuration
        return new OemConfigDto
        {
            AppName = "OctoMesh Identity",
            LogoUrl = null,
            FaviconUrl = _oemService.Favicon,
            PrimaryColor = null,
            AccentColor = null,
            HideNavigation = false
        };
    }
}

#region DTOs

public record OemConfigDto
{
    public string AppName { get; init; } = "OctoMesh Identity";
    public string? LogoUrl { get; init; }
    public string? FaviconUrl { get; init; }
    public string? PrimaryColor { get; init; }
    public string? AccentColor { get; init; }
    public bool HideNavigation { get; init; }
}

#endregion
