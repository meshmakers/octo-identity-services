using IdentityModel;
using Meshmakers.Octo.Common.Shared.DataTransferObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

/// <summary>
///     REST Controller for diagnostics information
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class DiagnosticsController : ControllerBase
{
    /// <summary>
    ///     Returns a diagnostics information of the current authenticated user
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    public IActionResult Get()
    {
        var model = new DiagnosticsDto(HttpContext.User);
        return Ok(model);
    }
}
