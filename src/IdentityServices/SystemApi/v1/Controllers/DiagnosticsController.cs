using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Infrastructure.Services;
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
    private readonly ILogger<DiagnosticsController> _logger;
    private readonly IDiagnosticsService _diagnosticsService;

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="logger"></param>
    /// <param name="diagnosticsService"></param>
    public DiagnosticsController(ILogger<DiagnosticsController> logger, IDiagnosticsService diagnosticsService)
    {
        _logger = logger;
        _diagnosticsService = diagnosticsService;
    }
    
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
    
    /// <summary>
    /// Reconfigures the log level of the service
    /// </summary>
    /// <param name="minLogLevel">The minimal log level to be logged.</param>
    /// <param name="maxLogLevel">The maximal log level to be logged.</param>
    /// <param name="loggerName">The name of the logger to be reconfigured.</param>
    /// <returns></returns>
    [HttpPost("reconfigureLogLevel")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> ReconfigureLogLevelAsync([Required] LogLevelDto minLogLevel,
        [Required] LogLevelDto maxLogLevel, string loggerName = "*")
    {
        try
        {
            _logger.LogInformation("Reconfiguring logger {LoggerName} log level to min level {MinLogLevel}, max level {MaxLoglevel}", loggerName, minLogLevel, maxLogLevel);
            await _diagnosticsService.ReconfigureLogLevelAsync(minLogLevel, maxLogLevel, loggerName);
            return NoContent();
        }
        catch (Exception e)
        {
            return BadRequest(e.Message);
        }
    }
}