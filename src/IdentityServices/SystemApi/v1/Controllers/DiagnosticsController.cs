using System.ComponentModel;
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
    
    [HttpGet]
    [EndpointSummary("Returns a diagnostics information of the current authenticated user")]
    [ProducesResponseType(typeof(DiagnosticsDto), StatusCodes.Status200OK)]
    public IActionResult Get()
    {
        var model = new DiagnosticsDto(HttpContext.User);
        return Ok(model);
    }
    
    [HttpPost("reconfigureLogLevel")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Reconfigures the log level of the service")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> ReconfigureLogLevelAsync(
        [Required] [Description("The minimal log level to be logged.")] LogLevelDto minLogLevel,
        [Required] [Description("The maximal log level to be logged.")] LogLevelDto maxLogLevel,
        [Description("The name of the logger to be reconfigured.")] string loggerName = "*")
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