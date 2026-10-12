using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.FileRoles;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     AB#6542: read-only proof report which pipeline service accounts of the tenant hold FileManagement.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class PipelineServiceAccountFileRolesController(
    IMultiTenancyResolverService multiTenancyResolverService,
    ICkCacheService ckCacheService) : ControllerBase
{
    // GET system/v1/pipelineServiceAccountFileRoles
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Reports which pipeline service accounts (octo-pipeline-sa-*) hold the FileManagement role. Read-only.")]
    [ProducesResponseType(typeof(PipelineServiceAccountFileRoleReportResult), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get()
    {
        try
        {
            var report = await PipelineServiceAccountFileRoleReport.ReadAsync(
                multiTenancyResolverService.GetTenantRepository(), multiTenancyResolverService.GetTenantId(),
                ckCacheService);
            return Ok(report);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }
}
