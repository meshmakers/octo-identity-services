using Asp.Versioning;
using IdentityServerPersistence;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Meshmakers.Octo.Backend.Authentication;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ToolsController
{
    // GET: system/v1/tools/generatePassword
    [HttpGet("generatePassword")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Generates a new password")]
    [ProducesResponseType(typeof(GeneratedPasswordDto), StatusCodes.Status200OK)]
    public Task<GeneratedPasswordDto> Get()
    {
        return Task.FromResult(new GeneratedPasswordDto { Value = PasswordGenerator.GetRandomAlphanumericString(16) });
    }
}