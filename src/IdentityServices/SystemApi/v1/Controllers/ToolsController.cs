using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
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