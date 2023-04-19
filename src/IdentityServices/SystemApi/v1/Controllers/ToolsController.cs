using System.Threading.Tasks;
using IdentityModel;
using Meshmakers.Octo.Common.Shared;
using Meshmakers.Octo.Common.Shared.DataTransferObjects;
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
    /// <summary>
    ///     Generates a new password
    /// </summary>
    /// <returns></returns>
    [HttpGet("generatePassword")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public Task<GeneratedPasswordDto> Get()
    {
        return Task.FromResult(new GeneratedPasswordDto { Value = PasswordGenerator.GetRandomAlphanumericString(16) });
    }
}
