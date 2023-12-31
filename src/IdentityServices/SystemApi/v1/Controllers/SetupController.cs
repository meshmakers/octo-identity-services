using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class SetupController : ControllerBase
{
    private readonly ICredentialGenerator _credentialGenerator;
    private readonly ILogger<SetupController> _logger;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly UserManager<RtUser> _userManager;

    public SetupController(UserManager<RtUser> userManager, RoleManager<RtRole> roleManager,
        ILogger<SetupController> logger,
        ICredentialGenerator credentialGenerator)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _logger = logger;
        _credentialGenerator = credentialGenerator;
    }

    /// <summary>
    ///     Configures identity services in the case no user is existing.
    /// </summary>
    /// <param name="adminUserDto">The client to be added. A client with the same client id must not exist.</param>
    /// <response code="200">Returns the created client.</response>
    /// <response code="400">
    ///     The client could not be created due to either invalid input or failure to replace
    ///     the client when another client with the same clientId already exists.
    /// </response>
    /// <response code="404">Not Found. The setting of the admin user is allowed only during installation.</response>
    [HttpPost]
    public async Task<IActionResult> AddAdminUser([FromBody] AdminUserDto adminUserDto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        if (_userManager.Users.Any()) return NotFound("The request is not valid for this configuration.");
        if (string.IsNullOrWhiteSpace(adminUserDto.EMail))
        {
            _logger.LogInformation("E-Mail value is missing");
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }

        if (string.IsNullOrWhiteSpace(adminUserDto.Password))
        {
            _logger.LogInformation("Password value is missing");
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }

        if (!_credentialGenerator.CheckPassword(adminUserDto.Password))
        {
            _logger.LogInformation("The password does not comply with the minimum requirements");
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }

        var adminRole = await _roleManager.FindByNameAsync(CommonConstants.AdministratorsRole);
        if (adminRole == null)
        {
            _logger.LogInformation("No Administrator-Role has been found");
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }

        var developerRole = await _roleManager.FindByNameAsync(CommonConstants.DevelopersRole);
        if (developerRole == null)
        {
            _logger.LogInformation("No Developer-Role has been found");
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }

        var managersRole = await _roleManager.FindByNameAsync(CommonConstants.ManagersRole);
        if (managersRole == null)
        {
            _logger.LogInformation("No Managers-Role has been found");
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }

        var usersRole = await _roleManager.FindByNameAsync(CommonConstants.UsersRole);
        if (usersRole == null)
        {
            _logger.LogInformation("No Users-Role has been found");
            return StatusCode(StatusCodes.Status406NotAcceptable);
        }

        var adminUser = await _userManager.FindByNameAsync(adminUserDto.EMail);
        if (adminUser == null)
        {
            adminUser = new RtUser { UserName = adminUserDto.EMail, Email = adminUserDto.EMail };

            await _userManager.CreateAsync(adminUser, adminUserDto.Password);
            await _userManager.AddToRoleAsync(adminUser, adminRole.RtId.ToString());
            await _userManager.AddToRoleAsync(adminUser, developerRole.RtId.ToString());
            await _userManager.AddToRoleAsync(adminUser, managersRole.RtId.ToString());
            await _userManager.AddToRoleAsync(adminUser, usersRole.RtId.ToString());
        }

        return Ok();
    }
}