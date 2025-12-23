using System.Diagnostics;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Setup;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Home;

[SecurityHeaders]
public class SetupController : Controller
{
    private readonly ICredentialGenerator _credentialGenerator;
    private readonly IUserManagementService _userManagementService;
    private readonly ILogger<SetupController> _logger;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly UserManager<RtUser> _userManager;

    public SetupController(ILogger<SetupController> logger, UserManager<RtUser> userManager,
        RoleManager<RtRole> roleManager, ICredentialGenerator credentialGenerator, IUserManagementService userManagementService)
    {
        _logger = logger;
        _userManager = userManager;
        _roleManager = roleManager;
        _credentialGenerator = credentialGenerator;
        _userManagementService = userManagementService;
    }

    public IActionResult Index()
    {
        if (_userManager.Users.Any())
        {
            return RedirectToAction("Index", "Home");
        }

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Index(SetupViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (_userManager.Users.Any())
        {
            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_Identity_Setup_Status_UsersAlreadyConfigured);
            return View(model);
        }

        if (string.IsNullOrWhiteSpace(model.EMailAddress))
        {
            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_Identity_Setup_Status_EMailMissing);
            return View(model);
        }

        if (string.IsNullOrWhiteSpace(model.NewPassword))
        {
            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_Identity_Setup_Status_PasswordMissing);
            return View(model);
        }
        
        if (!_credentialGenerator.CheckPassword(model.NewPassword))
        {
            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_Identity_Setup_Status_PasswordComplexity);
            return View(model);
        }

        try
        {
            await _userManagementService.CreateAdminUserAsync(new AdminUserDto
            {
                EMail = model.EMailAddress,
                Password = model.NewPassword
            });
            return RedirectToAction("Index", "Home");
        }
        catch (UsersAlreadyConfiguredException)
        {
            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_Identity_Setup_Status_UsersAlreadyConfigured);
            return View(model);
        }
        catch (UserManagementException)
        {
            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_Persistence_Identity_CommonError);
            return View(model);
        }
    }
}