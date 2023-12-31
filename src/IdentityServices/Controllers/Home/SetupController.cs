using System.Diagnostics;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Setup;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Home;

[SecurityHeaders]
public class SetupController : Controller
{
    private readonly ICredentialGenerator _credentialGenerator;
    private readonly ILogger<SetupController> _logger;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly UserManager<RtUser> _userManager;

    public SetupController(ILogger<SetupController> logger, UserManager<RtUser> userManager,
        RoleManager<RtRole> roleManager, ICredentialGenerator credentialGenerator)
    {
        _logger = logger;
        _userManager = userManager;
        _roleManager = roleManager;
        _credentialGenerator = credentialGenerator;
    }

    public IActionResult Index()
    {
        if (_userManager.Users.Any()) return RedirectToAction("Index", "Home");

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Index(SetupViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

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
        var adminRole = await _roleManager.FindByNameAsync(CommonConstants.AdministratorsRole);
        if (adminRole == null)
        {
            _logger.LogInformation("No Administrator-Role has been found");

            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_General_Error_Label);
            return View(model);
        }

        var adminUser = await _userManager.FindByNameAsync(model.EMailAddress);
        if (adminUser == null)
        {
            adminUser = new RtUser { UserName = model.EMailAddress, Email = model.EMailAddress };

            await _userManager.CreateAsync(adminUser, model.NewPassword);
            Debug.Assert(adminRole.NormalizedName != null, "adminRole.NormalizedName != null");
            await _userManager.AddToRoleAsync(adminUser, adminRole.NormalizedName);
        }

        return RedirectToAction("Index", "Home");
    }
}