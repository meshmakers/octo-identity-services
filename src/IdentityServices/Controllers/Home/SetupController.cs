using System.Linq;
using System.Threading.Tasks;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Setup;
using Meshmakers.Octo.Backend.Infrastructure.CredentialGenerator;
using Meshmakers.Octo.Common.Shared;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Home;

[SecurityHeaders]
public class SetupController : Controller
{
    private readonly ICredentialGenerator _credentialGenerator;
    private readonly ILogger<SetupController> _logger;
    private readonly RoleManager<OctoRole> _roleManager;
    private readonly UserManager<OctoUser> _userManager;

    public SetupController(ILogger<SetupController> logger, UserManager<OctoUser> userManager,
        RoleManager<OctoRole> roleManager, ICredentialGenerator credentialGenerator)
    {
        _logger = logger;
        _userManager = userManager;
        _roleManager = roleManager;
        _credentialGenerator = credentialGenerator;
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
            adminUser = new OctoUser { UserName = model.EMailAddress, Email = model.EMailAddress };

            await _userManager.CreateAsync(adminUser, model.NewPassword);
            await _userManager.AddToRoleAsync(adminUser, adminRole.NormalizedName);
        }

        return RedirectToAction("Index", "Home");
    }
}
