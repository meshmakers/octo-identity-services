using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Manage;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Shared;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Manage;

[Authorize]
public class ManageController : Controller
{
    private readonly IUserEmailInteractionService _emailInteractionService;
    private readonly IOptions<OctoSystemConfiguration> _options;
    private readonly ILogger _logger;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly UserManager<RtUser> _userManager;

    public ManageController(
        UserManager<RtUser> userManager,
        SignInManager<RtUser> signInManager,
        IUserEmailInteractionService emailInteractionService,
        IOptions<OctoSystemConfiguration> options,
        ILoggerFactory loggerFactory)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailInteractionService = emailInteractionService;
        _options = options;
        _logger = loggerFactory.CreateLogger<ManageController>();
    }

    //
    // GET: /Manage/Index
    [HttpGet]
    public async Task<IActionResult> Index(ManageMessageId? message = null)
    {
        ViewData["StatusMessage"] =
            message == ManageMessageId.ChangePasswordSuccess
                ? IdentityTexts.Backend_Identity_Manage_StatusMessage_ChangePasswordSuccess
                : message == ManageMessageId.SetPasswordSuccess
                    ? IdentityTexts.Backend_Identity_Manage_StatusMessage_SetPasswordSuccess
                    : message == ManageMessageId.Error
                        ? IdentityTexts.Backend_Identity_Manage_StatusMessage_Error
                        : "";

        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return View("Error");
        }

        var model = new IndexViewModel
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            EMail = user.Email,
            UserName = user.UserName,
            AccessFailedCount = user.AccessFailedCount,
            Id = user.RtId.ToString(),
            HasPassword = await _userManager.HasPasswordAsync(user),
            Logins = await _userManager.GetLoginsAsync(user),
            BrowserRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user)
        };
        return View(model);
    }

    //
    // POST: /Manage/RemoveLogin
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveLogin(RemoveLoginViewModel account)
    {
        ManageMessageId? message = ManageMessageId.Error;
        var user = await GetCurrentUserAsync();
        if (user != null && account.LoginProvider != null
                         && account.ProviderKey != null)
        {
            var result = await _userManager.RemoveLoginAsync(user, account.LoginProvider, account.ProviderKey);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                message = ManageMessageId.RemoveLoginSuccess;
            }
        }

        return RedirectToAction(nameof(ManageLogins), new { Message = message });
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string id)
    {
        if (!ModelState.IsValid)
        {
            return View("Error", new ErrorViewModel("Token is missing."));
        }

        var vm = new ResetPasswordViewModel
        {
            Token = id
        };
        return View(vm);
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword([FromForm] ResetPasswordViewModel vm)
    {
        if (!ModelState.IsValid)
        {
            return View(vm);
        }

        try
        {
            var redirectUrl =
                await _emailInteractionService.ValidateAndResetPasswordAsync(_options.Value.SystemTenantId, vm.Token!,
                    vm.NewPassword!);
            var successViewModel = new SuccessViewModel
            {
                Operation = IdentityTexts.Backend_Identity_Manage_StatusMessage_ChangePasswordSuccess,
                Text = IdentityTexts.Backend_Identity_Msg_You_Can_Login_With_New_Password,
                NextStepLink = redirectUrl
            };
            return View("Success", successViewModel);
        }
        catch (PasswordComplexityTooLowException e)
        {
            foreach (var error in e.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
        catch (Exception e)
        {
            ModelState.AddModelError(string.Empty, e.Message);
        }

        var resetPasswordViewModel = new ResetPasswordViewModel
        {
            Token = vm.Token
        };
        return View(resetPasswordViewModel);
    }
    
    //
    // GET: /Manage/ChangePassword
    [HttpGet]
    public IActionResult ChangePassword()
    {
        var vm = new ChangePasswordViewModel();
        return View(vm);
    }

    //
    // POST: /Manage/ChangePassword
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await GetCurrentUserAsync();
        if (user != null)
        {
            var result = await _userManager.ChangePasswordAsync(user, model.OldPassword!, model.NewPassword!);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                _logger.LogInformation(3, "User changed their password successfully");
                return RedirectToAction(nameof(Index), new { Message = ManageMessageId.ChangePasswordSuccess });
            }

            AddErrors(result);
            return View(model);
        }

        return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    //
    // GET: /Manage/SetPassword
    [HttpGet]
    public IActionResult SetPassword()
    {
        return View();
    }

    //
    // POST: /Manage/SetPassword
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await GetCurrentUserAsync();
        if (user != null)
        {
            var result = await _userManager.AddPasswordAsync(user, model.NewPassword!);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                return RedirectToAction(nameof(Index), new { Message = ManageMessageId.SetPasswordSuccess });
            }

            AddErrors(result);
            return View(model);
        }

        return RedirectToAction(nameof(Index), new { Message = ManageMessageId.Error });
    }

    //GET: /Manage/ManageLogins
    [HttpGet]
    public async Task<IActionResult> ManageLogins(ManageMessageId? message = null)
    {
        ViewData["StatusMessage"] =
            message == ManageMessageId.RemoveLoginSuccess
                ? IdentityTexts.Backend_Identity_Manage_StatusMessage_RemoveLoginSuccess
                : message == ManageMessageId.AddLoginSuccess
                    ? IdentityTexts.Backend_Identity_Manage_StatusMessage_AddLoginSuccess
                    : message == ManageMessageId.Error
                        ? IdentityTexts.Backend_Identity_Manage_StatusMessage_Error
                        : "";
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return View("Error");
        }

        var userLogins = await _userManager.GetLoginsAsync(user);

        var otherLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync())
            .Where(auth => userLogins.All(ul => auth.Name != ul.LoginProvider)).ToList();
        ViewData["ShowRemoveButton"] = user.PasswordHash != null || userLogins.Count > 1;
        return View(new ManageLoginsViewModel { CurrentLogins = userLogins, OtherLogins = otherLogins });
    }

    //
    // POST: /Manage/LinkLogin
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LinkLogin(string provider)
    {
        // Clear the existing external cookie to ensure a clean login process
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        // Request a redirect to the external login provider to link a login for the current user
        var redirectUrl = Url.Action(nameof(LinkLoginCallback), "Manage");
        var properties =
            _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl,
                _userManager.GetUserId(User));
        return Challenge(properties, provider);
    }

    //
    // GET: /Manage/LinkLoginCallback
    [HttpGet]
    public async Task<ActionResult> LinkLoginCallback()
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return View("Error");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync(await _userManager.GetUserIdAsync(user));
        if (info == null)
        {
            return RedirectToAction(nameof(ManageLogins), new { Message = ManageMessageId.Error });
        }

        var result = await _userManager.AddLoginAsync(user, info);
        var message = ManageMessageId.Error;
        if (result.Succeeded)
        {
            message = ManageMessageId.AddLoginSuccess;
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        }

        return RedirectToAction(nameof(ManageLogins), new { Message = message });
    }

    #region Helpers

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }

    public enum ManageMessageId
    {
        AddLoginSuccess,
        ChangePasswordSuccess,
        SetPasswordSuccess,
        RemoveLoginSuccess,
        Error
    }

    private Task<RtUser?> GetCurrentUserAsync()
    {
        return _userManager.GetUserAsync(HttpContext.User);
    }

    #endregion
}