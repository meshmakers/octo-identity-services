using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using IdentityServerPersistence;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Home;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Shared;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

#pragma warning disable 1591

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Home;

[SecurityHeaders]
public class HomeController : Controller
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly UserManager<RtUser> _userManager;

    public HomeController(IIdentityServerInteractionService interaction, UserManager<RtUser> userManager)
    {
        _interaction = interaction;
        _userManager = userManager;
    }

    public async Task<IActionResult> Index()
    {
        if (!_userManager.Users.Any())
        {
            return RedirectToAction("Index", "Setup");
        }

        if (!User.IsAuthenticated())
        {
            return Redirect("~/Account/Login");
        }

        var user = await GetCurrentUserAsync();
        if (user == null)
            // Same cookie - but ids to not match - new database?
        {
            return Redirect("~/Account/Login");
        }

        var vm = new HomeViewModel
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            EMail = user.Email,
            UserName = user.UserName,
            AccessFailedCount = user.AccessFailedCount,
            Id = user.RtId.ToString()
        };

        return View(vm);
    }

    /// <summary>
    ///     Shows the error page
    /// </summary>
    public async Task<IActionResult> Error(string errorId)
    {
        var exceptionHandlerPathFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();

        if (exceptionHandlerPathFeature?.Path.StartsWith($"/{IdentityServiceConstants.ApiPathPrefix}") ?? false)
        {
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }

        var vm = new ErrorViewModel();

        // retrieve error details from identity server
        var message = await _interaction.GetErrorContextAsync(errorId);
        if (message != null)
        {
            vm.Error = message;
        }

        return View("Error", vm);
    }

    private Task<RtUser?> GetCurrentUserAsync()
    {
        return _userManager.GetUserAsync(HttpContext.User);
    }
}