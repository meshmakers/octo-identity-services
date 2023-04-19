using System.Threading.Tasks;
using Meshmakers.Octo.Backend.Authentication.ViewModels;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.Authentication.Controllers;

[Route(AuthenticationConstants.ControllerRouteTemplate)]
public class MicrosoftAdController : Controller
{
    private readonly SignInManager<OctoUser> _signInManager;

    public MicrosoftAdController(SignInManager<OctoUser> signInManager)
    {
        _signInManager = signInManager;
    }

    [HttpGet]
    public IActionResult Index([FromQuery] MicrosoftAdIndexModel login)
    {
        if (ModelState.IsValid)
        {
            var loginViewModel = new MicrosoftAdLoginViewModel()
            {
                ReturnUrl = login.RedirectUri,
                LoginProvider = login.LoginProvider,
                XsrfId = login.XsrfId
            };
            return View(loginViewModel);
        }
        return Unauthorized(ModelState);
    }

    [HttpPost]
    public async Task<IActionResult> Login(MicrosoftAdLoginViewModel login)
    {
        if (ModelState.IsValid)
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(login.LoginProvider);

            if (authenticateResult.Succeeded)
            {
                var props = _signInManager.ConfigureExternalAuthenticationProperties(login.LoginProvider, login.ReturnUrl, login.XsrfId);
                await HttpContext.SignInAsync(IdentityConstants.ExternalScheme, authenticateResult.Principal, props);
                return Redirect(login.ReturnUrl);
            }
            return Unauthorized();
        }

        return View("Index", login);
    }

    public static string RouteName => nameof(MicrosoftAdController).Replace("Controller", "");
}