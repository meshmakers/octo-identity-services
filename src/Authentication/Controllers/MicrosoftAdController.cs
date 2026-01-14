using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Meshmakers.Octo.Backend.Authentication.ViewModels;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.Controllers;

[Route(AuthenticationConstants.ControllerRouteTemplate)]
public class MicrosoftAdController : Controller
{
    private readonly IEventService _events;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly SignInManager<RtUser> _signInManager;

    public MicrosoftAdController(SignInManager<RtUser> signInManager,
        IIdentityServerInteractionService interaction,
        IEventService events
    )
    {
        _signInManager = signInManager;
        _interaction = interaction;
        _events = events;
    }

    public static string RouteName => nameof(MicrosoftAdController).Replace("Controller", "");

    [HttpGet]
    public IActionResult Index([FromQuery] MicrosoftAdIndexModel login)
    {
        if (ModelState.IsValid)
        {
            var loginViewModel = new MicrosoftAdLoginViewModel
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
    public async Task<IActionResult> Login(MicrosoftAdLoginViewModel login, string button)
    {
        var context = await _interaction.GetAuthorizationContextAsync(login.ReturnUrl);

        // the user clicked the "cancel" button
        if (button != "login")
        {
            if (context != null)
            {
                // if the user cancels, send a result back into IdentityServer as if they 
                // denied the consent (even if this client does not require consent).
                // this will send back an access denied OIDC error response to the client.
                await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (context.IsNativeClient())
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                {
                    return this.LoadingPage("Redirect", login.ReturnUrl);
                }

                return Redirect(login.ReturnUrl ?? "~/");
            }

            // since we don't have a valid context, then we just go back to the home page
            return Redirect("~/");
        }

        if (ModelState.IsValid)
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(login.LoginProvider);

            if (authenticateResult.Succeeded)
            {
                var props = _signInManager.ConfigureExternalAuthenticationProperties(login.LoginProvider, login.ReturnUrl, login.XsrfId);
                await HttpContext.SignInAsync(IdentityConstants.ExternalScheme, authenticateResult.Principal, props);
                return Redirect(login.ReturnUrl ?? "~/");
            }

            await _events.RaiseAsync(new UserLoginFailureEvent(login.Email, "invalid credentials",
                clientId: context?.Client.ClientId));
            ModelState.AddModelError(string.Empty, IdentityTexts.Backend_Identity_Login_InvalidUserPassword);
        }

        return View("Index", login);
    }
}