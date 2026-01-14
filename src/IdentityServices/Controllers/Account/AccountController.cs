using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityModel;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Account;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Shared;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Account;

/// <summary>
///     Implements the login/logout functionality of identity server
/// </summary>
[AllowAnonymous]
public class AccountController : Controller
{
    private readonly IClientStore _clientStore;
    private readonly IUserEmailInteractionService _emailInteractionService;
    private readonly IEventService _events;
    private readonly IOptions<OctoSystemConfiguration> _options;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly UserManager<RtUser> _userManager;


    public AccountController(
        UserManager<RtUser> userManager,
        SignInManager<RtUser> signInManager,
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IAuthenticationSchemeProvider schemeProvider,
        IEventService events,
        IOptions<OctoSystemConfiguration> options,
        IUserEmailInteractionService emailInteractionService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _interaction = interaction;
        _clientStore = clientStore;
        _schemeProvider = schemeProvider;
        _events = events;
        _options = options;
        _emailInteractionService = emailInteractionService;
    }

    /// <summary>
    ///     Entry point into the login workflow
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Login(string? returnUrl)
    {
        // build a model so we know what to show on the login page
        var vm = await BuildLoginViewModelAsync(returnUrl);

        if (vm.IsExternalLoginOnly)
            // we only have one option for logging in and it's an external provider
        {
            return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
        }

        return View(vm);
    }

    /// <summary>
    ///     Handle postback from username/password login
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginInputModel model, string button)
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

        // the user clicked the "cancel" button
        if (button != "login")
        {
            if (context != null)
            {
                // if the user cancels, send a result back into IdentityServer as if they 
                // denied the consent (even if this client does not require consent).
                // this will send back access denied OIDC error response to the client.
                await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (context.IsNativeClient())
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                {
                    return this.LoadingPage("Redirect", model.ReturnUrl);
                }

                return Redirect(model.ReturnUrl ?? "~/");
            }

            // since we don't have a valid context, then we just go back to the home page
            return Redirect("~/");
        }

        if (ModelState.IsValid && model.Username != null && model.Password != null)
        {
            var result =
                await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, true);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(model.Username);
                if (user != null)
                {
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.RtId.ToString(),
                        user.UserName,
                        clientId: context?.Client.ClientId));
                }

                if (context != null)
                {
                    if (context.IsNativeClient())
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                    {
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    return Redirect(model.ReturnUrl ?? "~/");
                }

                // request for a local page
                if (Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }

                if (string.IsNullOrEmpty(model.ReturnUrl))
                {
                    return Redirect("~/");
                }

                // user might have clicked on a malicious link - should be logged
                throw new Exception("invalid return URL");
            }

            await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials",
                clientId: context?.Client.ClientId));
            ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
        }

        // something went wrong, show form with error
        var vm = await BuildLoginViewModelAsync(model);
        return View(vm);
    }


    /// <summary>
    ///     Show logout page
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Logout(string logoutId)
    {
        // build a model so the logout page knows what to display
        var vm = await BuildLogoutViewModelAsync(logoutId);

        if (vm.ShowLogoutPrompt == false)
            // if the request for logout was properly authenticated from IdentityServer, then
            // we don't need to show the prompt and can just log the user out directly.
        {
            return await Logout(vm);
        }

        return View(vm);
    }

    /// <summary>
    ///     Handle logout page postback
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(LogoutInputModel model)
    {
        // build a model so the logged out page knows what to display
        var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

        if (User.Identity?.IsAuthenticated == true)
        {
            // delete local authentication cookie
            await _signInManager.SignOutAsync();

            // raise the logout event
            await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
        }

        // check if we need to trigger sign-out at an upstream identity provider
        if (vm.TriggerExternalSignout && vm.ExternalAuthenticationScheme != null)
        {
            // build a return URL so the upstream provider will redirect back
            // to us after the user has logged out. this allows us to then
            // complete our single sign-out processing.
            var url = Url.Action("Logout", new { logoutId = vm.LogoutId });

            // this triggers a redirect to the external provider for sign-out
            return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
        }

        return View("LoggedOut", vm);
    }

    /// <summary>
    ///     Endpoint to confirm an email address
    /// </summary>
    /// <param name="id">The generated guid to confirm the email address</param>
    /// <returns></returns>
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Confirmation(string id)
    {
        try
        {
            var redirectUri =
                await _emailInteractionService.ValidateEmailNotificationTokenAsync(_options.Value.SystemTenantId, id);
            var successVm = new SuccessViewModel
            {
                Operation = IdentityTexts.Backend_General_Title_Success,
                Text = IdentityTexts.Backend_Identity_Email_Verification_Success,
                NextStepLink = redirectUri
            };

            return View("Success", successVm);
        }
        catch (UserEmailInteractionException)
        {
            return BadRequest(new { message = "Email confirmation failed." });
        }
    }


    [HttpGet]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordModel vm)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(vm.UserName);
            if (user != null)
            {
                await _emailInteractionService.SendPasswordResetNotificationAsync(_options.Value.SystemTenantId, user);
            }
        }
        catch (Exception)
        {
            // we are not going to notify the user that an email address it not found.
        }

        return View("Success", new SuccessViewModel
        {
            Operation = IdentityTexts.Backend_General_Title_Success,
            Text = IdentityTexts.Backend_Identity_Reset_Email_Sent_Successfully
        });
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }


    /*****************************************/
    /* helper APIs for the AccountController */
    /*****************************************/
    private async Task<LoginViewModel> BuildLoginViewModelAsync(string? returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

            // this is meant to short circuit the UI and only trigger the one external IdP
            var vm = new LoginViewModel
            {
                EnableLocalLogin = local,
                TenantId = _options.Value.SystemTenantId,
                ReturnUrl = returnUrl ?? "",
                Username = context.LoginHint
            };

            if (!local)
            {
                vm.ExternalProviders = [new ExternalProvider { AuthenticationScheme = context.IdP }];
            }

            return vm;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProvider
            {
                DisplayName = x.DisplayName ?? x.Name,
                AuthenticationScheme = x.Name
            }).ToList();

        var allowLocal = true;
        if (context?.Client.ClientId != null)
        {
            var client = await _clientStore.FindClientByIdAsync(context.Client.ClientId);
            if (client != null)
            {
                allowLocal = client.EnableLocalLogin;

                if (client.IdentityProviderRestrictions.Any())
                {
                    providers = providers.Where(provider => !string.IsNullOrWhiteSpace(provider.AuthenticationScheme) &&
                                                            client.IdentityProviderRestrictions.Contains(
                                                                provider.AuthenticationScheme))
                        .ToList();
                }
            }
        }

        return new LoginViewModel
        {
            AllowRememberLogin = AccountOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
            TenantId = _options.Value.SystemTenantId,
            ReturnUrl = returnUrl,
            Username = context?.LoginHint,
            ExternalProviders = providers.ToArray()
        };
    }

    private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
    {
        var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
        vm.Username = model.Username;
        vm.RememberLogin = model.RememberLogin;
        return vm;
    }

    private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
    {
        var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

        if (User.Identity?.IsAuthenticated != true)
        {
            // if the user is not authenticated, then just show logged out page
            vm.ShowLogoutPrompt = false;
            return vm;
        }

        var context = await _interaction.GetLogoutContextAsync(logoutId);
        if (context.ShowSignoutPrompt == false)
        {
            // it's safe to automatically sign-out
            vm.ShowLogoutPrompt = false;
            return vm;
        }

        // show the logout prompt. this prevents attacks where the user
        // is automatically signed out by another malicious web page.
        return vm;
    }

    private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string? logoutId)
    {
        // get context information (client name, post logout redirect URI and iframe for federated sign out)
        var logout = await _interaction.GetLogoutContextAsync(logoutId);

        var vm = new LoggedOutViewModel
        {
            AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
            PostLogoutRedirectUri = logout.PostLogoutRedirectUri ?? "/",
            ClientName = string.IsNullOrEmpty(logout.ClientName) ? logout.ClientId : logout.ClientName,
            SignOutIframeUrl = logout.SignOutIFrameUrl,
            LogoutId = logoutId
        };

        if (User.Identity?.IsAuthenticated == true)
        {
            var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
            if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
            {
                var provider = HttpContext.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
                var handler = await provider.GetHandlerAsync(HttpContext, idp);
                if (handler is IAuthenticationSignOutHandler)
                {
                    vm.LogoutId ??= await _interaction.CreateLogoutContextAsync();
                    vm.ExternalAuthenticationScheme = idp;
                }
            }
        }

        return vm;
    }
}