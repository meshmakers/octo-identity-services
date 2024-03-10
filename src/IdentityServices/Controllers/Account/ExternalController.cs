using System.Security.Claims;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Account;

[AllowAnonymous]
public class ExternalController : Controller
{
    private readonly IEventService _events;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly UserManager<RtUser> _userManager;

    public ExternalController(
        UserManager<RtUser> userManager,
        SignInManager<RtUser> signInManager,
        IIdentityServerInteractionService interaction,
        RoleManager<RtRole> roleManager,
        IEventService events)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _interaction = interaction;
        _roleManager = roleManager;
        _events = events;
    }

    /// <summary>
    ///     initiate roundtrip to external authentication provider
    /// </summary>
    [HttpGet]
    public Task<IActionResult> Challenge(string provider, string returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = "~/";
        }

        // validate returnUrl - either it is a valid OIDC URL or back to a local page
        if (Url.IsLocalUrl(returnUrl) == false && _interaction.IsValidReturnUrl(returnUrl) == false)
            // user might have clicked on a malicious link - should be logged
        {
            throw new Exception("invalid return URL");
        }

        var redirectUrl = Url.Action("Callback", "External", new { ReturnUrl = returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Task.FromResult<IActionResult>(Challenge(properties, provider));
    }

    /// <summary>
    ///     PostApiResource processing of external authentication
    /// </summary>
    /// <summary>
    ///     Post processing of external authentication
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> Callback(string? returnUrl = null)
    {
        // read external identity from the temporary cookie
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
        if (result.Succeeded != true)
        {
            throw new Exception("External authentication error");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return Redirect("~/");
        }

        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);


        // lookup our user and external provider info
        if (user == null)
            // this might be where you might initiate a custom workflow for user registration
            // in this sample we don't show how that would be done, as our sample implementation
            // simply auto-provisions new external user
        {
            user = await AutoProvisionUserAsync(info.LoginProvider, info.ProviderKey,
                info.Principal.Claims.ToList());
        }

        await SynchronizeGroups(info.Principal.Claims, user);

        // this allows us to collect any additional claims or properties
        // for the specific protocols used and store them in the local auth cookie.
        // this is typically used to store data needed for sign out from those protocols.
        var additionalLocalClaims = new List<Claim>();
        var localSignInProps = new AuthenticationProperties();
        ProcessLoginCallbackForOidc(result, additionalLocalClaims, localSignInProps);

        // issue authentication cookie for user
        // we must issue the cookie manually, and can't use the SignInManager because
        // it doesn't expose an API to issue additional claims from the login workflow
        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        additionalLocalClaims.AddRange(principal.Claims);
        var name = principal.FindFirst(JwtClaimTypes.Name)?.Value ?? user.RtId.ToString();
        await _events.RaiseAsync(
            new UserLoginSuccessEvent(info.LoginProvider, info.ProviderKey, user.RtId.ToString(), name));

        var identityServerUser = new IdentityServerUser(user.RtId.ToString())
        {
            DisplayName = name,
            IdentityProvider = info.LoginProvider,
            AdditionalClaims = additionalLocalClaims.ToArray(),
            AuthenticationTime = DateTime.UtcNow
        };
        await HttpContext.SignInAsync(identityServerUser, localSignInProps);

        // delete temporary cookie used during external authentication
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        // validate return URL and redirect back to authorization endpoint or a local page
        //var returnUrl = result.Properties.Items["returnUrl"];
        if (!string.IsNullOrWhiteSpace(returnUrl) && (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl)))
        {
            return Redirect(returnUrl);
        }

        return Redirect("~/");
    }

    private async Task SynchronizeGroups(IEnumerable<Claim> claims, RtUser user)
    {
        // Get roles of identity provider and check if they exist in octo mesh
        var rolesRequested = claims.Where(x => x.Type == JwtClaimTypes.Role).Select(x => x.Value).ToList();
        foreach (var roleName in rolesRequested.ToArray())
        {
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role == null)
            {
                rolesRequested.Remove(roleName);
            }
        }

        // check which roles has to be added or removed.
        var rolesToRemove = user.RoleIds?.Except(rolesRequested).ToList();
        var rolesToAdd = rolesRequested.ToList();
        if (user.RoleIds != null)
        {
            rolesToAdd = rolesToAdd.Except(user.RoleIds).ToList();
        }

        if (rolesToRemove != null && rolesToRemove.Any())
        {
            await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
        }

        if (rolesToAdd.Any())
        {
            await _userManager.AddToRolesAsync(user, rolesToAdd);
        }
    }

    private async Task<RtUser> AutoProvisionUserAsync(string provider, string providerUserId, IList<Claim> claims)
    {
        // create a list of claims that we want to transfer into our store
        var filtered = new List<Claim>();

        // user's display name
        var name = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Name)?.Value ??
                   claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
        var givenName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value ??
                        claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
        var familyName = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value ??
                         claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;
        if (name != null)
        {
            filtered.Add(new Claim(JwtClaimTypes.Name, name));
        }
        else
        {
            if (givenName != null && familyName != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, givenName + " " + familyName));
            }
            else if (givenName != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, givenName));
            }
            else if (familyName != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, familyName));
            }
        }

        // first name
        if (!string.IsNullOrEmpty(givenName))
        {
            filtered.Add(new Claim(JwtClaimTypes.GivenName, givenName));
        }

        // family name
        if (!string.IsNullOrEmpty(familyName))
        {
            filtered.Add(new Claim(JwtClaimTypes.FamilyName, familyName));
        }

        // email
        var email = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Email)?.Value ??
                    claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
        if (email != null)
        {
            filtered.Add(new Claim(JwtClaimTypes.Email, email));
        }

        var user = new RtUser
        {
            UserName = Guid.NewGuid().ToString(),
            FirstName = givenName,
            LastName = familyName,
            Email = email,
            EmailConfirmed = true
        };

        var identityResult = await _userManager.CreateAsync(user);
        if (!identityResult.Succeeded)
        {
            throw new Exception(identityResult.Errors.First().Description);
        }

        if (filtered.Any())
        {
            identityResult = await _userManager.AddClaimsAsync(user, filtered);
            if (!identityResult.Succeeded)
            {
                throw new Exception(identityResult.Errors.First().Description);
            }
        }

        identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, name));
        if (!identityResult.Succeeded)
        {
            throw new Exception(identityResult.Errors.First().Description);
        }

        return user;
    }


    private void ProcessLoginCallbackForOidc(AuthenticateResult externalResult, List<Claim> localClaims,
        AuthenticationProperties localSignInProps)
    {
        // if the external system sent a session id claim, copy it over
        // so we can use it for single sign-out
        var sid = externalResult.Principal?.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
        if (sid != null)
        {
            localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
        }

        // if the external provider issued an id_token, we'll keep it for sign out
        var idToken = externalResult.Properties?.GetTokenValue("id_token");
        if (idToken != null)
        {
            localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
        }
    }
}