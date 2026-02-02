using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for Angular SPA user management operations
/// </summary>
[ApiController]
[Route("{tenantId}/api/manage")]
[Authorize]
public class ManageApiController : ControllerBase
{
    private readonly UserManager<RtUser> _userManager;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    public ManageApiController(
        UserManager<RtUser> userManager,
        SignInManager<RtUser> signInManager,
        IAuthenticationSchemeProvider schemeProvider)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _schemeProvider = schemeProvider;
    }

    /// <summary>
    /// Get the current user's profile
    /// </summary>
    [HttpGet("profile")]
    public async Task<ActionResult<UserProfileDto>> GetProfile()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var logins = await _userManager.GetLoginsAsync(user);
        var hasPassword = await _userManager.HasPasswordAsync(user);

        return new UserProfileDto
        {
            Id = user.RtId.ToString(),
            UserName = user.UserName ?? string.Empty,
            Email = user.Email,
            EmailConfirmed = user.EmailConfirmed,
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            TwoFactorEnabled = user.TwoFactorEnabled,
            HasPassword = hasPassword,
            ExternalLogins = logins.Select(l => new ExternalLoginInfoDto
            {
                LoginProvider = l.LoginProvider,
                ProviderDisplayName = l.ProviderDisplayName ?? l.LoginProvider,
                ProviderKey = l.ProviderKey
            }).ToList()
        };
    }

    /// <summary>
    /// Get all external logins for the current user
    /// </summary>
    [HttpGet("external-logins")]
    public async Task<ActionResult<IEnumerable<ExternalLoginInfoDto>>> GetExternalLogins()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var logins = await _userManager.GetLoginsAsync(user);
        return logins.Select(l => new ExternalLoginInfoDto
        {
            LoginProvider = l.LoginProvider,
            ProviderDisplayName = l.ProviderDisplayName ?? l.LoginProvider,
            ProviderKey = l.ProviderKey
        }).ToList();
    }

    /// <summary>
    /// Get available external authentication providers that the user hasn't linked yet
    /// </summary>
    [HttpGet("available-providers")]
    public async Task<ActionResult<IEnumerable<AvailableProviderDto>>> GetAvailableProviders()
    {
        var schemes = await _schemeProvider.GetAllSchemesAsync();

        return schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new AvailableProviderDto
            {
                Scheme = x.Name,
                DisplayName = x.DisplayName ?? x.Name
            })
            .ToList();
    }

    /// <summary>
    /// Initiate adding an external login - redirects to the external provider
    /// </summary>
    [HttpGet("add-external-login")]
    public async Task<IActionResult> AddExternalLogin([FromQuery] string scheme, [FromQuery] string tenantId)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(AddExternalLoginCallback), new { tenantId }),
            Items =
            {
                { "scheme", scheme },
                { "tenantId", tenantId }
            }
        };

        return Challenge(props, scheme);
    }

    /// <summary>
    /// Callback for adding external login
    /// </summary>
    [HttpGet("add-external-login-callback")]
    public async Task<IActionResult> AddExternalLoginCallback([FromQuery] string tenantId)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return Redirect($"/{tenantId}/manage/external-logins?error=User not found");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync(await _userManager.GetUserIdAsync(user));
        if (info == null)
        {
            return Redirect($"/{tenantId}/manage/external-logins?error=External login info not found");
        }

        var result = await _userManager.AddLoginAsync(user, info);
        if (!result.Succeeded)
        {
            var error = result.Errors.FirstOrDefault()?.Description ?? "Failed to add external login";
            return Redirect($"/{tenantId}/manage/external-logins?error={Uri.EscapeDataString(error)}");
        }

        return Redirect($"/{tenantId}/manage/external-logins?success=true");
    }

    /// <summary>
    /// Remove an external login from the current user
    /// </summary>
    [HttpPost("remove-external-login")]
    public async Task<ActionResult<RemoveLoginResultDto>> RemoveExternalLogin([FromBody] RemoveLoginRequestDto request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return new RemoveLoginResultDto
            {
                Success = false,
                ErrorMessage = "User not found"
            };
        }

        // Check if user would have no way to login after removal
        var hasPassword = await _userManager.HasPasswordAsync(user);
        var logins = await _userManager.GetLoginsAsync(user);

        if (!hasPassword && logins.Count <= 1)
        {
            return new RemoveLoginResultDto
            {
                Success = false,
                ErrorMessage = "You cannot remove your only login method. Please set a password first."
            };
        }

        var result = await _userManager.RemoveLoginAsync(user, request.LoginProvider, request.ProviderKey);
        if (!result.Succeeded)
        {
            return new RemoveLoginResultDto
            {
                Success = false,
                ErrorMessage = result.Errors.FirstOrDefault()?.Description ?? "Failed to remove login"
            };
        }

        await _signInManager.RefreshSignInAsync(user);
        return new RemoveLoginResultDto { Success = true };
    }

    /// <summary>
    /// Change the current user's password
    /// </summary>
    [HttpPost("change-password")]
    public async Task<ActionResult<PasswordResultDto>> ChangePassword([FromBody] ChangePasswordRequestDto request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return new PasswordResultDto
            {
                Success = false,
                ErrorMessage = "User not found"
            };
        }

        if (request.NewPassword != request.ConfirmPassword)
        {
            return new PasswordResultDto
            {
                Success = false,
                ErrorMessage = "Passwords do not match"
            };
        }

        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            return new PasswordResultDto
            {
                Success = false,
                ErrorMessage = "Failed to change password",
                Errors = result.Errors.Select(e => e.Description).ToList()
            };
        }

        await _signInManager.RefreshSignInAsync(user);
        return new PasswordResultDto { Success = true };
    }

    /// <summary>
    /// Set a password for a user who only has external logins
    /// </summary>
    [HttpPost("set-password")]
    public async Task<ActionResult<PasswordResultDto>> SetPassword([FromBody] SetPasswordRequestDto request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return new PasswordResultDto
            {
                Success = false,
                ErrorMessage = "User not found"
            };
        }

        var hasPassword = await _userManager.HasPasswordAsync(user);
        if (hasPassword)
        {
            return new PasswordResultDto
            {
                Success = false,
                ErrorMessage = "User already has a password. Use change-password instead."
            };
        }

        if (request.NewPassword != request.ConfirmPassword)
        {
            return new PasswordResultDto
            {
                Success = false,
                ErrorMessage = "Passwords do not match"
            };
        }

        var result = await _userManager.AddPasswordAsync(user, request.NewPassword);
        if (!result.Succeeded)
        {
            return new PasswordResultDto
            {
                Success = false,
                ErrorMessage = "Failed to set password",
                Errors = result.Errors.Select(e => e.Description).ToList()
            };
        }

        await _signInManager.RefreshSignInAsync(user);
        return new PasswordResultDto { Success = true };
    }
}

#region DTOs

public record UserProfileDto
{
    public string Id { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string? Email { get; init; }
    public bool EmailConfirmed { get; init; }
    public string? PhoneNumber { get; init; }
    public bool PhoneNumberConfirmed { get; init; }
    public bool TwoFactorEnabled { get; init; }
    public bool HasPassword { get; init; }
    public IEnumerable<ExternalLoginInfoDto> ExternalLogins { get; init; } = [];
}

public record ExternalLoginInfoDto
{
    public string LoginProvider { get; init; } = string.Empty;
    public string ProviderDisplayName { get; init; } = string.Empty;
    public string ProviderKey { get; init; } = string.Empty;
}

public record AvailableProviderDto
{
    public string Scheme { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
}

public record RemoveLoginRequestDto
{
    public string LoginProvider { get; init; } = string.Empty;
    public string ProviderKey { get; init; } = string.Empty;
}

public record RemoveLoginResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

public record ChangePasswordRequestDto
{
    public string CurrentPassword { get; init; } = string.Empty;
    public string NewPassword { get; init; } = string.Empty;
    public string ConfirmPassword { get; init; } = string.Empty;
}

public record SetPasswordRequestDto
{
    public string NewPassword { get; init; } = string.Empty;
    public string ConfirmPassword { get; init; } = string.Empty;
}

public record PasswordResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public IEnumerable<string>? Errors { get; init; }
}

#endregion
