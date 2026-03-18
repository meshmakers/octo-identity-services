using System.Text;
using System.Text.Encodings.Web;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
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
    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
    private const string InternalLoginProvider = "[AspNetUserStore]";
    private const string AuthenticatorKeyTokenName = "AuthenticatorKey";
    private const string RecoveryCodeTokenName = "RecoveryCodes";

    private readonly UserManager<RtUser> _userManager;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly UrlEncoder _urlEncoder;
    private readonly IQrCodeService _qrCodeService;
    private readonly IUserAuthenticationTokenStore<RtUser> _tokenStore;
    private readonly IAllowedTenantsResolver _allowedTenantsResolver;
    private readonly ISystemContext _systemContext;
    private readonly IGroupStore _groupStore;

    public ManageApiController(
        UserManager<RtUser> userManager,
        SignInManager<RtUser> signInManager,
        IAuthenticationSchemeProvider schemeProvider,
        UrlEncoder urlEncoder,
        IQrCodeService qrCodeService,
        IUserStore<RtUser> userStore,
        IAllowedTenantsResolver allowedTenantsResolver,
        ISystemContext systemContext,
        IGroupStore groupStore)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _schemeProvider = schemeProvider;
        _urlEncoder = urlEncoder;
        _qrCodeService = qrCodeService;
        _tokenStore = (IUserAuthenticationTokenStore<RtUser>)userStore;
        _allowedTenantsResolver = allowedTenantsResolver;
        _systemContext = systemContext;
        _groupStore = groupStore;
    }

    /// <summary>
    /// Get the current user's profile
    /// </summary>
    [HttpGet("profile")]
    public async Task<ActionResult<UserProfileDto>> GetProfile()
    {
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? string.Empty;
        if (await _systemContext.TryFindTenantContextAsync(tenantId) == null)
        {
            return NotFound($"Tenant '{tenantId}' not found.");
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var logins = await _userManager.GetLoginsAsync(user);
        var hasPassword = await _userManager.HasPasswordAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

        var allowedTenants = await _allowedTenantsResolver.ResolveAsync(tenantId, user);

        // Resolve group memberships via associations
        var allGroups = (await _groupStore.GetAllAsync()).ToList();
        var userRtIdString = user.RtId.ToString();
        var groupNames = new List<string>();
        foreach (var group in allGroups)
        {
            var memberUserIds = await _groupStore.GetMemberUserIdsAsync(group.RtId);
            if (memberUserIds.Contains(userRtIdString) && !string.IsNullOrEmpty(group.GroupName))
            {
                groupNames.Add(group.GroupName);
            }
        }

        return new UserProfileDto
        {
            Id = user.RtId.ToString(),
            TenantId = tenantId,
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
            }).ToList(),
            Roles = roles,
            AllowedTenants = allowedTenants,
            Groups = groupNames
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

    #region Two-Factor Authentication

    /// <summary>
    /// Get the current user's two-factor authentication status
    /// </summary>
    [HttpGet("2fa/status")]
    public async Task<ActionResult<TwoFactorStatusDto>> GetTwoFactorStatus()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var hasAuthenticator = !string.IsNullOrEmpty(await _userManager.GetAuthenticatorKeyAsync(user));
        var recoveryCodesCount = await _userManager.CountRecoveryCodesAsync(user);

        return new TwoFactorStatusDto
        {
            Enabled = await _userManager.GetTwoFactorEnabledAsync(user),
            HasAuthenticator = hasAuthenticator,
            RecoveryCodesLeft = recoveryCodesCount
        };
    }

    /// <summary>
    /// Setup authenticator app for two-factor authentication
    /// </summary>
    [HttpPost("2fa/authenticator/setup")]
    public async Task<ActionResult<AuthenticatorSetupDto>> SetupAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        // Get or create authenticator key
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        if (string.IsNullOrEmpty(unformattedKey))
        {
            return BadRequest("Failed to generate authenticator key");
        }

        var email = await _userManager.GetEmailAsync(user) ?? user.UserName ?? "user";
        var qrCodeUri = GenerateQrCodeUri("OctoMesh", email, unformattedKey);
        var qrCodeImage = _qrCodeService.GenerateQrCodeWithLogo(qrCodeUri);

        return new AuthenticatorSetupDto
        {
            SharedKey = FormatKey(unformattedKey),
            QrCodeUri = qrCodeUri,
            QrCodeImage = qrCodeImage
        };
    }

    /// <summary>
    /// Verify the authenticator code and enable two-factor authentication
    /// </summary>
    [HttpPost("2fa/authenticator/verify")]
    public async Task<ActionResult<VerifyAuthenticatorResultDto>> VerifyAuthenticator([FromBody] VerifyAuthenticatorRequestDto request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return new VerifyAuthenticatorResultDto
            {
                Success = false,
                ErrorMessage = "User not found"
            };
        }

        // Strip spaces and hyphens from the code
        var verificationCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            verificationCode);

        if (!isTokenValid)
        {
            return new VerifyAuthenticatorResultDto
            {
                Success = false,
                ErrorMessage = "Verification code is invalid"
            };
        }

        // Enable 2FA
        await _userManager.SetTwoFactorEnabledAsync(user, true);

        // Generate recovery codes
        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        return new VerifyAuthenticatorResultDto
        {
            Success = true,
            RecoveryCodes = recoveryCodes ?? []
        };
    }

    /// <summary>
    /// Disable two-factor authentication
    /// </summary>
    [HttpPost("2fa/disable")]
    public async Task<ActionResult<DisableTwoFactorResultDto>> DisableTwoFactor([FromBody] DisableTwoFactorRequestDto request)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return new DisableTwoFactorResultDto
            {
                Success = false,
                ErrorMessage = "User not found"
            };
        }

        // Verify the code before disabling
        var verificationCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            verificationCode);

        if (!isTokenValid)
        {
            return new DisableTwoFactorResultDto
            {
                Success = false,
                ErrorMessage = "Verification code is invalid"
            };
        }

        // Disable 2FA
        var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!result.Succeeded)
        {
            return new DisableTwoFactorResultDto
            {
                Success = false,
                ErrorMessage = "Failed to disable two-factor authentication"
            };
        }

        // Remove authenticator key and recovery codes tokens entirely
        await _tokenStore.RemoveTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, CancellationToken.None);
        await _tokenStore.RemoveTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, CancellationToken.None);

        // Update the user to persist the token changes
        await _userManager.UpdateAsync(user);
        await _signInManager.RefreshSignInAsync(user);

        return new DisableTwoFactorResultDto { Success = true };
    }

    /// <summary>
    /// Generate new recovery codes
    /// </summary>
    [HttpPost("2fa/recovery-codes/generate")]
    public async Task<ActionResult<GenerateRecoveryCodesResultDto>> GenerateRecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        if (!isTwoFactorEnabled)
        {
            return BadRequest("Cannot generate recovery codes when two-factor authentication is not enabled");
        }

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        return new GenerateRecoveryCodesResultDto
        {
            RecoveryCodes = recoveryCodes ?? []
        };
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        var currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }
        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string issuer, string email, string unformattedKey)
    {
        return string.Format(
            AuthenticatorUriFormat,
            _urlEncoder.Encode(issuer),
            _urlEncoder.Encode(email),
            unformattedKey);
    }

    #endregion
}

#region DTOs

public record UserProfileDto
{
    public string Id { get; init; } = string.Empty;
    public string TenantId { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string? Email { get; init; }
    public bool EmailConfirmed { get; init; }
    public string? PhoneNumber { get; init; }
    public bool PhoneNumberConfirmed { get; init; }
    public bool TwoFactorEnabled { get; init; }
    public bool HasPassword { get; init; }
    public IEnumerable<ExternalLoginInfoDto> ExternalLogins { get; init; } = [];
    public IEnumerable<string> Roles { get; init; } = [];
    public IEnumerable<string> AllowedTenants { get; init; } = [];
    public IEnumerable<string> Groups { get; init; } = [];
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

// Two-Factor Authentication DTOs

public record TwoFactorStatusDto
{
    public bool Enabled { get; init; }
    public bool HasAuthenticator { get; init; }
    public int RecoveryCodesLeft { get; init; }
}

public record AuthenticatorSetupDto
{
    public string SharedKey { get; init; } = string.Empty;
    public string QrCodeUri { get; init; } = string.Empty;
    public string QrCodeImage { get; init; } = string.Empty;
}

public record VerifyAuthenticatorRequestDto
{
    public string Code { get; init; } = string.Empty;
}

public record VerifyAuthenticatorResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public IEnumerable<string> RecoveryCodes { get; init; } = [];
}

public record DisableTwoFactorRequestDto
{
    public string Code { get; init; } = string.Empty;
}

public record DisableTwoFactorResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

public record GenerateRecoveryCodesResultDto
{
    public IEnumerable<string> RecoveryCodes { get; init; } = [];
}

#endregion
