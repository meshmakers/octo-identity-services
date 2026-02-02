using System.Security.Claims;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for Angular SPA authentication operations
/// </summary>
[ApiController]
[Route("{tenantId}/api/auth")]
[AllowAnonymous]
public class AuthApiController : ControllerBase
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IClientStore _clientStore;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly UserManager<RtUser> _userManager;
    private readonly IEventService _events;
    private readonly IPersistedGrantStore _persistedGrantStore;
    private readonly ILogger<AuthApiController> _logger;

    public AuthApiController(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IClientStore clientStore,
        SignInManager<RtUser> signInManager,
        UserManager<RtUser> userManager,
        IEventService events,
        IPersistedGrantStore persistedGrantStore,
        ILogger<AuthApiController> logger)
    {
        _interaction = interaction;
        _schemeProvider = schemeProvider;
        _clientStore = clientStore;
        _signInManager = signInManager;
        _userManager = userManager;
        _events = events;
        _persistedGrantStore = persistedGrantStore;
        _logger = logger;
    }

    /// <summary>
    /// Get the login context for building the login UI
    /// </summary>
    [HttpGet("login-context")]
    public async Task<ActionResult<LoginContextDto>> GetLoginContext([FromQuery] string? returnUrl)
    {
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProviderDto
            {
                Scheme = x.Name,
                DisplayName = x.DisplayName ?? x.Name
            })
            .ToList();

        var allowLocal = true;
        string? clientName = null;
        string? clientLogoUrl = null;

        if (context?.Client?.ClientId != null)
        {
            var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
            if (client != null)
            {
                allowLocal = client.EnableLocalLogin;
                clientName = client.ClientName ?? client.ClientId;
                clientLogoUrl = client.LogoUri;

                if (client.IdentityProviderRestrictions.Any())
                {
                    providers = providers
                        .Where(p => client.IdentityProviderRestrictions.Contains(p.Scheme))
                        .ToList();
                }
            }
        }

        // Check if user is already authenticated
        var isAuthenticated = User.Identity?.IsAuthenticated ?? false;
        string? username = null;
        if (isAuthenticated)
        {
            username = User.Identity?.Name;
        }

        return new LoginContextDto
        {
            ReturnUrl = returnUrl ?? string.Empty,
            ClientName = clientName,
            ClientLogoUrl = clientLogoUrl,
            ExternalProviders = providers,
            AllowRememberLogin = true,
            EnableLocalLogin = allowLocal,
            IsAuthenticated = isAuthenticated,
            Username = username
        };
    }

    /// <summary>
    /// Process login credentials
    /// </summary>
    [HttpPost("login")]
    public async Task<ActionResult<LoginResultDto>> Login([FromBody] LoginRequestDto request)
    {
        var context = await _interaction.GetAuthorizationContextAsync(request.ReturnUrl);

        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Username and password are required"
            };
        }

        var result = await _signInManager.PasswordSignInAsync(
            request.Username,
            request.Password,
            request.RememberLogin,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            await _events.RaiseAsync(new UserLoginSuccessEvent(
                user?.UserName,
                user?.RtId.ToString(),
                user?.UserName,
                clientId: context?.Client?.ClientId));

            if (context != null)
            {
                return new LoginResultDto
                {
                    Success = true,
                    RedirectUrl = request.ReturnUrl
                };
            }

            // No context - redirect to manage page with tenant ID
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            return new LoginResultDto
            {
                Success = true,
                RedirectUrl = $"/{tenantId}/manage"
            };
        }

        await _events.RaiseAsync(new UserLoginFailureEvent(
            request.Username,
            "Invalid credentials",
            clientId: context?.Client?.ClientId));

        if (result.IsLockedOut)
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Account is locked out",
                IsLockedOut = true
            };
        }

        if (result.RequiresTwoFactor)
        {
            // Check what 2FA methods are available
            var twoFactorUser = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            var canUseTotp = twoFactorUser != null &&
                !string.IsNullOrEmpty(await _userManager.GetAuthenticatorKeyAsync(twoFactorUser));
            var canUseEmail = twoFactorUser != null &&
                await _userManager.IsEmailConfirmedAsync(twoFactorUser);

            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication required",
                RequiresTwoFactor = true,
                CanUseTotpAuthenticator = canUseTotp,
                CanUseEmailCode = canUseEmail
            };
        }

        return new LoginResultDto
        {
            Success = false,
            ErrorMessage = "Invalid username or password"
        };
    }

    /// <summary>
    /// Get available external authentication providers
    /// </summary>
    [HttpGet("external-providers")]
    public async Task<ActionResult<IEnumerable<ExternalProviderDto>>> GetExternalProviders()
    {
        var schemes = await _schemeProvider.GetAllSchemesAsync();

        return schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ExternalProviderDto
            {
                Scheme = x.Name,
                DisplayName = x.DisplayName ?? x.Name
            })
            .ToList();
    }

    /// <summary>
    /// Initiate external login - redirects to the external provider
    /// </summary>
    [HttpGet("external-login")]
    public IActionResult ExternalLogin([FromQuery] string scheme, [FromQuery] string? returnUrl)
    {
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(ExternalLoginCallback)),
            Items =
            {
                { "returnUrl", returnUrl },
                { "scheme", scheme }
            }
        };

        return Challenge(props, scheme);
    }

    /// <summary>
    /// Callback for external login
    /// </summary>
    [HttpGet("external-callback")]
    public async Task<IActionResult> ExternalLoginCallback()
    {
        // 1. Authenticate from external cookie
        var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (!result.Succeeded)
        {
            _logger.LogWarning("External authentication failed: {Error}", result.Failure?.Message);
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            return Redirect($"/{tenantId}/error?error=External authentication failed");
        }

        // 2. Extract external login info
        var externalUser = result.Principal;
        var claims = externalUser?.Claims.ToList() ?? [];

        var provider = result.Properties?.Items["scheme"] ??
                       result.Properties?.Items[".AuthScheme"] ??
                       claims.FirstOrDefault(c => c.Type == "idp")?.Value;
        var returnUrl = result.Properties?.Items["returnUrl"] ?? "~/";

        // Get unique identifier from provider
        var userIdClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier) ??
                          claims.FirstOrDefault(c => c.Type == "sub");

        if (userIdClaim == null || string.IsNullOrEmpty(provider))
        {
            _logger.LogWarning("External login missing required claims. Provider: {Provider}, UserIdClaim: {UserIdClaim}",
                provider, userIdClaim?.Value);
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            return Redirect($"/{tenantId}/error?error=Invalid external login - missing required claims");
        }

        _logger.LogInformation("Processing external login callback for provider {Provider}, user {UserId}",
            provider, userIdClaim.Value);

        // 3. Find existing user by external login
        var user = await _userManager.FindByLoginAsync(provider, userIdClaim.Value);

        if (user == null)
        {
            // 4a. Try to find user by email (for account linking)
            var emailClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            if (emailClaim != null && !string.IsNullOrEmpty(emailClaim.Value))
            {
                user = await _userManager.FindByEmailAsync(emailClaim.Value);
                if (user != null)
                {
                    _logger.LogInformation("Found existing user {UserName} by email {Email}, linking external login",
                        user.UserName, emailClaim.Value);
                }
            }

            if (user == null)
            {
                // 4b. Create new user from external provider
                user = await CreateUserFromExternalProvider(claims, provider);
                if (user == null)
                {
                    var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
                    return Redirect($"/{tenantId}/error?error=Failed to create user account");
                }

                _logger.LogInformation("Created new user {UserName} from external provider {Provider}",
                    user.UserName, provider);
            }

            // 5. Link external login to user
            var addLoginResult = await _userManager.AddLoginAsync(
                user,
                new UserLoginInfo(provider, userIdClaim.Value, provider));

            if (!addLoginResult.Succeeded)
            {
                _logger.LogError("Failed to add external login for user {UserName}: {Errors}",
                    user.UserName,
                    string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
            }
            else
            {
                _logger.LogInformation("Linked external login {Provider} to user {UserName}",
                    provider, user.UserName);
            }
        }

        // 6. Sign in the user
        await _signInManager.SignInAsync(user, isPersistent: false);

        await _events.RaiseAsync(new UserLoginSuccessEvent(
            user.UserName,
            user.RtId.ToString(),
            user.UserName,
            clientId: null));

        // 7. Clean up external cookie
        await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        // 8. Handle return URL
        if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        var defaultTenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        return Redirect($"/{defaultTenantId}/manage");
    }

    /// <summary>
    /// Creates a new user from external provider claims
    /// </summary>
    private async Task<RtUser?> CreateUserFromExternalProvider(List<Claim> claims, string provider)
    {
        var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
        var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
        var givenName = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value;
        var surname = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value;

        // Generate username from email or provider + unique id
        var userName = email ?? $"{provider}_{Guid.NewGuid():N}";

        // Ensure username is unique
        var existingUser = await _userManager.FindByNameAsync(userName);
        if (existingUser != null)
        {
            userName = $"{userName}_{Guid.NewGuid().ToString("N")[..8]}";
        }

        var user = new RtUser
        {
            RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email?.ToUpperInvariant(),
            EmailConfirmed = email != null, // Trust external provider's email verification
            FirstName = givenName ?? string.Empty,
            LastName = surname ?? string.Empty,
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var result = await _userManager.CreateAsync(user);

        if (!result.Succeeded)
        {
            _logger.LogError("Failed to create user from external provider {Provider}: {Errors}",
                provider,
                string.Join(", ", result.Errors.Select(e => e.Description)));
            return null;
        }

        return user;
    }

    /// <summary>
    /// Get the logout context
    /// </summary>
    [HttpGet("logout-context")]
    public async Task<ActionResult<LogoutContextDto>> GetLogoutContext([FromQuery] string? logoutId)
    {
        var context = await _interaction.GetLogoutContextAsync(logoutId);

        return new LogoutContextDto
        {
            LogoutId = logoutId ?? string.Empty,
            ShowLogoutPrompt = context?.ShowSignoutPrompt ?? true,
            PostLogoutRedirectUri = context?.PostLogoutRedirectUri,
            ClientName = context?.ClientName
        };
    }

    /// <summary>
    /// Process logout
    /// </summary>
    [HttpPost("logout")]
    public async Task<ActionResult<LogoutResultDto>> Logout([FromBody] LogoutRequestDto request)
    {
        var context = await _interaction.GetLogoutContextAsync(request.LogoutId);

        if (User.Identity?.IsAuthenticated == true)
        {
            var subjectId = User.GetSubjectId();

            // Revoke all persisted grants (refresh tokens, etc.) for this user
            // This ensures that clients cannot use refresh tokens after logout
            await _persistedGrantStore.RemoveAllAsync(new PersistedGrantFilter
            {
                SubjectId = subjectId
            });

            await _signInManager.SignOutAsync();
            await _events.RaiseAsync(new UserLogoutSuccessEvent(
                subjectId,
                User.GetDisplayName()));
        }

        return new LogoutResultDto
        {
            Success = true,
            PostLogoutRedirectUri = context?.PostLogoutRedirectUri,
            ClientName = context?.ClientName,
            SignOutIframeUrl = context?.SignOutIFrameUrl,
            AutomaticRedirectAfterSignOut = true
        };
    }

    /// <summary>
    /// Request a password reset email
    /// </summary>
    [HttpPost("forgot-password")]
    public async Task<ActionResult<ForgotPasswordResultDto>> ForgotPassword([FromBody] ForgotPasswordRequestDto request)
    {
        if (string.IsNullOrEmpty(request.Email))
        {
            return new ForgotPasswordResultDto
            {
                Success = false,
                ErrorMessage = "Email is required"
            };
        }

        var user = await _userManager.FindByEmailAsync(request.Email);

        // Always return success to prevent email enumeration attacks
        if (user == null)
        {
            return new ForgotPasswordResultDto { Success = true };
        }

        // Generate password reset token
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        // TODO: Send email with reset link
        // For now, we'll log the token (in production, this would send an email)
        // The reset link would be: /{tenantId}/reset-password?email={email}&token={token}

        // In a real implementation, inject IEmailSender and send:
        // await _emailSender.SendPasswordResetEmailAsync(user.Email, token);

        return new ForgotPasswordResultDto { Success = true };
    }

    /// <summary>
    /// Reset password with token
    /// </summary>
    [HttpPost("reset-password")]
    public async Task<ActionResult<ResetPasswordResultDto>> ResetPassword([FromBody] ResetPasswordRequestDto request)
    {
        if (string.IsNullOrEmpty(request.Email))
        {
            return new ResetPasswordResultDto
            {
                Success = false,
                ErrorMessage = "Email is required"
            };
        }

        if (string.IsNullOrEmpty(request.Token))
        {
            return new ResetPasswordResultDto
            {
                Success = false,
                ErrorMessage = "Reset token is required"
            };
        }

        if (string.IsNullOrEmpty(request.NewPassword))
        {
            return new ResetPasswordResultDto
            {
                Success = false,
                ErrorMessage = "New password is required"
            };
        }

        if (request.NewPassword != request.ConfirmPassword)
        {
            return new ResetPasswordResultDto
            {
                Success = false,
                ErrorMessage = "Passwords do not match"
            };
        }

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            // Don't reveal that the user doesn't exist
            return new ResetPasswordResultDto
            {
                Success = false,
                ErrorMessage = "Invalid reset token"
            };
        }

        var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

        if (result.Succeeded)
        {
            return new ResetPasswordResultDto { Success = true };
        }

        var errors = result.Errors.Select(e => e.Description).ToList();
        return new ResetPasswordResultDto
        {
            Success = false,
            ErrorMessage = errors.FirstOrDefault() ?? "Failed to reset password",
            Errors = errors
        };
    }

    /// <summary>
    /// Validate a password reset token (check if it's still valid)
    /// </summary>
    [HttpGet("validate-reset-token")]
    public async Task<ActionResult<ValidateResetTokenResultDto>> ValidateResetToken(
        [FromQuery] string email,
        [FromQuery] string token)
    {
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
        {
            return new ValidateResetTokenResultDto { IsValid = false };
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return new ValidateResetTokenResultDto { IsValid = false };
        }

        // Verify the token is valid
        var isValid = await _userManager.VerifyUserTokenAsync(
            user,
            _userManager.Options.Tokens.PasswordResetTokenProvider,
            "ResetPassword",
            token);

        return new ValidateResetTokenResultDto { IsValid = isValid };
    }

    #region Two-Factor Authentication

    /// <summary>
    /// Login with two-factor authentication code (TOTP)
    /// </summary>
    [HttpPost("login-2fa")]
    public async Task<ActionResult<TwoFactorLoginResultDto>> LoginTwoFactor([FromBody] TwoFactorLoginRequestDto request)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication session expired. Please login again."
            };
        }

        var authenticatorCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
            authenticatorCode,
            isPersistent: false,
            rememberClient: request.RememberMachine);

        if (result.Succeeded)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(
                user.UserName,
                user.RtId.ToString(),
                user.UserName,
                clientId: null));

            // Get the return URL from the session/context if available
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            return new TwoFactorLoginResultDto
            {
                Success = true,
                RedirectUrl = $"/{tenantId}/manage"
            };
        }

        if (result.IsLockedOut)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Account is locked out"
            };
        }

        await _events.RaiseAsync(new UserLoginFailureEvent(
            user.UserName,
            "Invalid two-factor code",
            clientId: null));

        return new TwoFactorLoginResultDto
        {
            Success = false,
            ErrorMessage = "Invalid authenticator code"
        };
    }

    /// <summary>
    /// Login with two-factor email code
    /// </summary>
    [HttpPost("login-2fa-email")]
    public async Task<ActionResult<TwoFactorLoginResultDto>> LoginTwoFactorEmail([FromBody] TwoFactorEmailLoginRequestDto request)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication session expired. Please login again."
            };
        }

        var emailCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await _signInManager.TwoFactorSignInAsync(
            TokenOptions.DefaultEmailProvider,
            emailCode,
            isPersistent: false,
            rememberClient: request.RememberMachine);

        if (result.Succeeded)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(
                user.UserName,
                user.RtId.ToString(),
                user.UserName,
                clientId: null));

            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            return new TwoFactorLoginResultDto
            {
                Success = true,
                RedirectUrl = $"/{tenantId}/manage"
            };
        }

        if (result.IsLockedOut)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Account is locked out"
            };
        }

        await _events.RaiseAsync(new UserLoginFailureEvent(
            user.UserName,
            "Invalid two-factor email code",
            clientId: null));

        return new TwoFactorLoginResultDto
        {
            Success = false,
            ErrorMessage = "Invalid email verification code"
        };
    }

    /// <summary>
    /// Send two-factor email verification code
    /// </summary>
    [HttpPost("send-2fa-email")]
    public async Task<ActionResult<SendTwoFactorEmailResultDto>> SendTwoFactorEmail()
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return new SendTwoFactorEmailResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication session expired. Please login again."
            };
        }

        if (string.IsNullOrEmpty(user.Email))
        {
            return new SendTwoFactorEmailResultDto
            {
                Success = false,
                ErrorMessage = "No email address associated with this account"
            };
        }

        var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

        // TODO: Send email with the code using IEmailSender
        // await _emailSender.SendTwoFactorEmailAsync(user.Email, code);
        // For now, we log the code (in production, this would send an email)

        return new SendTwoFactorEmailResultDto { Success = true };
    }

    /// <summary>
    /// Login with recovery code
    /// </summary>
    [HttpPost("login-recovery")]
    public async Task<ActionResult<TwoFactorLoginResultDto>> LoginRecovery([FromBody] RecoveryCodeLoginRequestDto request)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication session expired. Please login again."
            };
        }

        var recoveryCode = request.RecoveryCode.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await _signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

        if (result.Succeeded)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(
                user.UserName,
                user.RtId.ToString(),
                user.UserName,
                clientId: null));

            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            return new TwoFactorLoginResultDto
            {
                Success = true,
                RedirectUrl = $"/{tenantId}/manage"
            };
        }

        if (result.IsLockedOut)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Account is locked out"
            };
        }

        await _events.RaiseAsync(new UserLoginFailureEvent(
            user.UserName,
            "Invalid recovery code",
            clientId: null));

        return new TwoFactorLoginResultDto
        {
            Success = false,
            ErrorMessage = "Invalid recovery code"
        };
    }

    #endregion
}

#region DTOs

public record LoginContextDto
{
    public string ReturnUrl { get; init; } = string.Empty;
    public string? ClientName { get; init; }
    public string? ClientLogoUrl { get; init; }
    public IEnumerable<ExternalProviderDto> ExternalProviders { get; init; } = [];
    public bool AllowRememberLogin { get; init; }
    public bool EnableLocalLogin { get; init; }
    public bool IsAuthenticated { get; init; }
    public string? Username { get; init; }
}

public record LoginRequestDto
{
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public bool RememberLogin { get; init; }
    public string? ReturnUrl { get; init; }
}

public record LoginResultDto
{
    public bool Success { get; init; }
    public string? RedirectUrl { get; init; }
    public string? ErrorMessage { get; init; }
    public bool IsLockedOut { get; init; }
    public bool RequiresTwoFactor { get; init; }
    public bool CanUseTotpAuthenticator { get; init; }
    public bool CanUseEmailCode { get; init; }
}

public record ExternalProviderDto
{
    public string Scheme { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
}

public record LogoutContextDto
{
    public string LogoutId { get; init; } = string.Empty;
    public bool ShowLogoutPrompt { get; init; }
    public string? PostLogoutRedirectUri { get; init; }
    public string? ClientName { get; init; }
}

public record LogoutRequestDto
{
    public string LogoutId { get; init; } = string.Empty;
}

public record LogoutResultDto
{
    public bool Success { get; init; }
    public string? PostLogoutRedirectUri { get; init; }
    public string? ClientName { get; init; }
    public string? SignOutIframeUrl { get; init; }
    public bool AutomaticRedirectAfterSignOut { get; init; }
}

public record ForgotPasswordRequestDto
{
    public string Email { get; init; } = string.Empty;
}

public record ForgotPasswordResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

public record ResetPasswordRequestDto
{
    public string Email { get; init; } = string.Empty;
    public string Token { get; init; } = string.Empty;
    public string NewPassword { get; init; } = string.Empty;
    public string ConfirmPassword { get; init; } = string.Empty;
}

public record ResetPasswordResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public IEnumerable<string>? Errors { get; init; }
}

public record ValidateResetTokenResultDto
{
    public bool IsValid { get; init; }
}

// Two-Factor Authentication DTOs

public record TwoFactorLoginRequestDto
{
    public string Code { get; init; } = string.Empty;
    public bool RememberMachine { get; init; }
}

public record TwoFactorEmailLoginRequestDto
{
    public string Code { get; init; } = string.Empty;
    public bool RememberMachine { get; init; }
}

public record TwoFactorLoginResultDto
{
    public bool Success { get; init; }
    public string? RedirectUrl { get; init; }
    public string? ErrorMessage { get; init; }
}

public record RecoveryCodeLoginRequestDto
{
    public string RecoveryCode { get; init; } = string.Empty;
}

public record SendTwoFactorEmailResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

#endregion
