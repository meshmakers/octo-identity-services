using System.Security.Claims;
using System.Text.Json;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.Login;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for Angular SPA authentication operations
/// </summary>
[ApiController]
[Route("{tenantId}/api/auth")]
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public class AuthApiController(
    IIdentityServerInteractionService interaction,
    IAuthenticationSchemeProvider schemeProvider,
    IClientStore clientStore,
    SignInManager<RtUser> signInManager,
    UserManager<RtUser> userManager,
    IEventService events,
    IPersistedGrantStore persistedGrantStore,
    ILdapAuthenticationService ldapAuthService,
    ICrossTenantAuthenticationService crossTenantAuthService,
    IExternalTenantUserMappingStore externalTenantUserMappingStore,
    IOctoIdentityProviderStore identityProviderStore,
    ILoginGroupAssignmentService loginGroupAssignmentService,
    IDataProtectionProvider dataProtectionProvider,
    ICrossTenantUserProvisioningService crossTenantUserProvisioningService,
    IOptions<OctoSystemConfiguration> systemConfiguration,
    ILogger<AuthApiController> logger)
    : ControllerBase
{
    /// <summary>
    /// Get the login context for building the login UI
    /// </summary>
    [HttpGet("login-context")]
    public async Task<ActionResult<LoginContextDto>> GetLoginContext([FromQuery] string? returnUrl)
    {
        var context = await interaction.GetAuthorizationContextAsync(returnUrl, HttpContext.RequestAborted);
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var prefix = $"{tenantId}:";
        var schemes = await schemeProvider.GetAllSchemesAsync();

        // Build providers list with LDAP detection, filtered to this tenant's schemes
        var externalSchemes = schemes
            .Where(x => x.DisplayName != null && x.Name.StartsWith(prefix, StringComparison.Ordinal))
            .ToList();
        var providers = new List<ExternalProviderDto>();

        foreach (var scheme in externalSchemes)
        {
            var isLdap = await ldapAuthService.IsLdapSchemeAsync(scheme.Name);
            providers.Add(new ExternalProviderDto
            {
                Scheme = scheme.Name,
                DisplayName = scheme.DisplayName ?? scheme.Name,
                IsLdap = isLdap
            });
        }

        // Add parent tenant identity providers (OctoTenantIdentityProvider)
        var allIdentityProviders = await identityProviderStore.GetAllAsync();
        foreach (var idp in allIdentityProviders.OfType<RtOctoTenantIdentityProvider>())
        {
            if (idp.IsEnabled && !string.IsNullOrEmpty(idp.ParentTenantId))
            {
                providers.Add(new ExternalProviderDto
                {
                    Scheme = $"octo-tenant-{idp.ParentTenantId}",
                    DisplayName = idp.DisplayName ?? $"Login via {idp.ParentTenantId}",
                    IsLdap = false,
                    IsParentTenant = true
                });
            }
        }

        var allowLocal = true;
        string? clientName = null;
        string? clientLogoUrl = null;

        if (context?.Client.ClientId != null)
        {
            var client = await clientStore.FindEnabledClientByIdAsync(context.Client.ClientId, HttpContext.RequestAborted);
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

        var isSystemTenant = string.Equals(tenantId, systemConfiguration.Value.SystemTenantId, StringComparison.OrdinalIgnoreCase);
        var hasNoUsers = !userManager.Users.Any();
        var hasNoMappings = !(await externalTenantUserMappingStore.GetAllAsync(take: 1)).Any();

        return new LoginContextDto
        {
            ReturnUrl = returnUrl ?? string.Empty,
            ClientName = clientName,
            ClientLogoUrl = clientLogoUrl,
            ExternalProviders = providers,
            AllowRememberLogin = true,
            EnableLocalLogin = allowLocal,
            IsAuthenticated = isAuthenticated,
            Username = username,
            SetupRequired = isSystemTenant && hasNoUsers && hasNoMappings,
            TenantUnavailable = !isSystemTenant && hasNoUsers && hasNoMappings
        };
    }

    /// <summary>
    /// Process login credentials
    /// </summary>
    [HttpPost("login")]
    public async Task<ActionResult<LoginResultDto>> Login([FromBody] LoginRequestDto request)
    {
        var context = await interaction.GetAuthorizationContextAsync(request.ReturnUrl, HttpContext.RequestAborted);

        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Username and password are required"
            };
        }

        var result = await signInManager.PasswordSignInAsync(
            request.Username,
            request.Password,
            request.RememberLogin,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            var user = await userManager.FindByNameAsync(request.Username);
            await events.RaiseAsync(new UserLoginSuccessEvent(
                user?.UserName,
                user?.RtId.ToString(),
                user?.UserName,
                clientId: context?.Client.ClientId), HttpContext.RequestAborted);

            // Use return URL if valid, otherwise redirect to manage page
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            var redirectUrl = !string.IsNullOrEmpty(request.ReturnUrl) &&
                              (interaction.IsValidReturnUrl(request.ReturnUrl) || Url.IsLocalUrl(request.ReturnUrl))
                ? request.ReturnUrl
                : $"/{tenantId}/manage";

            return new LoginResultDto
            {
                Success = true,
                RedirectUrl = redirectUrl
            };
        }

        if (result.IsLockedOut)
        {
            await events.RaiseAsync(new UserLoginFailureEvent(
                request.Username, "Account locked out", clientId: context?.Client.ClientId), HttpContext.RequestAborted);

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
            var twoFactorUser = await signInManager.GetTwoFactorAuthenticationUserAsync();
            var canUseTotp = twoFactorUser != null &&
                !string.IsNullOrEmpty(await userManager.GetAuthenticatorKeyAsync(twoFactorUser));
            var canUseEmail = twoFactorUser != null &&
                await userManager.IsEmailConfirmedAsync(twoFactorUser);

            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication required",
                RequiresTwoFactor = true,
                CanUseTotpAuthenticator = canUseTotp,
                CanUseEmailCode = canUseEmail
            };
        }

        // Local auth failed — try cross-tenant authentication
        var tenantIdForCrossTenant = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var crossTenantResult = await crossTenantAuthService.AuthenticateAsync(
            tenantIdForCrossTenant, request.Username, request.Password);

        if (crossTenantResult != null)
        {
            // Check self-registration gate for cross-tenant providers
            var octoTenantProviders = (await identityProviderStore.GetAllAsync())
                .OfType<RtOctoTenantIdentityProvider>()
                .Where(p => p.IsEnabled && string.Equals(p.ParentTenantId, crossTenantResult.SourceTenantId, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var octoTenantProvider = octoTenantProviders.FirstOrDefault();

            // Check if this is a new user (no existing local account)
            var crossTenantUserName = $"xt_{crossTenantResult.SourceTenantId}_{crossTenantResult.SourceUserName}";
            var existingCrossTenantUser = await userManager.FindByNameAsync(crossTenantUserName);

            if (existingCrossTenantUser == null && octoTenantProvider is { AllowSelfRegistration: false })
            {
                logger.LogWarning("Self-registration denied for cross-tenant user '{UserName}' from tenant '{SourceTenant}'",
                    crossTenantResult.SourceUserName, crossTenantResult.SourceTenantId);

                return new LoginResultDto
                {
                    Success = false,
                    ErrorMessage = "Self-registration is not allowed for this provider"
                };
            }

            // Cross-tenant auth succeeded — create or find a local user for the session
            var isNewUser = existingCrossTenantUser == null;
            var localUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(crossTenantResult, tenantIdForCrossTenant);
            if (localUser != null)
            {
                // Assign groups for newly created users
                if (isNewUser)
                {
                    await loginGroupAssignmentService.AssignGroupsAsync(localUser, octoTenantProvider);
                }

                await signInManager.SignInAsync(localUser, request.RememberLogin);

                await events.RaiseAsync(new UserLoginSuccessEvent(
                    localUser.UserName,
                    localUser.RtId.ToString(),
                    localUser.UserName,
                    clientId: context?.Client.ClientId), HttpContext.RequestAborted);

                var redirectUrl = !string.IsNullOrEmpty(request.ReturnUrl) &&
                                  (interaction.IsValidReturnUrl(request.ReturnUrl) || Url.IsLocalUrl(request.ReturnUrl))
                    ? request.ReturnUrl
                    : $"/{tenantIdForCrossTenant}/manage";

                return new LoginResultDto
                {
                    Success = true,
                    RedirectUrl = redirectUrl
                };
            }
        }

        await events.RaiseAsync(new UserLoginFailureEvent(
            request.Username,
            "Invalid credentials",
            clientId: context?.Client.ClientId), HttpContext.RequestAborted);

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
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var prefix = $"{tenantId}:";
        var schemes = await schemeProvider.GetAllSchemesAsync();
        var externalSchemes = schemes
            .Where(x => x.DisplayName != null && x.Name.StartsWith(prefix, StringComparison.Ordinal))
            .ToList();
        var providers = new List<ExternalProviderDto>();

        foreach (var scheme in externalSchemes)
        {
            var isLdap = await ldapAuthService.IsLdapSchemeAsync(scheme.Name);
            providers.Add(new ExternalProviderDto
            {
                Scheme = scheme.Name,
                DisplayName = scheme.DisplayName ?? scheme.Name,
                IsLdap = isLdap
            });
        }

        return providers;
    }

    /// <summary>
    /// Initiate external login - redirects to the external provider
    /// </summary>
    [HttpGet("external-login")]
    public IActionResult ExternalLogin([FromQuery] string scheme, [FromQuery] string? returnUrl)
    {
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";

        // OctoTenantIdentityProvider (cross-tenant) has no ASP.NET auth handler.
        // Cross-tenant login works via password entry on the login form, not via
        // external redirect. Redirect back to login if the client calls this by mistake.
        if (scheme.StartsWith("octo-tenant-", StringComparison.OrdinalIgnoreCase))
        {
            return Redirect($"/{tenantId}/login{(string.IsNullOrEmpty(returnUrl) ? "" : $"?returnUrl={Uri.EscapeDataString(returnUrl)}")}");
        }

        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(ExternalLoginCallback), new { tenantId }),
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
        // Default tenant ID for error handling
        const string defaultTenantId = "System";

        try
        {
            return await ExternalLoginCallbackInternal();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled exception in ExternalLoginCallback");
            return Redirect($"/{defaultTenantId}/error?error=External authentication failed");
        }
    }

    private async Task<IActionResult> ExternalLoginCallbackInternal()
    {
        // Get tenant ID early for error handling
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";

        // 1. Authenticate from external cookie
        AuthenticateResult result;
        try
        {
            result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "External authentication threw exception");
            return Redirect($"/{tenantId}/error?error=External authentication failed");
        }

        if (!result.Succeeded)
        {
            logger.LogWarning("External authentication failed: {Error}", result.Failure?.Message);
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
            logger.LogWarning("External login missing required claims. Provider: {Provider}, UserIdClaim: {UserIdClaim}",
                provider, userIdClaim?.Value);
            return Redirect($"/{tenantId}/error?error=Invalid external login - missing required claims");
        }

        logger.LogInformation("Processing external login callback for provider {Provider}, user {UserId}",
            provider, userIdClaim.Value);

        // Log all claims for debugging
        logger.LogDebug("External provider claims received:");
        foreach (var claim in claims)
        {
            logger.LogDebug("  Claim: {Type} = {Value}", claim.Type, claim.Value);
        }

        // 3. Find existing user by external login
        var user = await userManager.FindByLoginAsync(provider, userIdClaim.Value);

        if (user == null)
        {
            // 4a. Look up the identity provider to check self-registration
            var providerName = provider.Contains(':') ? provider.Split(':', 2)[1] : provider;
            var rtIdentityProvider = await identityProviderStore.GetByNameAsync(providerName);

            // 4b. Check AllowSelfRegistration
            if (rtIdentityProvider is { AllowSelfRegistration: false })
            {
                logger.LogWarning("Self-registration denied for provider {Provider}, user {UserId}",
                    provider, userIdClaim.Value);
                await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
                return Redirect($"/{tenantId}/error?error=Self-registration is not allowed for this provider");
            }

            // 4c. Create new user from external provider claims.
            // SECURITY: We intentionally do NOT auto-link external logins to existing users
            // found by email. An attacker could register a Google/Microsoft account with the
            // same email as an existing local user and inherit their roles and permissions.
            // Instead, each external provider login always creates a dedicated external user.
            user = await CreateUserFromExternalProvider(claims, provider);
            if (user == null)
            {
                return Redirect($"/{tenantId}/error?error=Failed to create user account");
            }

            logger.LogInformation("Created new user {UserName} from external provider {Provider}",
                user.UserName, provider);

            // 5. Link external login to user
            var addLoginResult = await userManager.AddLoginAsync(
                user,
                new UserLoginInfo(provider, userIdClaim.Value, provider));

            if (!addLoginResult.Succeeded)
            {
                logger.LogError("Failed to add external login for user {UserName}: {Errors}",
                    user.UserName,
                    string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
            }
            else
            {
                logger.LogInformation("Linked external login {Provider} to user {UserName}",
                    provider, user.UserName);
            }

            // 6. Assign groups based on provider config and email domain rules (first login only)
            await loginGroupAssignmentService.AssignGroupsAsync(user, rtIdentityProvider);
        }

        // 7. Sync external identity group claims (e.g., AD groups) on every login
        await loginGroupAssignmentService.SyncExternalGroupClaimsAsync(user, claims);

        // 8. Sign in the user
        await signInManager.SignInAsync(user, isPersistent: false);

        await events.RaiseAsync(new UserLoginSuccessEvent(
            user.UserName,
            user.RtId.ToString(),
            user.UserName,
            clientId: null), HttpContext.RequestAborted);

        // 7. Clean up external cookie
        await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        // 8. Handle return URL
        if (interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        return Redirect($"/{tenantId}/manage");
    }

    /// <summary>
    /// Creates a new dedicated user from external provider claims.
    /// Each external provider login creates its own user account. This prevents privilege
    /// escalation where an external identity could inherit roles of an existing local user
    /// with the same email address.
    /// </summary>
    private async Task<RtUser?> CreateUserFromExternalProvider(List<Claim> claims, string provider)
    {
        // Try multiple claim types (different providers use different formats)
        var email = GetEmailFromClaims(claims);
        var givenName = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value
                        ?? claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
        var surname = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value
                      ?? claims.FirstOrDefault(c => c.Type == "family_name")?.Value;

        // Generate a unique username that includes the provider type to avoid collisions
        // with local users or users from other providers. Strip the tenant prefix from
        // tenant-scoped scheme names (e.g., "octosystem:Google" → "Google").
        var providerName = provider.Contains(':') ? provider.Split(':', 2)[1] : provider;
        var userName = !string.IsNullOrEmpty(email)
            ? $"{providerName}_{email}"
            : $"{providerName}_{Guid.NewGuid():N}";

        // Ensure username is unique (handles edge cases like same email across providers)
        var existingUser = await userManager.FindByNameAsync(userName);
        if (existingUser != null)
        {
            userName = $"{userName}_{Guid.NewGuid().ToString("N")[..8]}";
        }

        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email?.ToUpperInvariant(),
            EmailConfirmed = email != null, // Trust external provider's email verification
            FirstName = givenName ?? string.Empty,
            LastName = surname ?? string.Empty,
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var result = await userManager.CreateAsync(user);

        if (!result.Succeeded)
        {
            logger.LogError("Failed to create user from external provider {Provider}: {Errors}",
                provider,
                string.Join(", ", result.Errors.Select(e => e.Description)));
            return null;
        }

        return user;
    }

    /// <summary>
    /// Extracts email from claims, trying multiple claim types used by different providers
    /// </summary>
    private static string? GetEmailFromClaims(List<Claim> claims)
    {
        // Try standard email claims first
        var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value
                    ?? claims.FirstOrDefault(c => c.Type == "email")?.Value;

        if (!string.IsNullOrEmpty(email))
            return email;

        // Azure Entra ID often uses UPN (User Principal Name) as email
        var upn = claims.FirstOrDefault(c => c.Type == ClaimTypes.Upn)?.Value
                  ?? claims.FirstOrDefault(c => c.Type == "upn")?.Value;

        if (!string.IsNullOrEmpty(upn) && upn.Contains('@'))
            return upn;

        // Fallback to preferred_username if it looks like an email
        var preferredUsername = claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
        if (!string.IsNullOrEmpty(preferredUsername) && preferredUsername.Contains('@'))
            return preferredUsername;

        return null;
    }

    /// <summary>
    /// Get the logout context
    /// </summary>
    [HttpGet("logout-context")]
    public async Task<ActionResult<LogoutContextDto>> GetLogoutContext([FromQuery] string? logoutId)
    {
        var context = await interaction.GetLogoutContextAsync(logoutId, HttpContext.RequestAborted);

        return new LogoutContextDto
        {
            LogoutId = logoutId ?? string.Empty,
            ShowLogoutPrompt = context.ShowSignoutPrompt,
            PostLogoutRedirectUri = context.PostLogoutRedirectUri,
            ClientName = context.ClientName
        };
    }

    /// <summary>
    /// Process logout
    /// </summary>
    [HttpPost("logout")]
    public async Task<ActionResult<LogoutResultDto>> Logout([FromBody] LogoutRequestDto request)
    {
        var context = await interaction.GetLogoutContextAsync(request.LogoutId, HttpContext.RequestAborted);

        if (User.Identity?.IsAuthenticated == true)
        {
            var subjectId = User.GetSubjectId();

            // Revoke all persisted grants (refresh tokens, etc.) for this user
            // This ensures that clients cannot use refresh tokens after logout
            await persistedGrantStore.RemoveAllAsync(new PersistedGrantFilter
            {
                SubjectId = subjectId
            }, HttpContext.RequestAborted);

            await signInManager.SignOutAsync();

            // Also sign out from the IdentityServer session cookie scheme ("idsrv").
            // signInManager.SignOutAsync() only clears the Identity.Application cookie,
            // but the idsrv cookie maintains the SSO session. Without clearing it,
            // clients redirecting back will get a new authorization code automatically.
            await HttpContext.SignOutAsync(IdentityServerConstants.DefaultCookieAuthenticationScheme);

            await events.RaiseAsync(new UserLogoutSuccessEvent(
                subjectId,
                User.GetDisplayName()), HttpContext.RequestAborted);
        }

        return new LogoutResultDto
        {
            Success = true,
            PostLogoutRedirectUri = context.PostLogoutRedirectUri,
            ClientName = context.ClientName,
            SignOutIframeUrl = context.SignOutIFrameUrl,
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

        var user = await userManager.FindByEmailAsync(request.Email);

        // Always return success to prevent email enumeration attacks
        if (user == null)
        {
            return new ForgotPasswordResultDto { Success = true };
        }

        // Generate password reset token
        var token = await userManager.GeneratePasswordResetTokenAsync(user);

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

        var user = await userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            // Don't reveal that the user doesn't exist
            return new ResetPasswordResultDto
            {
                Success = false,
                ErrorMessage = "Invalid reset token"
            };
        }

        var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

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

        var user = await userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return new ValidateResetTokenResultDto { IsValid = false };
        }

        // Verify the token is valid
        var isValid = await userManager.VerifyUserTokenAsync(
            user,
            userManager.Options.Tokens.PasswordResetTokenProvider,
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
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication session expired. Please login again."
            };
        }

        var authenticatorCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await signInManager.TwoFactorAuthenticatorSignInAsync(
            authenticatorCode,
            isPersistent: false,
            rememberClient: request.RememberMachine);

        if (result.Succeeded)
        {
            await events.RaiseAsync(new UserLoginSuccessEvent(
                user.UserName,
                user.RtId.ToString(),
                user.UserName,
                clientId: null), HttpContext.RequestAborted);

            // Use the return URL from request, or default to manage page
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            var redirectUrl = !string.IsNullOrEmpty(request.ReturnUrl) &&
                              (interaction.IsValidReturnUrl(request.ReturnUrl) || Url.IsLocalUrl(request.ReturnUrl))
                ? request.ReturnUrl
                : $"/{tenantId}/manage";

            return new TwoFactorLoginResultDto
            {
                Success = true,
                RedirectUrl = redirectUrl
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

        await events.RaiseAsync(new UserLoginFailureEvent(
            user.UserName,
            "Invalid two-factor code",
            clientId: null), HttpContext.RequestAborted);

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
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication session expired. Please login again."
            };
        }

        var emailCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await signInManager.TwoFactorSignInAsync(
            TokenOptions.DefaultEmailProvider,
            emailCode,
            isPersistent: false,
            rememberClient: request.RememberMachine);

        if (result.Succeeded)
        {
            await events.RaiseAsync(new UserLoginSuccessEvent(
                user.UserName,
                user.RtId.ToString(),
                user.UserName,
                clientId: null), HttpContext.RequestAborted);

            // Use the return URL from request, or default to manage page
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            var redirectUrl = !string.IsNullOrEmpty(request.ReturnUrl) &&
                              (interaction.IsValidReturnUrl(request.ReturnUrl) || Url.IsLocalUrl(request.ReturnUrl))
                ? request.ReturnUrl
                : $"/{tenantId}/manage";

            return new TwoFactorLoginResultDto
            {
                Success = true,
                RedirectUrl = redirectUrl
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

        await events.RaiseAsync(new UserLoginFailureEvent(
            user.UserName,
            "Invalid two-factor email code",
            clientId: null), HttpContext.RequestAborted);

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
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
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

        var code = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

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
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication session expired. Please login again."
            };
        }

        var recoveryCode = request.RecoveryCode.Replace(" ", string.Empty).Replace("-", string.Empty);

        var result = await signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

        if (result.Succeeded)
        {
            await events.RaiseAsync(new UserLoginSuccessEvent(
                user.UserName,
                user.RtId.ToString(),
                user.UserName,
                clientId: null), HttpContext.RequestAborted);

            // Use the return URL from request, or default to manage page
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            var redirectUrl = !string.IsNullOrEmpty(request.ReturnUrl) &&
                              (interaction.IsValidReturnUrl(request.ReturnUrl) || Url.IsLocalUrl(request.ReturnUrl))
                ? request.ReturnUrl
                : $"/{tenantId}/manage";

            return new TwoFactorLoginResultDto
            {
                Success = true,
                RedirectUrl = redirectUrl
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

        await events.RaiseAsync(new UserLoginFailureEvent(
            user.UserName,
            "Invalid recovery code",
            clientId: null), HttpContext.RequestAborted);

        return new TwoFactorLoginResultDto
        {
            Success = false,
            ErrorMessage = "Invalid recovery code"
        };
    }

    #endregion

    #region LDAP Authentication

    /// <summary>
    /// Login with LDAP credentials (OpenLDAP or Microsoft AD)
    /// </summary>
    [HttpPost("ldap-login")]
    public async Task<ActionResult<LdapLoginResultDto>> LdapLogin([FromBody] LdapLoginRequestDto request)
    {
        // 1. Validate the scheme is an LDAP provider
        if (!await ldapAuthService.IsLdapSchemeAsync(request.Scheme))
        {
            return new LdapLoginResultDto
            {
                Success = false,
                ErrorMessage = "Invalid authentication scheme"
            };
        }

        // 2. Authenticate against LDAP
        var authResult = await ldapAuthService.AuthenticateAsync(
            request.Scheme,
            request.Username,
            request.Password);

        if (!authResult.Succeeded || authResult.LoginInfo == null)
        {
            await events.RaiseAsync(new UserLoginFailureEvent(
                request.Username,
                authResult.ErrorMessage ?? "LDAP authentication failed",
                clientId: null), HttpContext.RequestAborted);

            return new LdapLoginResultDto
            {
                Success = false,
                ErrorMessage = authResult.ErrorMessage ?? "Invalid username or password"
            };
        }

        var loginInfo = authResult.LoginInfo;
        var claims = loginInfo.Principal.Claims.ToList();

        // 3. Find existing user by external login
        var user = await userManager.FindByLoginAsync(
            loginInfo.LoginProvider,
            loginInfo.ProviderKey);

        if (user == null)
        {
            // 4a. Look up the identity provider to check self-registration
            var ldapProviderName = loginInfo.LoginProvider.Contains(':')
                ? loginInfo.LoginProvider.Split(':', 2)[1]
                : loginInfo.LoginProvider;
            var rtLdapProvider = await identityProviderStore.GetByNameAsync(ldapProviderName);

            // 4b. Check AllowSelfRegistration
            if (rtLdapProvider is { AllowSelfRegistration: false })
            {
                logger.LogWarning("Self-registration denied for LDAP provider {Provider}, user {UserName}",
                    loginInfo.LoginProvider, request.Username);
                return new LdapLoginResultDto
                {
                    Success = false,
                    ErrorMessage = "Self-registration is not allowed for this provider"
                };
            }

            // 4c. Create new user from LDAP info.
            // SECURITY: We intentionally do NOT auto-link LDAP logins to existing users
            // found by email. This prevents privilege escalation where an LDAP user could
            // inherit the roles of an existing local user with the same email address.
            user = await CreateUserFromExternalProvider(claims, loginInfo.LoginProvider);
            if (user == null)
            {
                return new LdapLoginResultDto
                {
                    Success = false,
                    ErrorMessage = "Failed to create user account"
                };
            }

            logger.LogInformation(
                "Created new user {UserName} from LDAP provider {Provider}",
                user.UserName, loginInfo.LoginProvider);

            // 5. Link LDAP login to user
            var addLoginResult = await userManager.AddLoginAsync(
                user,
                new UserLoginInfo(
                    loginInfo.LoginProvider,
                    loginInfo.ProviderKey,
                    loginInfo.ProviderDisplayName));

            if (!addLoginResult.Succeeded)
            {
                logger.LogError(
                    "Failed to add LDAP login for user {UserName}: {Errors}",
                    user.UserName,
                    string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
            }
            else
            {
                logger.LogInformation(
                    "Linked LDAP login {Provider} to user {UserName}",
                    loginInfo.LoginProvider, user.UserName);
            }

            // 6. Assign groups based on provider config and email domain rules (first login only)
            await loginGroupAssignmentService.AssignGroupsAsync(user, rtLdapProvider);
        }

        // 7. Sync external identity group claims (e.g., AD groups) on every login
        await loginGroupAssignmentService.SyncExternalGroupClaimsAsync(user, claims);

        // 8. Sign in the user
        await signInManager.SignInAsync(user, isPersistent: false);

        await events.RaiseAsync(new UserLoginSuccessEvent(
            user.UserName,
            user.RtId.ToString(),
            user.UserName,
            clientId: null), HttpContext.RequestAborted);

        // 7. Handle return URL
        var redirectUrl = request.ReturnUrl;
        if (string.IsNullOrEmpty(redirectUrl) ||
            !(interaction.IsValidReturnUrl(redirectUrl) || Url.IsLocalUrl(redirectUrl)))
        {
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            redirectUrl = $"/{tenantId}/manage";
        }

        return new LdapLoginResultDto
        {
            Success = true,
            RedirectUrl = redirectUrl
        };
    }

    /// <summary>
    /// Check if a scheme is an LDAP-based authentication provider
    /// </summary>
    [HttpGet("is-ldap-scheme")]
    public async Task<ActionResult<IsLdapSchemeResultDto>> IsLdapScheme([FromQuery] string scheme)
    {
        var isLdap = await ldapAuthService.IsLdapSchemeAsync(scheme);
        return new IsLdapSchemeResultDto { IsLdap = isLdap };
    }

    #endregion

    #region Cross-Tenant / Tenant Switch

    private const string CrossTenantLoginPurpose = "CrossTenantLogin";
    private static readonly TimeSpan CrossTenantTokenExpiry = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Generates a short-lived, encrypted token for cross-tenant auto-login.
    /// The caller must be authenticated in the current (parent) tenant.
    /// The token can be exchanged via cross-tenant-login on the target tenant.
    /// </summary>
    [HttpPost("cross-tenant-token")]
    public async Task<ActionResult<CrossTenantTokenResultDto>> GetCrossTenantToken(
        [FromBody] CrossTenantTokenRequestDto request)
    {
        var currentTenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var userId = User.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        // Validate that the current tenant is an ancestor of the target tenant
        var crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
            request.TargetTenantId, currentTenantId, userId);

        if (crossTenantResult == null)
        {
            return Forbid();
        }

        // Create a DataProtection-encrypted token
        var protector = dataProtectionProvider.CreateProtector(CrossTenantLoginPurpose);
        var payload = JsonSerializer.Serialize(new CrossTenantTokenPayload
        {
            SourceTenantId = currentTenantId,
            SourceUserId = userId,
            TargetTenantId = request.TargetTenantId,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        });
        var token = protector.Protect(payload);

        return new CrossTenantTokenResultDto { Token = token };
    }

    /// <summary>
    /// Exchanges a cross-tenant token for a session in the current (child) tenant.
    /// No authentication required — the token itself proves the caller's identity.
    /// </summary>
    [HttpPost("cross-tenant-login")]
    public async Task<ActionResult<LoginResultDto>> CrossTenantLogin(
        [FromBody] CrossTenantLoginRequestDto request)
    {
        var currentTenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";

        // Unprotect and validate the token
        CrossTenantTokenPayload payload;
        try
        {
            var protector = dataProtectionProvider.CreateProtector(CrossTenantLoginPurpose);
            var json = protector.Unprotect(request.Token);
            payload = JsonSerializer.Deserialize<CrossTenantTokenPayload>(json)!;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to unprotect cross-tenant login token");
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Invalid or expired cross-tenant token"
            };
        }

        // Validate expiry (60 seconds)
        var tokenAge = DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(payload.Timestamp);
        if (tokenAge > CrossTenantTokenExpiry)
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Cross-tenant token has expired"
            };
        }

        // Validate target tenant matches current route
        if (!string.Equals(payload.TargetTenantId, currentTenantId, StringComparison.OrdinalIgnoreCase))
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Token was issued for a different tenant"
            };
        }

        // Build CrossTenantAuthResult from validated token payload
        var crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
            currentTenantId, payload.SourceTenantId, payload.SourceUserId);

        if (crossTenantResult == null)
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Cross-tenant access denied"
            };
        }

        // Check self-registration gate for cross-tenant token login
        var tokenOctoTenantProviders = (await identityProviderStore.GetAllAsync())
            .OfType<RtOctoTenantIdentityProvider>()
            .Where(p => p.IsEnabled && string.Equals(p.ParentTenantId, payload.SourceTenantId, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var tokenOctoTenantProvider = tokenOctoTenantProviders.FirstOrDefault();

        var tokenCrossTenantUserName = $"xt_{crossTenantResult.SourceTenantId}_{crossTenantResult.SourceUserName}";
        var existingTokenUser = await userManager.FindByNameAsync(tokenCrossTenantUserName);

        if (existingTokenUser == null && tokenOctoTenantProvider is { AllowSelfRegistration: false })
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Self-registration is not allowed for this provider"
            };
        }

        // Find or create the local shadow user
        var isNewTokenUser = existingTokenUser == null;
        var localUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(crossTenantResult, currentTenantId);
        if (localUser == null)
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Failed to create local user in target tenant"
            };
        }

        // Assign groups for newly created users
        if (isNewTokenUser)
        {
            await loginGroupAssignmentService.AssignGroupsAsync(localUser, tokenOctoTenantProvider);
        }

        // Sign in
        await signInManager.SignInAsync(localUser, isPersistent: false);

        await events.RaiseAsync(new UserLoginSuccessEvent(
            localUser.UserName,
            localUser.RtId.ToString(),
            localUser.UserName,
            clientId: null), HttpContext.RequestAborted);

        // Compute redirect URL
        var redirectUrl = request.ReturnUrl;
        if (string.IsNullOrEmpty(redirectUrl) ||
            !(interaction.IsValidReturnUrl(redirectUrl) || Url.IsLocalUrl(redirectUrl)))
        {
            redirectUrl = $"/{currentTenantId}/manage";
        }

        return new LoginResultDto
        {
            Success = true,
            RedirectUrl = redirectUrl
        };
    }

    /// <summary>
    /// Returns child tenants where the current user has role mappings.
    /// The user must be authenticated.
    /// </summary>
    [HttpGet("accessible-tenants")]
    public async Task<ActionResult<List<AccessibleTenantDto>>> GetAccessibleTenants()
    {
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var userId = User.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized();
        }

        // Get all mappings in the current tenant that point to this user's home tenant
        var homeTenantId = User.FindFirst("home_tenant_id")?.Value ?? tenantId;
        var mappings = await externalTenantUserMappingStore.GetBySourceTenantAsync(homeTenantId);

        // For each mapping where the source user matches, return the tenant info
        var accessibleTenants = new List<AccessibleTenantDto>();
        foreach (var mapping in mappings)
        {
            if (mapping.SourceUserId == userId || mapping.SourceUserName == User.Identity?.Name)
            {
                accessibleTenants.Add(new AccessibleTenantDto
                {
                    TenantId = tenantId,
                    Roles = mapping.MappedRoleIds?.ToList() ?? []
                });
            }
        }

        return accessibleTenants;
    }

    /// <summary>
    /// Switches the current user's session to the target tenant without re-entering credentials.
    /// Validates that the current user's home tenant is an ancestor of the target tenant.
    /// </summary>
    [HttpPost("tenant-switch")]
    public async Task<ActionResult<TenantSwitchResultDto>> SwitchTenant(
        [FromBody] TenantSwitchRequestDto request)
    {
        var targetTenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var currentUserId = User.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(currentUserId))
        {
            return Unauthorized();
        }

        var sourceTenantId = request.SourceTenantId;
        var sourceUserId = request.SourceUserId ?? currentUserId;

        var crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
            targetTenantId, sourceTenantId, sourceUserId);

        if (crossTenantResult == null)
        {
            return new TenantSwitchResultDto
            {
                Success = false,
                ErrorMessage = "Access to target tenant denied"
            };
        }

        // Find or create a local user in the target tenant
        var localUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(crossTenantResult, targetTenantId);
        if (localUser == null)
        {
            return new TenantSwitchResultDto
            {
                Success = false,
                ErrorMessage = "Failed to create local user in target tenant"
            };
        }

        // Sign in as the local user
        await signInManager.SignInAsync(localUser, isPersistent: false);

        // Get the roles for the response
        var roles = await userManager.GetRolesAsync(localUser);

        return new TenantSwitchResultDto
        {
            Success = true,
            TenantId = targetTenantId,
            Roles = roles.ToList()
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
    public bool SetupRequired { get; init; }
    public bool TenantUnavailable { get; init; }
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
    public bool IsLdap { get; init; }
    public bool IsParentTenant { get; init; }
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
    public string? ReturnUrl { get; init; }
}

public record TwoFactorEmailLoginRequestDto
{
    public string Code { get; init; } = string.Empty;
    public bool RememberMachine { get; init; }
    public string? ReturnUrl { get; init; }
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
    public string? ReturnUrl { get; init; }
}

public record SendTwoFactorEmailResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

// LDAP Authentication DTOs

public record LdapLoginRequestDto
{
    public string Scheme { get; init; } = string.Empty;
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string? ReturnUrl { get; init; }
}

public record LdapLoginResultDto
{
    public bool Success { get; init; }
    public string? RedirectUrl { get; init; }
    public string? ErrorMessage { get; init; }
}

public record IsLdapSchemeResultDto
{
    public bool IsLdap { get; init; }
}

// Cross-Tenant / Tenant Switch DTOs

public record CrossTenantTokenRequestDto
{
    public string TargetTenantId { get; init; } = string.Empty;
}

public record CrossTenantTokenResultDto
{
    public string Token { get; init; } = string.Empty;
}

public record CrossTenantLoginRequestDto
{
    public string Token { get; init; } = string.Empty;
    public string? ReturnUrl { get; init; }
}

internal record CrossTenantTokenPayload
{
    public string SourceTenantId { get; init; } = string.Empty;
    public string SourceUserId { get; init; } = string.Empty;
    public string TargetTenantId { get; init; } = string.Empty;
    public long Timestamp { get; init; }
}

public record AccessibleTenantDto
{
    public string TenantId { get; init; } = string.Empty;
    public string? TenantName { get; init; }
    public List<string> Roles { get; init; } = [];
}

public record TenantSwitchRequestDto
{
    public string SourceTenantId { get; init; } = string.Empty;
    public string? SourceUserId { get; init; }
}

public record TenantSwitchResultDto
{
    public bool Success { get; init; }
    public string? TenantId { get; init; }
    public List<string>? Roles { get; init; }
    public string? ErrorMessage { get; init; }
}

#endregion
