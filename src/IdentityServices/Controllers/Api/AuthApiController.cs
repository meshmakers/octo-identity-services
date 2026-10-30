using System.Security.Claims;
using System.Text.Json;
using Meshmakers.Common.Shared;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.Login;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.Authentication.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
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
    IOctoInteractionService interaction,
    IAuthenticationSchemeProvider schemeProvider,
    IOctoClientStore clientStore,
    SignInManager<RtUser> signInManager,
    UserManager<RtUser> userManager,
    IIdentityAuditService auditService,
    global::OpenIddict.Abstractions.IOpenIddictTokenStore<RtOAuthToken> oauthTokenStore,
    ILdapAuthenticationService ldapAuthService,
    ICrossTenantAuthenticationService crossTenantAuthService,
    IExternalTenantUserMappingStore externalTenantUserMappingStore,
    IOctoIdentityProviderStore identityProviderStore,
    ILoginGroupAssignmentService loginGroupAssignmentService,
    IEntraIdVerifiedIdentifierEnrollmentService entraIdVerifiedIdentifierEnrollmentService,
    IDataProtectionProvider dataProtectionProvider,
    ICrossTenantUserProvisioningService crossTenantUserProvisioningService,
    ICrossTenantSecondFactorVerifier crossTenantSecondFactorVerifier,
    ICrossTenantShadowUserChainResolver shadowUserChainResolver,
    IOptionsMonitor<CookieAuthenticationOptions> cookieOptions,
    IOptions<OctoSystemConfiguration> systemConfiguration,
    IUserCredentialChangeService userCredentialChangeService,
    ICrossTenantChallengeReplayGuard crossTenantChallengeReplayGuard,
    ILogger<AuthApiController> logger)
    : ControllerBase
{
    private string? GetSubjectId() =>
        User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

    /// <summary>Login success audit — log-only, matching the previous event-sink behavior.</summary>
    private void LogLoginSuccess(string? username, string? subjectId, string? displayName, string? clientId = null)
    {
        logger.LogInformation(
            "User login succeeded: user '{Username}' (sub '{SubjectId}', display '{DisplayName}', client '{ClientId}')",
            username, subjectId, displayName, clientId ?? "(none)");
    }

    /// <summary>Login failure audit — persisted to the runtime event log (event-sink parity).</summary>
    private async Task LogLoginFailureAsync(string? username, string reason, string? clientId = null)
    {
        logger.LogWarning("User login failed: user '{Username}' ({Reason}, client '{ClientId}')",
            username, reason, clientId ?? "(none)");
        await auditService.StoreFailureAsync("User Login Failure",
            $"Username: {username} - {reason}");
    }

    /// <summary>
    /// Get the login context for building the login UI
    /// </summary>
    [HttpGet("login-context")]
    public async Task<ActionResult<LoginContextDto>> GetLoginContext([FromQuery] string? returnUrl)
    {
        var context = await interaction.GetAuthorizationContextAsync(returnUrl);
        // Normalize the route-derived tenant id: schemes are registered with the lower-cased
        // tenant id (DynamicAuthSchemeServiceInitializer → systemContext.TenantId), but the URL
        // path segment can be PascalCase (e.g. /OctoSystem/login when the system tenant config
        // uses PascalCase). Without NormalizeString the case-sensitive StartsWith below would
        // miss every scheme and the login picker would show nothing. ADO #4199 Bug 3.
        var tenantId = (RouteData.Values["tenantId"]?.ToString() ?? "System").NormalizeString();
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

        if (context != null)
        {
            var client = context.Client;
            allowLocal = client.EnableLocalLogin;
            clientName = client.ClientName ?? client.ClientId;
            clientLogoUrl = client.LogoUri;

            if (client.IdentityProviderRestrictions?.Any() == true)
            {
                providers = providers
                    .Where(p => client.IdentityProviderRestrictions.Contains(p.Scheme))
                    .ToList();
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
    ///     Resolves the opaque <c>errorId</c> that IdentityServer puts on its error redirect into
    ///     something the error page can actually show, and — where it is safe — a way back to the
    ///     application the user came from.
    /// </summary>
    /// <remarks>
    ///     Without this the page only ever renders "An unexpected error occurred": it reads
    ///     <c>?error</c>/<c>?errorDescription</c>, which only the external-login callback produces,
    ///     while the authorize endpoint redirects with <c>?errorId</c>.
    ///     <para>
    ///         The back-link is taken from the registered client's <c>ClientUri</c> and never from
    ///         the <c>redirect_uri</c> of the failed request: the two cases that land here are
    ///         precisely "this client could not be validated" and "this redirect_uri is not
    ///         registered", so echoing the caller-supplied address as a link would turn this page
    ///         into an open redirect on the identity domain.
    ///     </para>
    ///     <para>
    ///         The classification is done by looking the client up, not by matching the English
    ///         error description — <c>unauthorized_client</c> is also emitted for unrelated causes.
    ///         The lookup stays inside the route tenant; whether the client exists in some other
    ///         tenant is deliberately not revealed.
    ///     </para>
    /// </remarks>
    [HttpGet("error-context")]
    public async Task<ActionResult<ErrorContextDto>> GetErrorContext([FromQuery] string? errorId)
    {
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? string.Empty;

        var message = string.IsNullOrWhiteSpace(errorId)
            ? null
            : interaction.GetErrorContext(errorId);

        if (message == null)
        {
            // An expired or unknown id is not an error of its own — the page still has to render.
            return new ErrorContextDto { Kind = ErrorContextKinds.Unknown, TenantId = tenantId };
        }

        RtClient? client = null;
        if (!string.IsNullOrWhiteSpace(message.ClientId))
        {
            var candidate = await clientStore.FindRtClientByIdAsync(message.ClientId);
            client = candidate is { Enabled: true } ? candidate : null;
        }

        var kind = ClassifyError(message, client);

        return new ErrorContextDto
        {
            Kind = kind,
            Error = message.Error,
            ErrorDescription = message.ErrorDescription,
            RequestId = message.RequestId,
            TenantId = tenantId,
            ClientId = message.ClientId,
            ClientName = client?.ClientName ?? message.ClientId,
            // Only the administratively configured client URI is a safe link target.
            ClientUrl = string.IsNullOrWhiteSpace(client?.ClientUri) ? null : client.ClientUri,
            ClientLogoUrl = string.IsNullOrWhiteSpace(client?.LogoUri) ? null : client.LogoUri
        };
    }

    private static string ClassifyError(OctoErrorContext message, RtClient? client)
    {
        // A client id that no enabled client in this tenant answers to is a configuration state,
        // not a crash: the application is either not registered here or disabled. The two are
        // indistinguishable without a second query, so the copy names both.
        if (!string.IsNullOrWhiteSpace(message.ClientId) && client == null)
        {
            return ErrorContextKinds.ClientNotRegistered;
        }

        if (client != null
            && string.Equals(message.Error, "invalid_request", StringComparison.Ordinal)
            && message.ErrorDescription?.Contains("redirect_uri", StringComparison.OrdinalIgnoreCase) == true)
        {
            return ErrorContextKinds.InvalidRedirectUri;
        }

        return ErrorContextKinds.Generic;
    }

    private const string SecondFactorSetupRequiredMessage =
        "Your second factor must be set up again. Please contact your administrator.";

    /// <summary>
    /// AB#7830: true when the user has two-factor authentication enabled but no usable second factor.
    /// Only an authenticator key counts: the e-mail provider is valid for ASP.NET Identity once the address is
    /// confirmed, but its code is not delivered yet, and recovery codes only work after a challenge.
    /// The rule fails closed.
    /// </summary>
    private async Task<bool> IsSecondFactorUnusableAsync(RtUser user)
    {
        return await userManager.GetTwoFactorEnabledAsync(user)
               && string.IsNullOrEmpty(await userManager.GetAuthenticatorKeyAsync(user));
    }

    /// <summary>
    /// Process login credentials
    /// </summary>
    [HttpPost("login")]
    public async Task<ActionResult<LoginResultDto>> Login([FromBody] LoginRequestDto request)
    {
        var context = await interaction.GetAuthorizationContextAsync(request.ReturnUrl);

        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Username and password are required"
            };
        }

        // AB#7830: a user whose second factor is switched on but who has no authenticator key (e.g. after a
        // tenant clone, which does not export UserTokens) must never get a session with the password alone.
        // ASP.NET Identity challenges only when a provider is valid, so PasswordSignInAsync would sign such a
        // user in without any second factor. The password is verified without issuing a cookie first; a correct
        // password is refused, anything else follows the normal failure path (lockout counted exactly once).
        var candidateUser = await userManager.FindByNameAsync(request.Username);
        Microsoft.AspNetCore.Identity.SignInResult result;
        if (candidateUser != null && await IsSecondFactorUnusableAsync(candidateUser))
        {
            result = await signInManager.CheckPasswordSignInAsync(candidateUser, request.Password, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                await LogLoginFailureAsync(request.Username,
                    "Second factor is enabled but no authenticator is set up; sign-in refused",
                    clientId: context?.Client.ClientId);

                return new LoginResultDto
                {
                    Success = false,
                    ErrorMessage = SecondFactorSetupRequiredMessage,
                    SecondFactorSetupRequired = true
                };
            }
        }
        else
        {
            result = await signInManager.PasswordSignInAsync(
                request.Username,
                request.Password,
                request.RememberLogin,
                lockoutOnFailure: true);
        }

        if (result.Succeeded)
        {
            // AB#7861: a successful local sign-in voids a pending cross-tenant challenge of this browser.
            DeleteCrossTenantTwoFactorChallenge();
            var user = candidateUser ?? await userManager.FindByNameAsync(request.Username);
            LogLoginSuccess(user?.UserName, user?.RtId.ToString(), user?.UserName, clientId: context?.Client.ClientId);

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
            await LogLoginFailureAsync(request.Username, "Account locked out", clientId: context?.Client.ClientId);

            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Account is locked out",
                IsLockedOut = true
            };
        }

        if (result.RequiresTwoFactor)
        {
            // A local 2FA challenge replaces any pending cross-tenant one (AB#7804).
            DeleteCrossTenantTwoFactorChallenge();

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
            if (crossTenantResult.SourceUserRequiresSecondFactor)
            {
                // AB#7804: the password proves only the first factor of the SOURCE user. No session in this
                // tenant before that user's second factor is verified (login-2fa / login-2fa-email /
                // login-recovery, against the source tenant). The self-registration gate is judged first, so a
                // user who may not enter this tenant anyway is not asked for a code.
                if (await CheckCrossTenantSelfRegistrationAsync(crossTenantResult) is { } denied)
                {
                    return new LoginResultDto { Success = false, ErrorMessage = denied };
                }

                var options = await crossTenantSecondFactorVerifier.GetOptionsAsync(
                    crossTenantResult.SourceTenantId, crossTenantResult.SourceUserId);
                if (options is { CanUseAuthenticator: false })
                {
                    // AB#7830: the source user has two-factor enabled but no authenticator key (e.g. after a tenant
                    // clone). Only an authenticator counts as usable, so the password alone must not open a session
                    // here either. Fails closed; recovery is an admin switching 2FA off in the source tenant.
                    await LogLoginFailureAsync(request.Username,
                        "Second factor is enabled but no authenticator is set up for the source user; sign-in refused",
                        clientId: context?.Client.ClientId);
                    return new LoginResultDto
                    {
                        Success = false,
                        ErrorMessage = SecondFactorSetupRequiredMessage,
                        SecondFactorSetupRequired = true
                    };
                }

                if (options != null)
                {
                    // A pending local 2FA challenge (framework cookie) would otherwise win in login-2fa and check the
                    // code against that local user.
                    await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
                    IssueCrossTenantTwoFactorChallenge(crossTenantResult, tenantIdForCrossTenant, request.RememberLogin);
                    return new LoginResultDto
                    {
                        Success = false,
                        ErrorMessage = "Two-factor authentication required",
                        RequiresTwoFactor = true,
                        CanUseTotpAuthenticator = options.CanUseAuthenticator,
                        CanUseEmailCode = options.CanUseEmail
                    };
                }
            }
            else
            {
                var signIn = await SignInCrossTenantUserAsync(crossTenantResult, tenantIdForCrossTenant,
                    request.RememberLogin, secondFactorVerified: false, clientId: context?.Client.ClientId);
                if (signIn.Error != null)
                {
                    return new LoginResultDto { Success = false, ErrorMessage = signIn.Error };
                }

                if (signIn.User != null)
                {
                    return new LoginResultDto
                    {
                        Success = true,
                        RedirectUrl = ResolveRedirectUrl(request.ReturnUrl, tenantIdForCrossTenant)
                    };
                }
            }
        }

        await LogLoginFailureAsync(request.Username, "Invalid credentials", clientId: context?.Client.ClientId);

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
        // See GetLoginContext above — schemes are registered lower-cased, the route segment may
        // be PascalCase. Normalize to avoid an empty picker on /OctoSystem/api/auth/...
        var tenantId = (RouteData.Values["tenantId"]?.ToString() ?? "System").NormalizeString();
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
            result = await HttpContext.AuthenticateAsync(OctoAuthSchemes.ExternalCookieScheme);
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
                await HttpContext.SignOutAsync(OctoAuthSchemes.ExternalCookieScheme);
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

        // 7b. Enroll the EntraID object id as a verified identifier so the mesh adapter can resolve
        // a Teams sender's aadObjectId to this user (AB#5124). No-op for non-EntraID providers.
        await entraIdVerifiedIdentifierEnrollmentService.EnrollFromExternalLoginAsync(user, provider, claims);

        // 8. Sign in the user
        await signInManager.SignInAsync(user, isPersistent: false);

        LogLoginSuccess(user.UserName, user.RtId.ToString(), user.UserName, clientId: null);

        // 7. Clean up external cookie
        await HttpContext.SignOutAsync(OctoAuthSchemes.ExternalCookieScheme);

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

        // Provider names are free-text (admin-defined) and may contain spaces or other
        // characters that ASP.NET Identity's UserValidator rejects (only letters, digits
        // and a small set of symbols are allowed). Because the provider label is embedded
        // in the generated user name, an Entra/AD/OIDC provider named e.g. "Microsoft Entra ID"
        // would make UserManager.CreateAsync fail with InvalidUserName, surfacing to the user
        // as "Failed to create user account". Sanitize the label to letters/digits so the
        // generated user name is always valid regardless of how the provider was named.
        var safeProviderName = SanitizeUserNameComponent(providerName);
        if (string.IsNullOrEmpty(safeProviderName))
        {
            safeProviderName = "External";
        }

        // The xt_ prefix is reserved for cross-tenant shadow users, whose name is trusted to unwind
        // to the person's home identity (AB#5708). A provider named "xt" or "xt_<tenant>" must not
        // mint a local user that impersonates such a chain — move it out of the reserved namespace.
        if (CrossTenantShadowUserName.IsShadowUserName($"{safeProviderName}_"))
        {
            safeProviderName = $"External_{safeProviderName}";
        }

        var userName = !string.IsNullOrEmpty(email)
            ? $"{safeProviderName}_{email}"
            : $"{safeProviderName}_{Guid.NewGuid():N}";

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
    /// Reduces a free-text component (typically an identity-provider name) to characters
    /// that are safe to embed in an ASP.NET Identity user name — ASCII letters, digits and
    /// the separators <c>. _ -</c>, all of which are part of the default
    /// <see cref="UserOptions.AllowedUserNameCharacters"/> set. Everything the validator
    /// would reject (spaces, parentheses, non-ASCII letters, …) is stripped. This is the
    /// login-time safety net; <c>IdentityProvidersController</c> rejects such names at
    /// configuration time so operators get immediate feedback instead of a broken login.
    /// </summary>
    internal static string SanitizeUserNameComponent(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return new string(value.Where(c =>
            c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-').ToArray());
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
        var context = interaction.GetLogoutContext(logoutId);

        return new LogoutContextDto
        {
            LogoutId = logoutId ?? string.Empty,
            // A logout initiated by a validated client request needs no prompt — the client
            // already expressed the user's intent; a user-initiated logout (no logoutId context)
            // asks for confirmation.
            ShowLogoutPrompt = context == null,
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
        var context = interaction.GetLogoutContext(request.LogoutId);

        string? signOutIframeUrl = null;
        if (User.Identity?.IsAuthenticated == true)
        {
            var subjectId = GetSubjectId();
            var sessionId = User.FindFirstValue("sid") ?? context?.SessionId;

            // Revoke all OAuth tokens (refresh tokens, pending codes) for this user so clients
            // cannot silently keep access after logout — logout must end the grant, not just the
            // browser session.
            if (!string.IsNullOrEmpty(subjectId))
            {
                await oauthTokenStore.RevokeBySubjectAsync(subjectId, HttpContext.RequestAborted);
            }

            await signInManager.SignOutAsync();

            logger.LogInformation("User '{SubjectId}' logged out", subjectId);

            // Front-channel logout: notify clients that registered a FrontChannelLogoutUri.
            signOutIframeUrl = $"/connect/endsession/callback?sid={Uri.EscapeDataString(sessionId ?? string.Empty)}";
        }

        // AB#7861: a pending cross-tenant second-factor challenge ends with the logout, signed in or not.
        DeleteCrossTenantTwoFactorChallenge();

        return new LogoutResultDto
        {
            Success = true,
            PostLogoutRedirectUri = context?.PostLogoutRedirectUri,
            ClientName = context?.ClientName,
            SignOutIframeUrl = signOutIframeUrl,
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
            await userCredentialChangeService.OnPasswordChangedAsync(user, PasswordChangePath.TokenResetPassword,
                null, HttpContext.RequestAborted);
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
            if (await TryCompleteCrossTenantTwoFactorAsync(SecondFactorCodeKind.Authenticator,
                    request.Code.Replace(" ", string.Empty).Replace("-", string.Empty), request.ReturnUrl,
                    "Invalid authenticator code") is { } crossTenant)
            {
                return crossTenant;
            }

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
            LogLoginSuccess(user.UserName, user.RtId.ToString(), user.UserName, clientId: null);

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

        await LogLoginFailureAsync(user.UserName, "Invalid two-factor code", clientId: null);

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
            if (await TryCompleteCrossTenantTwoFactorAsync(SecondFactorCodeKind.Email,
                    request.Code.Replace(" ", string.Empty).Replace("-", string.Empty), request.ReturnUrl,
                    "Invalid email verification code") is { } crossTenant)
            {
                return crossTenant;
            }

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
            LogLoginSuccess(user.UserName, user.RtId.ToString(), user.UserName, clientId: null);

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

        await LogLoginFailureAsync(user.UserName, "Invalid two-factor email code", clientId: null);

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
            if (ReadCrossTenantTwoFactorChallenge() is { } challenge)
            {
                return await crossTenantSecondFactorVerifier.GenerateEmailCodeAsync(
                    challenge.SourceTenantId, challenge.SourceUserId)
                    ? new SendTwoFactorEmailResultDto { Success = true }
                    : new SendTwoFactorEmailResultDto
                    {
                        Success = false,
                        ErrorMessage = "No email address associated with this account"
                    };
            }

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
            if (await TryCompleteCrossTenantTwoFactorAsync(SecondFactorCodeKind.RecoveryCode,
                    request.RecoveryCode.Replace(" ", string.Empty).Replace("-", string.Empty), request.ReturnUrl,
                    "Invalid recovery code") is { } crossTenant)
            {
                return crossTenant;
            }

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
            LogLoginSuccess(user.UserName, user.RtId.ToString(), user.UserName, clientId: null);

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

        await LogLoginFailureAsync(user.UserName, "Invalid recovery code", clientId: null);

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
            await LogLoginFailureAsync(request.Username, authResult.ErrorMessage ?? "LDAP authentication failed", clientId: null);

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

        LogLoginSuccess(user.UserName, user.RtId.ToString(), user.UserName, clientId: null);

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
        var userId = GetSubjectId();

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

        // AB#7804: a user with 2FA crosses the tenant boundary only with a session that proved the second factor.
        // 403 makes the SPA send the user to this tenant's login, where the second factor is asked.
        var secondFactorVerified = SecondFactorEvidence.IsPresent(User.Claims);
        if (crossTenantResult.SourceUserRequiresSecondFactor && !secondFactorVerified)
        {
            logger.LogWarning(
                "Cross-tenant token refused: user '{UserId}' of tenant '{TenantId}' has two-factor authentication enabled, but the session carries no second-factor evidence",
                userId, currentTenantId);
            return Forbid();
        }

        // Create a DataProtection-encrypted token
        var protector = dataProtectionProvider.CreateProtector(CrossTenantLoginPurpose);
        var payload = JsonSerializer.Serialize(new CrossTenantTokenPayload
        {
            SourceTenantId = currentTenantId,
            SourceUserId = userId,
            TargetTenantId = request.TargetTenantId,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            SecondFactorVerified = secondFactorVerified
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

        // AB#7804: re-checked at redemption — 2FA may have been enabled after the token was minted, and the token
        // only carries the evidence the source session had.
        if (crossTenantResult.SourceUserRequiresSecondFactor && !payload.SecondFactorVerified)
        {
            logger.LogWarning(
                "Cross-tenant login refused: user '{UserId}' of tenant '{TenantId}' has two-factor authentication enabled, but the token carries no second-factor evidence",
                payload.SourceUserId, payload.SourceTenantId);
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication is required; sign in to the parent tenant with your second factor"
            };
        }

        var signIn = await SignInCrossTenantUserAsync(crossTenantResult, currentTenantId, isPersistent: false,
            secondFactorVerified: payload.SecondFactorVerified, clientId: null);
        if (signIn.Error != null || signIn.User == null)
        {
            return new LoginResultDto
            {
                Success = false,
                ErrorMessage = signIn.Error ?? "Failed to create local user in target tenant"
            };
        }

        return new LoginResultDto
        {
            Success = true,
            RedirectUrl = ResolveRedirectUrl(request.ReturnUrl, currentTenantId)
        };
    }

    #region Cross-tenant sign-in helpers (AB#7804, AB#7815)

    private const string CrossTenantTwoFactorPurpose = "CrossTenantTwoFactorChallenge";
    private const string CrossTenantTwoFactorCookieName = ".AspNetCore.Octo.CrossTenantTwoFactor";

    /// <summary>Same lifetime as the framework's two-factor user cookie.</summary>
    private static readonly TimeSpan CrossTenantTwoFactorLifetime = TimeSpan.FromMinutes(5);

    private string ResolveRedirectUrl(string? returnUrl, string tenantId)
        => !string.IsNullOrEmpty(returnUrl) && (interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
            ? returnUrl
            : $"/{tenantId}/manage";

    /// <summary>
    /// Self-registration gate of the cross-tenant providers (AB#5015): <c>null</c> when the person may enter, else
    /// the denial message. Any shadow user of this person counts, whichever login path created it (AB#5708).
    /// </summary>
    private async Task<string?> CheckCrossTenantSelfRegistrationAsync(CrossTenantAuthResult crossTenantResult)
    {
        var provider = await FindOctoTenantProviderAsync(crossTenantResult.SourceTenantId);
        var existing = await crossTenantUserProvisioningService.FindCrossTenantUserAsync(crossTenantResult);
        if (existing == null && provider is { AllowSelfRegistration: false } &&
            !await IsExplicitlyProvisionedAsync(crossTenantResult))
        {
            logger.LogWarning("Self-registration denied for cross-tenant user '{UserName}' from tenant '{SourceTenant}'",
                crossTenantResult.SourceUserName, crossTenantResult.SourceTenantId);
            return "Self-registration is not allowed for this provider";
        }

        return null;
    }

    private async Task<RtOctoTenantIdentityProvider?> FindOctoTenantProviderAsync(string sourceTenantId)
        => (await identityProviderStore.GetAllAsync())
            .OfType<RtOctoTenantIdentityProvider>()
            .FirstOrDefault(p => p.IsEnabled &&
                                 string.Equals(p.ParentTenantId, sourceTenantId, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Creates the session in this tenant for a cross-tenant user whose credentials (and, where required, second
    /// factor) were verified: self-registration gate, shadow user, first-login groups, sign-in.
    /// </summary>
    private async Task<(RtUser? User, string? Error)> SignInCrossTenantUserAsync(
        CrossTenantAuthResult crossTenantResult, string tenantId, bool isPersistent, bool secondFactorVerified,
        string? clientId)
    {
        if (await CheckCrossTenantSelfRegistrationAsync(crossTenantResult) is { } denied)
        {
            return (null, denied);
        }

        var isNewUser = await crossTenantUserProvisioningService.FindCrossTenantUserAsync(crossTenantResult) == null;
        var localUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(crossTenantResult, tenantId);
        if (localUser == null)
        {
            return (null, null);
        }

        if (isNewUser)
        {
            await loginGroupAssignmentService.AssignGroupsAsync(localUser,
                await FindOctoTenantProviderAsync(crossTenantResult.SourceTenantId));
        }

        await SignInWithEvidenceAsync(localUser, isPersistent, secondFactorVerified);
        LogLoginSuccess(localUser.UserName, localUser.RtId.ToString(), localUser.UserName, clientId);
        return (localUser, null);
    }

    /// <summary>
    /// Signs the user in; with verified second-factor evidence the session carries <c>amr=mfa</c>, which
    /// <c>AuthorizeController</c> copies into tokens — so the next hop (grandchild tenant, token exchange) sees it.
    /// </summary>
    private Task SignInWithEvidenceAsync(RtUser user, bool isPersistent, bool secondFactorVerified)
        => secondFactorVerified
            ? signInManager.SignInWithClaimsAsync(user, isPersistent, [SecondFactorEvidence.CreateClaim()])
            : signInManager.SignInAsync(user, isPersistent);

    private void IssueCrossTenantTwoFactorChallenge(CrossTenantAuthResult crossTenantResult, string targetTenantId,
        bool rememberLogin)
    {
        var protector = dataProtectionProvider.CreateProtector(CrossTenantTwoFactorPurpose).ToTimeLimitedDataProtector();
        var value = protector.Protect(JsonSerializer.Serialize(new CrossTenantTwoFactorChallenge
        {
            SourceTenantId = crossTenantResult.SourceTenantId,
            SourceUserId = crossTenantResult.SourceUserId,
            TargetTenantId = targetTenantId,
            RememberLogin = rememberLogin,
            // AB#7861: single use — the nonce is marked used when the challenge completes or is cancelled.
            Nonce = Guid.NewGuid().ToString("N")
        }), CrossTenantTwoFactorLifetime);

        // Same cookie policy (secure, http-only, same-site, path) as the framework's own two-factor user cookie.
        var options = cookieOptions.Get(IdentityConstants.TwoFactorUserIdScheme).Cookie.Build(HttpContext);
        options.MaxAge = CrossTenantTwoFactorLifetime;
        options.Expires = null;
        options.IsEssential = true;
        Response.Cookies.Append(CrossTenantTwoFactorCookieName, value, options);
    }

    /// <summary>The pending challenge for THIS tenant, or <c>null</c> (none, expired, tampered, other tenant).</summary>
    private CrossTenantTwoFactorChallenge? ReadCrossTenantTwoFactorChallenge()
    {
        var value = Request.Cookies[CrossTenantTwoFactorCookieName];
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            var protector = dataProtectionProvider.CreateProtector(CrossTenantTwoFactorPurpose).ToTimeLimitedDataProtector();
            var challenge = JsonSerializer.Deserialize<CrossTenantTwoFactorChallenge>(protector.Unprotect(value));
            var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
            if (challenge == null ||
                !string.Equals(challenge.TargetTenantId, tenantId, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            // AB#7861: a challenge without a nonce (issued before single use) or one already completed / cancelled is
            // void, even if the browser — or a copy — still presents the cookie.
            if (string.IsNullOrEmpty(challenge.Nonce) || crossTenantChallengeReplayGuard.IsUsed(challenge.Nonce))
            {
                logger.LogInformation("Cross-tenant two-factor challenge rejected: already used");
                return null;
            }

            return challenge;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or JsonException)
        {
            logger.LogInformation("Cross-tenant two-factor challenge rejected: {Reason}", ex.GetType().Name);
            return null;
        }
    }

    private void DeleteCrossTenantTwoFactorChallenge()
    {
        if (Request.Cookies.ContainsKey(CrossTenantTwoFactorCookieName))
        {
            // AB#7861: void the challenge itself, not only the browser's copy of it.
            if (ReadCrossTenantTwoFactorChallenge() is { } challenge)
            {
                crossTenantChallengeReplayGuard.MarkUsed(challenge.Nonce, CrossTenantTwoFactorLifetime);
            }

            Response.Cookies.Delete(CrossTenantTwoFactorCookieName,
                cookieOptions.Get(IdentityConstants.TwoFactorUserIdScheme).Cookie.Build(HttpContext));
        }
    }

    /// <summary>
    /// Completes a pending cross-tenant sign-in with the SOURCE user's second factor. <c>null</c> when no challenge
    /// is pending for this tenant (the caller answers "session expired" as before).
    /// </summary>
    private async Task<TwoFactorLoginResultDto?> TryCompleteCrossTenantTwoFactorAsync(
        SecondFactorCodeKind kind, string code, string? returnUrl, string invalidCodeMessage)
    {
        var challenge = ReadCrossTenantTwoFactorChallenge();
        if (challenge == null)
        {
            return null;
        }

        var status = await crossTenantSecondFactorVerifier.VerifyAsync(
            challenge.SourceTenantId, challenge.SourceUserId, kind, code);
        switch (status)
        {
            case SecondFactorVerificationStatus.Invalid:
                await LogLoginFailureAsync(challenge.SourceUserId, $"Invalid cross-tenant two-factor code ({kind})");
                return new TwoFactorLoginResultDto { Success = false, ErrorMessage = invalidCodeMessage };

            case SecondFactorVerificationStatus.LockedOut:
                DeleteCrossTenantTwoFactorChallenge();
                await LogLoginFailureAsync(challenge.SourceUserId, "Account locked out (cross-tenant second factor)");
                return new TwoFactorLoginResultDto { Success = false, ErrorMessage = "Account is locked out" };

            case SecondFactorVerificationStatus.Unavailable:
                DeleteCrossTenantTwoFactorChallenge();
                return new TwoFactorLoginResultDto
                {
                    Success = false,
                    ErrorMessage = "Two-factor authentication session expired. Please login again."
                };
        }

        // Verified. Re-validate ancestry and the source user before the session is created.
        DeleteCrossTenantTwoFactorChallenge();
        var crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
            challenge.TargetTenantId, challenge.SourceTenantId, challenge.SourceUserId);
        var signIn = crossTenantResult == null
            ? (User: null, Error: "Cross-tenant access denied")
            : await SignInCrossTenantUserAsync(crossTenantResult, challenge.TargetTenantId, challenge.RememberLogin,
                secondFactorVerified: true, clientId: null);
        if (signIn.User == null)
        {
            return new TwoFactorLoginResultDto
            {
                Success = false,
                ErrorMessage = signIn.Error ?? "Failed to create local user in target tenant"
            };
        }

        return new TwoFactorLoginResultDto
        {
            Success = true,
            RedirectUrl = ResolveRedirectUrl(returnUrl, challenge.TargetTenantId)
        };
    }

    /// <summary>
    /// AB#7815: the caller's own identity in <paramref name="sourceTenantId" /> — the tier of the signed-in user's
    /// <c>xt_</c> name chain that lives there, resolved to its user id. <c>null</c> when the caller has no identity
    /// there (a local user, or a chain that does not pass through that tenant).
    /// </summary>
    private async Task<(string TenantId, string UserId)?> ResolveCallerSourceIdentityAsync(RtUser caller,
        string sourceTenantId)
    {
        if (string.IsNullOrEmpty(sourceTenantId))
        {
            return null;
        }

        foreach (var (tenantId, userName) in await shadowUserChainResolver.GetSourceChainAsync(caller.UserName))
        {
            if (!string.Equals(tenantId, sourceTenantId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var userId = await crossTenantAuthService.FindUserIdByNameInTenantAsync(tenantId, userName);
            return userId == null ? null : (tenantId, userId);
        }

        return null;
    }

    #endregion

    /// <summary>
    /// An ExternalTenantUserMapping created by an admin (e.g. via provisionCurrentUser) is explicit
    /// provisioning, not self-registration: the first login must be allowed to create the local
    /// shadow user even when the provider disallows self-registration (AB#5015).
    /// </summary>
    private Task<bool> IsExplicitlyProvisionedAsync(CrossTenantAuthResult crossTenantResult)
        => crossTenantUserProvisioningService.IsExplicitlyProvisionedAsync(crossTenantResult);

    /// <summary>
    /// Returns child tenants where the current user has role mappings.
    /// The user must be authenticated.
    /// </summary>
    [HttpGet("accessible-tenants")]
    public async Task<ActionResult<List<AccessibleTenantDto>>> GetAccessibleTenants()
    {
        var tenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var userId = GetSubjectId();

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
        var currentUserId = GetSubjectId();

        if (string.IsNullOrEmpty(currentUserId))
        {
            return Unauthorized();
        }

        // AB#7815: the source identity is the caller's OWN, proven by the session — a tier of the signed-in user's
        // xt_ name chain — never the request body's. The body may only name the tier (tenant) and, optionally,
        // repeat the user id of that tier; any other user id is refused.
        var caller = await userManager.FindByIdAsync(currentUserId);
        var source = caller == null
            ? null
            : await ResolveCallerSourceIdentityAsync(caller, request.SourceTenantId);
        if (source == null ||
            (!string.IsNullOrEmpty(request.SourceUserId) &&
             !string.Equals(request.SourceUserId, source.Value.UserId, StringComparison.Ordinal)))
        {
            logger.LogWarning(
                "Tenant switch denied: caller '{CallerId}' in tenant '{TargetTenantId}' named source '{SourceUserId}' of tenant '{SourceTenantId}', which is not the caller's own identity",
                currentUserId, targetTenantId, request.SourceUserId ?? "(none)", request.SourceTenantId);
            await auditService.StoreFailureAsync("Tenant Switch Failure",
                $"Caller '{currentUserId}' (tenant '{targetTenantId}') named source user '{request.SourceUserId ?? "(none)"}' of tenant '{request.SourceTenantId}': not the caller's own identity");
            return new TenantSwitchResultDto
            {
                Success = false,
                ErrorMessage = "Access to target tenant denied"
            };
        }

        var crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
            targetTenantId, source.Value.TenantId, source.Value.UserId);

        if (crossTenantResult == null)
        {
            return new TenantSwitchResultDto
            {
                Success = false,
                ErrorMessage = "Access to target tenant denied"
            };
        }

        // AB#7804: the session must carry the second-factor evidence when the source user has 2FA.
        var secondFactorVerified = SecondFactorEvidence.IsPresent(User.Claims);
        if (crossTenantResult.SourceUserRequiresSecondFactor && !secondFactorVerified)
        {
            return new TenantSwitchResultDto
            {
                Success = false,
                ErrorMessage = "Two-factor authentication required"
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

        // Sign in as the local user; the second-factor evidence goes with it
        await SignInWithEvidenceAsync(localUser, isPersistent: false, secondFactorVerified);

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

/// <summary>
///     The states <see cref="ErrorContextDto.Kind" /> can take. Kept as constants so the SPA and the
///     tests agree on the spelling.
/// </summary>
public static class ErrorContextKinds
{
    /// <summary>The error id was missing, expired or not ours — nothing could be resolved.</summary>
    public const string Unknown = "unknown";

    /// <summary>An error we can describe no further than IdentityServer itself does.</summary>
    public const string Generic = "generic";

    /// <summary>The requested client is not registered — or not enabled — in this tenant.</summary>
    public const string ClientNotRegistered = "clientNotRegistered";

    /// <summary>The client is known, but sent a redirect address that is not registered for it.</summary>
    public const string InvalidRedirectUri = "invalidRedirectUri";
}

public record ErrorContextDto
{
    /// <summary>See <see cref="ErrorContextKinds" />; drives which copy the page shows.</summary>
    public string Kind { get; init; } = ErrorContextKinds.Generic;

    /// <summary>Raw OAuth error code, for the technical-details block.</summary>
    public string? Error { get; init; }

    /// <summary>Raw IdentityServer description — developer-facing, not headline material.</summary>
    public string? ErrorDescription { get; init; }

    public string? RequestId { get; init; }
    public string? ActivityId { get; init; }
    public string TenantId { get; init; } = string.Empty;
    public string? ClientId { get; init; }

    /// <summary>Display name of the client, falling back to its id.</summary>
    public string? ClientName { get; init; }

    /// <summary>
    ///     The client's registered <c>ClientUri</c> — the only address safe to offer as a way back.
    ///     Never the <c>redirect_uri</c> of the failed request.
    /// </summary>
    public string? ClientUrl { get; init; }

    public string? ClientLogoUrl { get; init; }
}

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
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

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

    /// <summary>The password was correct, but the second factor is enabled without a usable authenticator (AB#7830).</summary>
    public bool SecondFactorSetupRequired { get; init; }
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
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

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
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

    public string Code { get; init; } = string.Empty;
    public bool RememberMachine { get; init; }
    public string? ReturnUrl { get; init; }
}

public record TwoFactorEmailLoginRequestDto
{
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

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
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

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
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

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
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

    public string Token { get; init; } = string.Empty;
}

public record CrossTenantLoginRequestDto
{
    protected virtual bool PrintMembers(System.Text.StringBuilder builder) => RedactingDtoPrinter.Print(this, builder);

    public string Token { get; init; } = string.Empty;
    public string? ReturnUrl { get; init; }
}

internal record CrossTenantTokenPayload
{
    public string SourceTenantId { get; init; } = string.Empty;
    public string SourceUserId { get; init; } = string.Empty;
    public string TargetTenantId { get; init; } = string.Empty;
    public long Timestamp { get; init; }

    /// <summary>The source session carried <c>amr=mfa</c> when the token was minted (AB#7804).</summary>
    public bool SecondFactorVerified { get; init; }
}

/// <summary>
/// Pending cross-tenant second-factor challenge (AB#7804): the source user passed the password check, the session in
/// the target tenant is created only after the second factor. Data-protected, short-lived, bound to the target tenant.
/// </summary>
internal record CrossTenantTwoFactorChallenge
{
    public string SourceTenantId { get; init; } = string.Empty;
    public string SourceUserId { get; init; } = string.Empty;
    public string TargetTenantId { get; init; } = string.Empty;
    public bool RememberLogin { get; init; }

    /// <summary>AB#7861: identifies the challenge for the single-use check.</summary>
    public string Nonce { get; init; } = string.Empty;
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
