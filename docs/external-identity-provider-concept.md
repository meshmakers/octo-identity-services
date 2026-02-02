# External Identity Provider Implementation Concept

## Overview

This document describes the concept for implementing complete external Identity Provider support in Octo Identity Services. The implementation covers OAuth2 providers (Google, Microsoft, Facebook, Azure Entra ID) and LDAP providers (OpenLDAP, Microsoft AD).

## Current Issues

### Issue 1: 404 Error on External Login Click

**Root Cause**: The `initiateExternalLogin()` method in `auth-api.service.ts` uses `window.location.href` for full-page redirect, which bypasses Angular's tenant HTTP interceptor.

**Current Code** (`src/IdentityServices/ClientApp/src/app/core/services/auth-api.service.ts:42-46`):
```typescript
initiateExternalLogin(scheme: string, returnUrl: string): void {
  const url = `/api/auth/external-login?scheme=${encodeURIComponent(scheme)}&returnUrl=${encodeURIComponent(returnUrl)}`;
  window.location.href = url;  // BYPASSES INTERCEPTOR - causes 404!
}
```

**Problem**: Backend route requires tenant ID prefix: `/{tenantId}/api/auth/external-login`

### Issue 2: Incomplete External Login Callback

**Location**: `AuthApiController.ExternalLoginCallback()` (lines 240-256)

**Current State**: The callback method authenticates the external user but doesn't:
- Create a new user account if none exists
- Link the external login to an existing user
- Sign in the user with the application's identity

### Issue 3: LDAP Provider Flow Gaps

LDAP providers redirect to form-based login pages (`/ExternalLogin/OpenLdap`) but:
- The form pages may not exist or be incomplete
- User creation/linking after LDAP authentication is not implemented

---

## Solution Architecture

### Phase 1: Fix 404 Error (Frontend)

#### Approach
Include the tenant ID in the external login URL construction.

#### Implementation

**File**: `src/IdentityServices/ClientApp/src/app/core/services/auth-api.service.ts`

**Option A - Inject Tenant Service**:
```typescript
@Injectable({ providedIn: 'root' })
export class AuthApiService {
  private readonly tenantId: string;

  constructor(
    private http: HttpClient,
    @Inject('TENANT_ID') tenantId: string
  ) {
    this.tenantId = tenantId;
  }

  initiateExternalLogin(scheme: string, returnUrl: string): void {
    const url = `/${this.tenantId}/api/auth/external-login?scheme=${encodeURIComponent(scheme)}&returnUrl=${encodeURIComponent(returnUrl)}`;
    window.location.href = url;
  }
}
```

**Option B - Extract from Current URL** (Recommended):
```typescript
initiateExternalLogin(scheme: string, returnUrl: string): void {
  // Extract tenant ID from current URL path (first segment after /)
  const pathSegments = window.location.pathname.split('/').filter(s => s);
  const tenantId = pathSegments[0] || 'System';

  const url = `/${tenantId}/api/auth/external-login?scheme=${encodeURIComponent(scheme)}&returnUrl=${encodeURIComponent(returnUrl)}`;
  window.location.href = url;
}
```

**Rationale for Option B**:
- No additional injection required
- Consistent with how the page was accessed
- Works for all tenants automatically

---

### Phase 2: Complete External Login Callback (Backend)

#### Current Flow
```
External Provider → Callback → [GAP: No user handling] → Redirect
```

#### Target Flow
```
External Provider → Callback → Find/Create User → Link Login → Sign In → Redirect
```

#### Implementation

**File**: `src/IdentityServices/Controllers/Api/AuthApiController.cs`

**New/Modified Endpoints**:

```csharp
[HttpGet("external-callback")]
public async Task<IActionResult> ExternalLoginCallback()
{
    // 1. Authenticate from external cookie
    var result = await HttpContext.AuthenticateAsync(
        IdentityServerConstants.ExternalCookieAuthenticationScheme);

    if (!result.Succeeded)
    {
        return Redirect("~/error?message=External authentication failed");
    }

    // 2. Extract external login info
    var externalUser = result.Principal;
    var claims = externalUser.Claims.ToList();

    var provider = result.Properties?.Items["scheme"] ??
                   result.Properties?.Items[".AuthScheme"];
    var returnUrl = result.Properties?.Items["returnUrl"] ?? "~/";

    // Get unique identifier from provider
    var userIdClaim = claims.FirstOrDefault(c =>
        c.Type == ClaimTypes.NameIdentifier ||
        c.Type == "sub");

    if (userIdClaim == null || string.IsNullOrEmpty(provider))
    {
        return Redirect("~/error?message=Invalid external login");
    }

    // 3. Find existing user by external login
    var user = await _userManager.FindByLoginAsync(provider, userIdClaim.Value);

    if (user == null)
    {
        // 4a. Try to find user by email (for account linking)
        var emailClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
        if (emailClaim != null)
        {
            user = await _userManager.FindByEmailAsync(emailClaim.Value);
        }

        if (user == null)
        {
            // 4b. Create new user
            user = await CreateUserFromExternalProvider(claims, provider);
            if (user == null)
            {
                return Redirect("~/error?message=Failed to create user");
            }
        }

        // 5. Link external login to user
        var addLoginResult = await _userManager.AddLoginAsync(
            user,
            new UserLoginInfo(provider, userIdClaim.Value, provider));

        if (!addLoginResult.Succeeded)
        {
            _logger.LogError("Failed to add login: {Errors}",
                string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
        }
    }

    // 6. Sign in the user
    await _signInManager.SignInAsync(user, isPersistent: false);

    // 7. Clean up external cookie
    await HttpContext.SignOutAsync(
        IdentityServerConstants.ExternalCookieAuthenticationScheme);

    // 8. Handle return URL
    if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
    {
        return Redirect(returnUrl);
    }

    return Redirect("~/");
}

private async Task<RtUser?> CreateUserFromExternalProvider(
    List<Claim> claims,
    string provider)
{
    var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
    var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
    var givenName = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value;
    var surname = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value;

    // Generate username from email or provider + id
    var userName = email ?? $"{provider}_{Guid.NewGuid():N}";

    var user = new RtUser
    {
        UserName = userName,
        Email = email,
        EmailConfirmed = email != null, // Trust external provider's email
        DisplayName = name ?? $"{givenName} {surname}".Trim()
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
```

---

### Phase 3: LDAP Provider Flow

LDAP providers use form-based authentication instead of OAuth redirects.

#### Flow Diagram
```
Login Page → Click LDAP Provider → LDAP Login Form → Submit Credentials
    → LDAP Authentication → Create/Link User → Sign In → Redirect
```

#### Existing Controllers

**OpenLDAP**: `src/Authentication/OpenLdap/OpenLdapController.cs`
**Microsoft AD**: `src/Authentication/MicrosoftAd/MicrosoftAdController.cs`

#### Required Changes

The LDAP controllers need to implement the same user creation/linking logic as the OAuth callback.

**File**: `src/Authentication/OpenLdap/OpenLdapController.cs`

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Login(OpenLdapLoginViewModel model)
{
    if (!ModelState.IsValid)
    {
        return View(model);
    }

    // 1. Authenticate against LDAP
    var authResult = await _ldapService.AuthenticateAsync(
        model.Username,
        model.Password,
        model.Scheme);

    if (!authResult.Succeeded)
    {
        ModelState.AddModelError("", "Invalid username or password");
        return View(model);
    }

    // 2. Find or create user
    var user = await _userManager.FindByLoginAsync(
        model.Scheme,
        authResult.DistinguishedName);

    if (user == null)
    {
        // Try to find by username
        user = await _userManager.FindByNameAsync(model.Username);

        if (user == null)
        {
            // Create new user from LDAP attributes
            user = new RtUser
            {
                UserName = model.Username,
                Email = authResult.Email,
                EmailConfirmed = authResult.Email != null,
                DisplayName = authResult.DisplayName ?? model.Username
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to create user account");
                return View(model);
            }
        }

        // Link LDAP login
        await _userManager.AddLoginAsync(
            user,
            new UserLoginInfo(model.Scheme, authResult.DistinguishedName, model.Scheme));
    }

    // 3. Sign in
    await _signInManager.SignInAsync(user, isPersistent: false);

    // 4. Redirect
    if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
    {
        return Redirect(model.ReturnUrl);
    }

    return Redirect("~/");
}
```

---

### Phase 4: Angular Login Form for LDAP

LDAP providers require a credential input form since they don't use OAuth redirects.

#### New Components

**File Structure**:
```
src/IdentityServices/ClientApp/src/app/features/
└── external-login/
    ├── ldap-login.component.ts
    ├── ldap-login.component.html
    └── ldap-login.component.scss
```

#### Component Implementation

```typescript
// ldap-login.component.ts
@Component({
  selector: 'app-ldap-login',
  templateUrl: './ldap-login.component.html',
  styleUrls: ['./ldap-login.component.scss'],
  standalone: true,
  imports: [CommonModule, FormsModule, LcarsPanelComponent, LcarsButtonComponent, LcarsInputComponent]
})
export class LdapLoginComponent implements OnInit {
  scheme = '';
  providerName = '';
  returnUrl = '';
  username = '';
  password = '';
  error = '';
  loading = false;

  constructor(
    private route: ActivatedRoute,
    private authApi: AuthApiService
  ) {}

  ngOnInit(): void {
    this.scheme = this.route.snapshot.queryParams['scheme'] || '';
    this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '';
    this.providerName = this.route.snapshot.queryParams['name'] || this.scheme;
  }

  async onSubmit(): Promise<void> {
    if (!this.username || !this.password) {
      this.error = 'Please enter username and password';
      return;
    }

    this.loading = true;
    this.error = '';

    try {
      const result = await this.authApi.ldapLogin({
        scheme: this.scheme,
        username: this.username,
        password: this.password,
        returnUrl: this.returnUrl
      });

      if (result.success) {
        window.location.href = result.redirectUrl || '/';
      } else {
        this.error = result.errorMessage || 'Authentication failed';
      }
    } catch (e) {
      this.error = 'An error occurred during authentication';
    } finally {
      this.loading = false;
    }
  }
}
```

#### Route Configuration

```typescript
// app.routes.ts
{
  path: 'external-login/ldap',
  loadComponent: () => import('./features/external-login/ldap-login.component')
    .then(m => m.LdapLoginComponent)
}
```

---

### Phase 5: Backend API for LDAP Login

#### New Endpoint

**File**: `src/IdentityServices/Controllers/Api/AuthApiController.cs`

```csharp
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

[HttpPost("ldap-login")]
public async Task<ActionResult<LdapLoginResultDto>> LdapLogin(
    [FromBody] LdapLoginRequestDto request)
{
    // 1. Validate scheme exists and is LDAP type
    var scheme = await _schemeProvider.GetSchemeAsync(request.Scheme);
    if (scheme == null)
    {
        return Ok(new LdapLoginResultDto
        {
            Success = false,
            ErrorMessage = "Invalid authentication scheme"
        });
    }

    // 2. Get LDAP handler and authenticate
    var handler = await _handlerProvider.GetHandlerAsync(HttpContext, request.Scheme);
    if (handler is not ILdapAuthenticationHandler ldapHandler)
    {
        return Ok(new LdapLoginResultDto
        {
            Success = false,
            ErrorMessage = "Scheme is not an LDAP provider"
        });
    }

    var authResult = await ldapHandler.AuthenticateAsync(
        request.Username,
        request.Password);

    if (!authResult.Succeeded)
    {
        return Ok(new LdapLoginResultDto
        {
            Success = false,
            ErrorMessage = authResult.Failure?.Message ?? "Invalid credentials"
        });
    }

    // 3. Find or create user (same logic as OAuth callback)
    var user = await FindOrCreateUserFromLdap(
        request.Scheme,
        authResult.Principal);

    if (user == null)
    {
        return Ok(new LdapLoginResultDto
        {
            Success = false,
            ErrorMessage = "Failed to create user account"
        });
    }

    // 4. Sign in
    await _signInManager.SignInAsync(user, isPersistent: false);

    // 5. Return redirect URL
    var redirectUrl = request.ReturnUrl;
    if (string.IsNullOrEmpty(redirectUrl) ||
        !(_interaction.IsValidReturnUrl(redirectUrl) || Url.IsLocalUrl(redirectUrl)))
    {
        redirectUrl = "~/";
    }

    return Ok(new LdapLoginResultDto
    {
        Success = true,
        RedirectUrl = redirectUrl
    });
}
```

---

## Implementation Plan

### Phase 1: Fix 404 Error
| Task | File | Effort |
|------|------|--------|
| Extract tenant ID from URL | `auth-api.service.ts` | Small |
| Update `initiateExternalLogin` method | `auth-api.service.ts` | Small |

### Phase 2: Complete OAuth Callback
| Task | File | Effort |
|------|------|--------|
| Implement `CreateUserFromExternalProvider` | `AuthApiController.cs` | Medium |
| Update `ExternalLoginCallback` | `AuthApiController.cs` | Medium |
| Add user linking logic | `AuthApiController.cs` | Medium |

### Phase 3: LDAP Backend
| Task | File | Effort |
|------|------|--------|
| Add `LdapLoginRequestDto` and `LdapLoginResultDto` | `AuthApiController.cs` | Small |
| Implement `LdapLogin` endpoint | `AuthApiController.cs` | Medium |
| Add `ILdapAuthenticationHandler` interface | `src/Authentication/` | Small |
| Update LDAP handlers | `OpenLdapAuthenticationHandler.cs`, `MicrosoftAdAuthenticationHandler.cs` | Medium |

### Phase 4: LDAP Frontend
| Task | File | Effort |
|------|------|--------|
| Create `LdapLoginComponent` | `ClientApp/src/app/features/external-login/` | Medium |
| Add route configuration | `app.routes.ts` | Small |
| Add `ldapLogin` method to service | `auth-api.service.ts` | Small |

### Phase 5: Update External Login Initiation
| Task | File | Effort |
|------|------|--------|
| Detect provider type (OAuth vs LDAP) | `auth-api.service.ts` | Small |
| Route to appropriate flow | `auth-api.service.ts` | Small |

---

## Testing Plan

### Unit Tests
- `AuthApiController.ExternalLoginCallback` - verify user creation logic
- `AuthApiController.LdapLogin` - verify LDAP authentication flow

### Integration Tests
| Test Case | Description |
|-----------|-------------|
| `ExternalLogin_WithValidScheme_RedirectsToProvider` | Verify OAuth challenge works |
| `ExternalCallback_NewUser_CreatesAccount` | Verify new user creation |
| `ExternalCallback_ExistingUser_LinksLogin` | Verify login linking |
| `LdapLogin_ValidCredentials_ReturnsSuccess` | Verify LDAP auth success |
| `LdapLogin_InvalidCredentials_ReturnsError` | Verify LDAP auth failure |

### Manual Testing
1. Configure an OAuth provider (e.g., Google)
2. Navigate to login page as tenant `System`
3. Click external provider button
4. Verify redirect includes tenant ID
5. Complete OAuth flow
6. Verify user is created/linked
7. Verify redirect to return URL

---

## Security Considerations

1. **Email Trust**: Only trust email from external providers if they verify emails
2. **Account Linking**: Consider requiring password confirmation when linking to existing account
3. **LDAP Credentials**: Never log or store LDAP passwords
4. **Return URL Validation**: Always validate return URLs to prevent open redirect attacks
5. **CSRF Protection**: Ensure LDAP login form includes anti-forgery token

---

## File Summary

### Modified Files
| File | Changes |
|------|---------|
| `src/IdentityServices/ClientApp/src/app/core/services/auth-api.service.ts` | Add tenant ID to external login URL, add LDAP login method |
| `src/IdentityServices/Controllers/Api/AuthApiController.cs` | Complete callback, add LDAP endpoint |
| `src/IdentityServices/ClientApp/src/app/app.routes.ts` | Add LDAP login route |

### New Files
| File | Purpose |
|------|---------|
| `src/IdentityServices/ClientApp/src/app/features/external-login/ldap-login.component.ts` | LDAP login form component |
| `src/IdentityServices/ClientApp/src/app/features/external-login/ldap-login.component.html` | LDAP login form template |
| `src/IdentityServices/ClientApp/src/app/features/external-login/ldap-login.component.scss` | LDAP login form styles |
| `src/Authentication/ILdapAuthenticationHandler.cs` | Interface for LDAP handlers |

---

## Dependencies

No new NuGet packages required. The implementation uses existing ASP.NET Core Identity and authentication infrastructure.
