# External Identity Provider Implementation

## Overview

This document describes the implementation of external Identity Provider support in Octo Identity Services. The implementation covers OAuth2 providers (Google, Microsoft, Facebook, Azure Entra ID) and LDAP providers (OpenLDAP, Microsoft AD).

**Status: IMPLEMENTED**

---

## Architecture

### Provider Types

| Type | Providers | Authentication Flow |
|------|-----------|---------------------|
| **OAuth2** | Google, Microsoft, Facebook, Azure Entra ID | Redirect → External Provider → Callback |
| **LDAP** | OpenLDAP, Microsoft AD | Form-based credential input → Direct authentication |

### Flow Diagrams

**OAuth2 Providers:**
```
Login Page
    ↓
Click Provider Button
    ↓
GET /{tenantId}/api/auth/external-login?scheme={scheme}&returnUrl={returnUrl}
    ↓
ASP.NET Core Challenge → External Provider
    ↓
User authenticates at provider
    ↓
GET /{tenantId}/api/auth/external-callback
    ↓
Find/Create User → Link Login → Sign In
    ↓
Redirect to returnUrl
```

**LDAP Providers:**
```
Login Page
    ↓
Click LDAP Provider Button (detected via isLdap flag)
    ↓
Navigate to /{tenantId}/ldap-login?scheme={scheme}&name={name}&returnUrl={returnUrl}
    ↓
User enters credentials in LDAP login form
    ↓
POST /{tenantId}/api/auth/ldap-login
    ↓
LdapAuthenticationService authenticates against LDAP server
    ↓
Find/Create User → Link Login → Sign In
    ↓
Return { success: true, redirectUrl: "..." }
    ↓
Frontend redirects to returnUrl
```

---

## Implementation Details

### Phase 1: Fix 404 Error (COMPLETED)

**Problem:** `initiateExternalLogin()` used `window.location.href` which bypasses Angular's HTTP interceptor, causing the tenant ID to be missing from the URL.

**Solution:** Extract tenant ID from current URL path.

**File:** `src/IdentityServices/ClientApp/src/app/core/services/auth-api.service.ts`

```typescript
initiateExternalLogin(scheme: string, returnUrl: string): void {
  // Extract tenant ID from current URL path (first segment after /)
  // The backend route requires: /{tenantId}/api/auth/external-login
  // window.location.href bypasses Angular's HTTP interceptor, so we must include tenant ID manually
  const pathSegments = window.location.pathname.split('/').filter(s => s);
  const tenantId = pathSegments[0] || 'System';

  const url = `/${tenantId}/api/auth/external-login?scheme=${encodeURIComponent(scheme)}&returnUrl=${encodeURIComponent(returnUrl)}`;
  window.location.href = url;
}
```

---

### Phase 2: Complete OAuth Callback (COMPLETED)

**Problem:** `ExternalLoginCallback` didn't create users or link external logins.

**Solution:** Implement full user creation and login linking logic.

**File:** `src/IdentityServices/Controllers/Api/AuthApiController.cs`

**Key Methods:**
- `ExternalLoginCallback()` - Handles OAuth callback, creates/links users, signs in
- `CreateUserFromExternalProvider()` - Creates new user from external provider claims

**Features:**
- Extracts claims from external authentication result
- Finds existing user by external login
- Tries to find user by email for account linking
- Creates new user if not found
- Links external login to user
- Signs in user with ASP.NET Identity
- Cleans up external cookie
- Redirects to return URL or manage page

---

### Phase 3: LDAP Backend (COMPLETED)

**New Service:** `ILdapAuthenticationService` / `LdapAuthenticationService`

**File:** `src/Authentication/Services/ILdapAuthenticationService.cs`

```csharp
public interface ILdapAuthenticationService
{
    Task<LdapAuthenticationResult> AuthenticateAsync(string scheme, string username, string password);
    Task<bool> IsLdapSchemeAsync(string scheme);
}
```

**File:** `src/Authentication/Services/LdapAuthenticationService.cs`

- Authenticates against OpenLDAP or Microsoft AD based on scheme handler type
- Uses existing `OpenLdapAuthentication` and `MicrosoftAdAuthentication` classes
- Returns `ExternalLoginInfo` on success

**New Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/{tenantId}/api/auth/ldap-login` | POST | Authenticate with LDAP credentials |
| `/{tenantId}/api/auth/is-ldap-scheme` | GET | Check if scheme is LDAP-based |

**DTOs:**
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
```

**Updated DTOs:**
```csharp
public record ExternalProviderDto
{
    public string Scheme { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public bool IsLdap { get; init; }  // NEW - indicates LDAP provider
}
```

---

### Phase 4: LDAP Frontend (COMPLETED)

**New Component:** `LdapLoginComponent`

**Files:**
- `src/IdentityServices/ClientApp/src/app/features/login/ldap-login.component.ts`
- `src/IdentityServices/ClientApp/src/app/features/login/ldap-login.component.html`
- `src/IdentityServices/ClientApp/src/app/features/login/ldap-login.component.scss`

**Features:**
- LCARS-styled login form
- Provider name and icon display
- Username and password input
- Error message display
- Loading state during authentication
- "Back to Login" button
- Redirects on success

**Route:** `/{tenantId}/ldap-login`

**Updated Login Component:**

```typescript
// login.component.ts
onExternalLogin(provider: ExternalProvider): void {
  if (provider.isLdap) {
    // LDAP providers use a form-based login page
    this.router.navigate(['/', this.tenantId, 'ldap-login'], {
      queryParams: {
        scheme: provider.scheme,
        name: provider.displayName,
        returnUrl: this.returnUrl
      }
    });
  } else {
    // OAuth providers redirect to external provider
    this.authApi.initiateExternalLogin(provider.scheme, this.returnUrl);
  }
}
```

**New Models:**
```typescript
export interface ExternalProvider {
  scheme: string;
  displayName: string;
  isLdap: boolean;  // NEW
}

export interface LdapLoginRequest {
  scheme: string;
  username: string;
  password: string;
  returnUrl?: string;
}

export interface LdapLoginResult {
  success: boolean;
  redirectUrl?: string;
  errorMessage?: string;
}
```

**New Service Method:**
```typescript
ldapLogin(request: LdapLoginRequest): Observable<LdapLoginResult> {
  return this.http.post<LdapLoginResult>('/api/auth/ldap-login', request);
}
```

---

## File Summary

### New Files

| File | Purpose |
|------|---------|
| `src/Authentication/Services/ILdapAuthenticationService.cs` | Interface for LDAP authentication |
| `src/Authentication/Services/LdapAuthenticationService.cs` | LDAP authentication implementation |
| `ClientApp/src/app/features/login/ldap-login.component.ts` | LDAP login form component |
| `ClientApp/src/app/features/login/ldap-login.component.html` | LDAP login form template |
| `ClientApp/src/app/features/login/ldap-login.component.scss` | LDAP login form styles |

### Modified Files

| File | Changes |
|------|---------|
| `src/Authentication/DynamicAuth/IDynamicAuthBuilder.cs` | Register `ILdapAuthenticationService` in DI |
| `src/IdentityServices/Controllers/Api/AuthApiController.cs` | Add LDAP login endpoint, complete OAuth callback, update DTOs |
| `ClientApp/src/app/core/services/auth-api.service.ts` | Add tenant ID to external login, add `ldapLogin()` method |
| `ClientApp/src/app/core/models/login.models.ts` | Add `isLdap` to `ExternalProvider`, add LDAP DTOs |
| `ClientApp/src/app/features/login/login.component.ts` | Route LDAP providers to form |
| `ClientApp/src/app/app.routes.ts` | Add `ldap-login` route |

---

## API Reference

### External Authentication Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/{tenantId}/api/auth/login-context` | GET | Get login context with providers | No |
| `/{tenantId}/api/auth/external-providers` | GET | List external providers | No |
| `/{tenantId}/api/auth/external-login` | GET | Initiate OAuth challenge | No |
| `/{tenantId}/api/auth/external-callback` | GET | OAuth callback handler | No |
| `/{tenantId}/api/auth/ldap-login` | POST | LDAP credential login | No |
| `/{tenantId}/api/auth/is-ldap-scheme` | GET | Check if scheme is LDAP | No |

### Login Context Response

```json
{
  "returnUrl": "/connect/authorize/callback?...",
  "clientName": "OctoMesh Admin Panel",
  "clientLogoUrl": null,
  "externalProviders": [
    {
      "scheme": "google",
      "displayName": "Google",
      "isLdap": false
    },
    {
      "scheme": "rackstation",
      "displayName": "Rackstation LDAP",
      "isLdap": true
    }
  ],
  "allowRememberLogin": true,
  "enableLocalLogin": true,
  "isAuthenticated": false,
  "username": null
}
```

### LDAP Login Request/Response

**Request:**
```json
{
  "scheme": "rackstation",
  "username": "john.doe",
  "password": "secret123",
  "returnUrl": "/connect/authorize/callback?..."
}
```

**Success Response:**
```json
{
  "success": true,
  "redirectUrl": "/connect/authorize/callback?...",
  "errorMessage": null
}
```

**Error Response:**
```json
{
  "success": false,
  "redirectUrl": null,
  "errorMessage": "Invalid username or password"
}
```

---

## Security Considerations

1. **Email Trust**: External provider emails are trusted (marked as confirmed) since providers verify them
2. **Account Linking**: Users with matching email are automatically linked to external logins
3. **LDAP Credentials**: Never logged or stored - only used for authentication
4. **Return URL Validation**: All return URLs are validated via `IIdentityServerInteractionService.IsValidReturnUrl()` or `Url.IsLocalUrl()`
5. **Tenant Isolation**: All endpoints are tenant-scoped via route parameter

---

## Testing

### Phase 5: Integration Tests (COMPLETED)

**New Test File:** `tests/IdentityServices.IntegrationTests/Api/Auth/ExternalLoginTests.cs`

**Test Cases:**

| Test | Description |
|------|-------------|
| `GetLoginContext_ExternalProviders_HaveIsLdapProperty` | Verifies all external providers have the `isLdap` property |
| `GetExternalProviders_ReturnsProvidersWithIsLdapFlag` | Verifies external providers endpoint returns `isLdap` flag |
| `IsLdapScheme_WithNonExistentScheme_ReturnsFalse` | Verifies non-existent scheme returns `isLdap: false` |
| `IsLdapScheme_WithEmptyScheme_ReturnsBadRequestOrFalse` | Verifies empty scheme handling |
| `LdapLogin_WithInvalidScheme_ReturnsError` | Verifies LDAP login with invalid scheme returns error |
| `LdapLogin_WithEmptyScheme_ReturnsError` | Verifies LDAP login with empty scheme returns error |
| `LdapLogin_WithEmptyCredentials_ReturnsError` | Verifies LDAP login with empty credentials returns error |
| `LdapLogin_WithNonLdapScheme_ReturnsNotLdapError` | Verifies LDAP login with OAuth scheme is rejected |
| `ExternalLogin_WithValidScheme_ReturnsChallenge` | Verifies OAuth challenge is initiated |
| `ExternalCallback_WithoutExternalCookie_ReturnsError` | Verifies callback without auth cookie fails |

### Automated Test Summary

All tests pass (69 passed, 1 skipped):

| Test Project | Passed | Skipped | Failed |
|--------------|--------|---------|--------|
| Authentication.UnitTests | 5 | 0 | 0 |
| IdentityServerPersistence.UnitTests | 20 | 0 | 0 |
| IdentityServices.UnitTests | 10 | 0 | 0 |
| IdentityServices.IntegrationTests | 69 | 1 | 0 |
| **Total** | **104** | **1** | **0** |

### Manual Testing Checklist

**OAuth Provider (e.g., Google):**
- [ ] Provider appears in login context with `isLdap: false`
- [ ] Clicking provider redirects to external provider
- [ ] Callback creates new user if not exists
- [ ] Callback links login to existing user by email
- [ ] User is signed in after callback
- [ ] Redirect to return URL works

**LDAP Provider:**
- [ ] Provider appears in login context with `isLdap: true`
- [ ] Clicking provider navigates to LDAP login form
- [ ] Form displays provider name
- [ ] Valid credentials authenticate and redirect
- [ ] Invalid credentials show error message
- [ ] "Back to Login" returns to main login page
- [ ] New user is created from LDAP attributes
- [ ] Existing user by login is found
- [ ] Existing user by email is linked

---

## Configuration

### Adding an LDAP Provider

LDAP providers are configured via the Identity Provider management API or database. Example configuration:

```json
{
  "type": "OpenLdap",
  "name": "rackstation",
  "displayName": "Rackstation LDAP",
  "enabled": true,
  "host": "192.168.1.100",
  "port": 389,
  "useTls": false,
  "userBaseDn": "cn=users,dc=synology,dc=com",
  "userNameAttribute": "uid"
}
```

### Supported LDAP Handler Types

| Handler | Type | Notes |
|---------|------|-------|
| `OpenLdapAuthenticationHandler` | OpenLDAP | Uses `uid` as username attribute |
| `MicrosoftAdAuthenticationHandler` | Microsoft AD | Uses `userPrincipalName` as username |

---

## Dependencies

No new NuGet packages required. Uses existing:
- ASP.NET Core Identity
- Duende IdentityServer
- Novell.Directory.Ldap (for LDAP connections)
