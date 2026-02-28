# Authentication Architecture

## Overview

Octo Identity Services implements a dynamic authentication framework that supports multiple identity provider types. Providers can be configured at runtime through the database, enabling flexible authentication without code deployment.

## Supported Identity Providers

### OAuth 2.0 Providers

| Provider | Handler | Configuration |
|----------|---------|---------------|
| Google | `GoogleHandler` | ClientId, ClientSecret |
| Facebook | `FacebookHandler` | ClientId, ClientSecret |
| Microsoft Account | `MicrosoftAccountHandler` | ClientId, ClientSecret |

### OpenID Connect Providers

| Provider | Handler | Configuration |
|----------|---------|---------------|
| Azure Entra ID | `OpenIdConnectHandler` | ClientId, ClientSecret, TenantId |

### LDAP Providers

| Provider | Handler | Configuration |
|----------|---------|---------------|
| OpenLDAP | `OpenLdapAuthenticationHandler` | Host, Port, UseTls, UserBaseDn, UserNameAttribute |
| Microsoft AD | `MicrosoftAdAuthenticationHandler` | Host, Port, UseTls, Name |

## Dynamic Authentication Framework

### Core Components

Located in `src/Authentication/DynamicAuth/`:

```
DynamicAuth/
├── IDynamicAuthSchemeService.cs      # Interface for scheme management
├── DynamicAuthSchemeService.cs       # Runtime scheme registration
├── IAuthSchemeCreatorFactory.cs      # Factory interface
├── AuthSchemeCreatorFactory.cs       # Resolves scheme creators via DI
├── IAuthSchemeCreator.cs             # Creates schemes for specific providers
├── IDynamicAuthOptionsBuilder.cs     # Options builder interface
├── DynamicAuthOptionsBuilder.cs      # Base options builder
├── OAuthDynamicAuthOptionsBuilder.cs # OAuth-specific options
└── OpenIdDynamicAuthOptionsBuilder.cs# OIDC-specific options
```

### Initialization Flow

```
Application Startup
        │
        ▼
DynamicAuthSchemeServiceInitializer.InitializeAsync() [Order: 50]
        │
        ▼
DynamicAuthSchemeService.ConfigureAsync()
        │
        ▼
Load enabled providers from IOctoIdentityProviderStore
        │
        ▼
┌───────────────────────────────────────┐
│  For each provider:                   │
│  1. Get IAuthSchemeCreator<TProvider> │
│  2. Creator builds AuthenticationScheme│
│  3. Add scheme to provider            │
└───────────────────────────────────────┘
```

### Service Registration

In `Program.cs`:

```csharp
builder.Services.AddDynamicAuthentication()
    .AddGoogle()
    .AddFacebook()
    .AddMicrosoft()
    .AddAzureEntraId()
    .AddOpenLdapAuthentication()
    .AddMicrosoftAdAuthentication();
```

Each `.Add*()` extension registers:
- The `IAuthSchemeCreator<TProvider>` implementation
- The options builder for that provider type
- Any additional dependencies (e.g., `ILdapConnectionFactory` for LDAP)

## Authentication Flows

### Local Login Flow

```
User submits login form
        │
        ▼
POST /Account/Login
        │
        ▼
SignInManager.PasswordSignInAsync()
        │
        ├── Success ──► Raise UserLoginSuccessEvent ──► Redirect to returnUrl
        │
        └── Failure ──► Raise UserLoginFailureEvent ──► Show error
```

### External Provider Flow (OAuth/OIDC)

```
User clicks provider button
        │
        ▼
GET /ExternalLogin/{provider}/Challenge
        │
        ├── Validate returnUrl
        ├── Configure authentication properties
        └── Issue Challenge to provider
        │
        ▼
┌─────────────────────────────┐
│   External Provider         │
│   (Google, Azure AD, etc.)  │
└─────────────────────────────┘
        │
        ▼
GET /ExternalLogin/{provider}/Callback
        │
        ├── Read identity from IdentityConstants.ExternalScheme
        ├── GetExternalLoginInfoAsync()
        │       └── Returns: LoginProvider, ProviderKey, Claims
        ├── Find existing user by external login (provider + key)
        ├── If not found: Find user by email (account linking)
        ├── If not found: Create user (with duplicate prevention)
        │       ├── Re-check email uniqueness before insert
        │       └── Handle unique index violation gracefully
        ├── Link external login to user
        ├── SignInAsync() with IdentityServer
        └── SignOutAsync(ExternalScheme) ──► Cleanup
        │
        ▼
Redirect to original returnUrl
```

#### External Login Security Model (Bug 3430)

External login user creation follows a strict security model:

1. **No automatic account linking by email**: External logins (OAuth/LDAP) **never** auto-link to existing local users by email. This prevents privilege escalation where an attacker could register a Google/Microsoft account with the same email as an existing local user and inherit their roles and permissions.

2. **Dedicated external user accounts**: Each external provider login creates its own dedicated user account with a provider-prefixed username (e.g., `Google_user@example.com`). The external user starts with no roles and must be granted permissions explicitly by an administrator.

3. **Provider key matching only**: Returning users are identified exclusively via `FindByLoginAsync(provider, providerKey)`, which matches the external provider's unique user identifier. This ensures that only the same person from the same provider can access the same account.

4. **Separate database indexes**: The User CK model defines separate `Ascending` indexes on `NormalizedEmail` and `NormalizedUserName` for efficient lookups.

### LDAP Authentication Flow

```
User submits LDAP login form
        │
        ▼
POST /ExternalLogin/{ldapProvider}
        │
        ▼
LdapAuthenticationHandler.HandleAuthenticateAsync()
        │
        ├── Extract credentials from form
        ├── Create LDAP connection via factory
        ├── Execute search query
        ├── Verify credentials
        ├── Extract user attributes
        ├── Get group membership (LdapGroupHandler)
        └── Return ExternalLoginInfo with claims
        │
        ▼
Continue with External Provider Flow (Callback)
```

### Device Authorization Flow (RFC 8628)

The device authorization flow is designed for devices with limited input capabilities (CLI tools, smart TVs, etc.). The Octo CLI uses this flow for user authentication.

```
CLI initiates device authorization
        │
        ▼
POST /connect/deviceauthorization
        │
        ├── Returns: device_code, user_code, verification_uri
        └── CLI displays user_code and verification URL
        │
        ▼
User opens verification URL in browser
        │
        ▼
GET /{tenantId}/device?userCode={userCode}
        │
        ├── Angular SPA loads device-code component
        ├── If userCode in URL params, auto-navigates to confirm
        └── Otherwise, user enters code manually
        │
        ▼
GET /api/device/context?userCode={userCode}
        │
        ├── Validates device code
        ├── Returns: client info, scopes requested
        └── User reviews permissions
        │
        ▼
POST /api/device/allow (or /deny)
        │
        ├── Grants or denies authorization
        └── Shows success/error message
        │
        ▼
CLI polls: POST /connect/token (grant_type=device_code)
        │
        ├── Pending: authorization_pending error
        ├── Denied: access_denied error
        └── Approved: Returns access_token (no refresh_token)
```

**Important Notes**:

1. **No Refresh Token**: The device flow does not request `offline_access` scope by default. The returned access token must be used directly. When the token expires, the user must re-authenticate.

2. **URL Parameters**: The device authorization URL supports passing `userCode` as a query parameter (`?userCode=123456`). When present, the Angular SPA automatically navigates to the confirmation page.

3. **CLI Integration**: The `octo-cli` tool's `AuthenticationService` handles both scenarios:
   - With refresh token: Attempts token refresh before expiration
   - Without refresh token: Uses access token directly

## Scheme Creation Patterns

### OAuth Provider Pattern

```csharp
public class GoogleAuthSchemeCreator : IAuthSchemeCreator<RtGoogleIdentityProvider>
{
    public AuthenticationScheme Create(RtGoogleIdentityProvider provider)
    {
        var options = _builder.CreateOptions(provider.Name);
        options.ClientId = provider.ClientId;
        options.ClientSecret = provider.ClientSecret;

        return new AuthenticationScheme(
            provider.Name,
            provider.DisplayName ?? provider.Name,
            typeof(GoogleHandler)
        );
    }
}
```

### OIDC Provider Pattern (Azure Entra ID)

```csharp
public class AzureEntraIdAuthSchemeCreator : IAuthSchemeCreator<RtAzureEntraIdIdentityProvider>
{
    public AuthenticationScheme Create(RtAzureEntraIdIdentityProvider provider)
    {
        var options = _builder.CreateOptions(provider.Name);
        options.Authority = $"https://login.microsoftonline.com/{provider.TenantId}";
        options.ClientId = provider.ClientId;
        options.ClientSecret = provider.ClientSecret;
        options.CallbackPath = "/auth/signin-callback";

        // Configure metadata discovery
        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{options.Authority}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever()
        );

        return new AuthenticationScheme(
            provider.Name,
            provider.DisplayName ?? provider.Name,
            typeof(OpenIdConnectHandler)
        );
    }
}
```

### LDAP Provider Pattern

```csharp
public class OpenLdapSchemeCreator : IAuthSchemeCreator<RtOpenLdapIdentityProvider>
{
    public AuthenticationScheme Create(RtOpenLdapIdentityProvider provider)
    {
        var options = _builder.CreateOptions(provider.Name);
        options.Host = provider.Host;
        options.Port = provider.Port;
        options.UseTls = provider.UseTls;
        options.UserBaseDn = provider.UserBaseDn;
        options.UserNameAttribute = provider.UserNameAttribute;

        return new AuthenticationScheme(
            provider.Name,
            provider.DisplayName ?? provider.Name,
            typeof(OpenLdapAuthenticationHandler)
        );
    }
}
```

## Claims and Roles Synchronization

External providers may include role/group claims. These are synchronized with Octo roles:

```csharp
private async Task SynchronizeGroups(IEnumerable<Claim> claims, RtUser user)
{
    // Extract role claims from external identity
    var externalRoles = claims
        .Where(c => c.Type == ClaimTypes.Role)
        .Select(c => c.Value);

    // Validate that roles exist in Octo
    var validRoles = await ValidateRolesExist(externalRoles);

    // Update user's role assignments
    var currentRoles = user.RoleIds;
    var rolesToRemove = currentRoles.Except(validRoles);
    var rolesToAdd = validRoles.Except(currentRoles);

    // Apply changes
    foreach (var role in rolesToRemove)
        await RemoveFromRoleAsync(user, role);
    foreach (var role in rolesToAdd)
        await AddToRoleAsync(user, role);
}
```

## LDAP Connection Architecture

### Components

- `ILdapConnectionFactory` - Creates LDAP connections
- `ILdapConnection` - LDAP operations interface
- `LdapConnection` - Implementation using Novell.Directory.Ldap
- `LdapGroupHandler` - Extracts group membership

### Claim Mapping

LDAP attributes are mapped to standard claims:

| LDAP Attribute | Claim Type |
|----------------|------------|
| `cn` / `displayName` | `ClaimTypes.Name` |
| `objectGUID` | `ClaimTypes.NameIdentifier` |
| `mail` | `ClaimTypes.Email` |
| `givenName` | `ClaimTypes.GivenName` |
| `sn` | `ClaimTypes.Surname` |
| `memberOf` | `ClaimTypes.Role` |

## Runtime Reconfiguration

Identity providers can be updated at runtime:

1. Admin updates provider via System API
2. `IdentityProviderUpdate` event is published
3. `IdentityProviderUpdateConsumer` receives event
4. `DynamicAuthSchemeService.ConfigureAsync()` is called
5. Old schemes are removed, new schemes are added

No server restart required.

## Cross-Tenant Authentication

### Overview

Cross-tenant authentication enables users from a parent tenant to log in to child tenants without requiring separate user accounts. The Identity Service validates credentials against parent tenant databases internally — this is **not** OIDC federation but an internal credential-delegation mechanism.

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `RtOctoTenantIdentityProvider` | CK Model | Configures a parent-tenant auth link |
| `RtExternalTenantUserMapping` | CK Model | Maps parent-tenant user to child-tenant roles |
| `ICrossTenantAuthenticationService` | `IdentityServerPersistence/Services/` | Validates credentials across tenant hierarchy |
| `IExternalTenantUserMappingStore` | `IdentityServerPersistence/SystemStores/` | CRUD for cross-tenant user mappings |
| `ExternalTenantUserMappingsController` | `TenantApi/v1/Controllers/` | REST API for managing mappings |

### Tenant Hierarchy

Tenants form a hierarchy via `RtOctoTenantIdentityProvider` entries:
- Each child tenant can have one or more `OctoTenantIdentityProvider` pointing to parent tenants
- Authentication walks **up** the hierarchy (child → parent → grandparent)
- A user in "octosystem" (root) can access all descendant tenants
- Lateral access (sibling-to-sibling) is not permitted

### Cross-Tenant Login Flow

```
User submits credentials at child tenant login
        │
        ▼
Try local authentication (existing SignInManager flow)
        │
        ├── Success ──► Normal local login
        │
        └── Failure ──► Check for OctoTenantIdentityProvider
                │
                ▼
        CrossTenantAuthenticationService.AuthenticateAsync()
                │
                ├── Walk up tenant hierarchy
                ├── For each parent: find user by username
                ├── Validate password via IPasswordHasher
                ├── Check lockout status
                ├── Max depth limit (10 levels)
                ├── Circular reference detection
                │
                ├── Not found in any parent ──► Login failed
                │
                └── Found ──► Find/create ExternalTenantUserMapping
                        │
                        ▼
                Create local session with:
                  - Mapped roles from ExternalTenantUserMapping
                  - "home_tenant_id" claim in token
                  - Username prefixed with "xt_" (cross-tenant)
```

### Tenant Switch Flow

Users already authenticated in a parent tenant can switch to a child tenant without re-entering credentials:

```
GET /{tenantId}/api/auth/accessible-tenants
        │
        └── Returns child tenants where user has role mappings
        │
        ▼
POST /{targetTenantId}/api/auth/tenant-switch
        │
        ├── Validate source tenant is ancestor of target
        ├── Find user in source tenant
        ├── Return mapped roles for target tenant
        │
        ├── Access denied ──► 200 { success: false }
        │
        └── Access granted ──► 200 { success: true, roles: [...] }
```

### CK Model Types

**OctoTenantIdentityProvider** (derives from IdentityProvider):
- `ParentTenantId` (String) — The tenant ID of the parent tenant

**ExternalTenantUserMapping** (derives from Entity):
- `SourceTenantId` (String) — The tenant where the user resides
- `SourceUserId` (String) — The user's RtId in the source tenant
- `SourceUserName` (String) — Display name
- `MappedRoleIds` (StringArray, optional) — Roles assigned in the child tenant

### Identity CK Model Installation

The Identity CK model and default roles are installed in **all** tenants (not just the system tenant). This ensures:
- Cross-tenant user mappings can be stored in any tenant
- Default roles are available for role mapping in every tenant

### Token Claims

Cross-tenant users receive a `home_tenant_id` claim in their tokens, indicating which tenant owns their actual user account.

### Tenant-Aware Login Redirects

When IdentityServer's `/connect/authorize` endpoint determines the user isn't authenticated, it redirects to the configured login URL (default: `/System/login`). The `TenantLoginRedirectMiddleware` intercepts these 302 redirects and rewrites the tenant prefix based on `acr_values` in the authorize request.

**How it works:**

1. OIDC client includes `acr_values=tenant:{tenantId}` in the authorize request
2. IdentityServer redirects to `/System/login?ReturnUrl=...` (with `acr_values` encoded in the ReturnUrl)
3. The middleware parses `acr_values` from the ReturnUrl, extracts `tenant:{tenantId}`
4. Rewrites the redirect to `/{tenantId}/login?ReturnUrl=...`

**Affected paths:** `/login`, `/consent`, `/logout`, `/error`, `/device`

**Backward compatibility:** Without `acr_values`, the redirect goes to `/System/login` as before.

### Auto-Creation of OctoTenantIdentityProvider

When a child tenant has a `ParentTenantId` set on its `RtTenant` record, the `RtOctoTenantIdentityProvider` is automatically created:

- **New tenants**: During `SetupTenantAsync`, after CK model import and role creation
- **Existing tenants**: Via the `OctoTenantIdentityProviderMigration` (migration version 8→9)

Both mechanisms are idempotent — they check for an existing provider before creating one.

## Security Considerations

### Scheme Isolation
External authentication uses a temporary cookie scheme (`IdentityConstants.ExternalScheme`) that is cleared after processing.

### Claim Validation
External claims are validated against configured Octo users. Unknown users can be auto-provisioned if configured.

### Group Synchronization
Only roles that exist in Octo are mapped. External roles without Octo equivalents are ignored.

### Token Protection
OAuth state parameters are encrypted using ASP.NET Data Protection API.

### TLS Support
LDAP connections support TLS encryption via the `UseTls` configuration option.

### Return URL Validation
All return URLs are validated to prevent open redirect attacks.
