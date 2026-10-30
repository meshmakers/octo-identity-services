# Authentication Architecture

## Overview

Octo Identity Services implements a dynamic authentication framework that supports multiple identity provider types. Providers can be configured at runtime through the database, enabling flexible authentication without code deployment.

The OAuth2/OIDC protocol stack is **OpenIddict 7.6** (migrated from Duende IdentityServer, Epic AB#4989). Endpoint paths, discovery, JWKS, and token/claims shapes are kept Duende-compatible; the remaining discovery-document differences are documented in [openiddict-discovery-diff.md](openiddict-discovery-diff.md). Cookie authentication uses the schemes defined in `OctoAuthSchemes` (`src/Authentication/`): `Identity.Application` (tenant-scoped) and `Identity.External`.

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

### Multi-Tenant Scheme Isolation

Authentication schemes are **tenant-prefixed** using the format `{tenantId}:{providerName}` so that all tenants' schemes coexist safely in the singleton `IAuthenticationSchemeProvider`. For example, if tenant `octosystem` has a Google provider and tenant `meshtest` has its own Google provider with different credentials, the registered scheme names are `octosystem:Google` and `meshtest:Google` respectively.

Key design decisions:
- **Scheme name**: `{tenantId}:{providerName}` — the colon separator is safe (not used in tenant IDs or provider names)
- **Display name**: Unchanged — users see "Google", "Microsoft", etc.
- **Options cache**: Since ASP.NET Core keys options by scheme name, different tenants' OAuth credentials are automatically isolated
- **Frontend**: Receives the full prefixed scheme name in the `Scheme` field and passes it back unchanged for challenge/login calls

### Initialization Flow

```
Application Startup
        │
        ▼
DynamicAuthSchemeServiceInitializer.InitializeAsync() [Order: 50]
        │
        ├── ConfigureAsync(systemTenantId)
        │
        ├── GetChildTenantsAsync() — load all child tenants
        │
        └── For each child tenant:
                └── ConfigureAsync(tenant.TenantId)
        │
        ▼
DynamicAuthSchemeService.ConfigureAsync(tenantId)
        │
        ├── Remove only schemes with prefix "{tenantId}:"
        │
        ├── Load providers directly from tenant's database
        │   (via ISystemContext.FindTenantRepositoryAsync, bypassing HTTP-scoped store)
        │
        └── For each enabled provider:
                ├── Create scheme with name "{tenantId}:{providerName}"
                └── Register scheme in IAuthenticationSchemeProvider
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

### Sign-In Attempts: Atomic Counting and Rate Limits (AB#7854)

Passwords, second-factor codes and recovery codes cannot be guessed faster than the lockout allows — neither with
parallel requests nor through a child tenant.

**Atomic failure counting.** `OctoUserManager` (registered as the `UserManager<RtUser>`) overrides
`AccessFailedAsync` and `ResetAccessFailedCountAsync`: the counter and the lockout end are changed in **one MongoDB
transaction** that reads the stored user and writes it back (`IAtomicUserLockoutStore` on `OctoUserStore`), retried on
write conflicts (`MongoWriteRetry.ExecuteTransactionWithRetryAsync`). The framework version incremented the caller's
in-memory copy and replaced the whole document, so N parallel wrong attempts counted about once. The arithmetic is the
framework's: 5 failures (`Lockout.MaxFailedAccessAttempts`) set a 5-minute lockout (`DefaultLockoutTimeSpan`) and restart
the count; a successful sign-in resets the stored counter, whatever the caller's copy says. The store copies the stored
values back onto the caller's instance, because `SignInManager` checks `IsLockedOutAsync` on it right after.

**Recovery codes are single-use under concurrency.** `OctoUserStore.RedeemCodeAsync` finds and removes the code in the
same transaction; two parallel requests with the same code redeem it once.

**Cross-tenant passwords count against the source user.** When the local password check of a child tenant fails and
`CrossTenantAuthenticationService` tries the parent tenants, a wrong password counts against the parent-tenant user it was
tried on (same arithmetic, in that tenant's database), a correct one resets the counter (only when that user has no
second factor; otherwise the verified code resets it), and a locked-out parent user is not verified at all.
Cross-tenant second-factor codes already counted against the source user (AB#7804); that counting is atomic now too.

**Rate limits** (`ISignInRateLimiter` / `SignInRateLimiter`, asked by `AuthApiController`) on `login`, `ldap-login`,
`login-2fa`, `login-2fa-email`, `send-2fa-email` and `login-recovery`:

| Limit | Default | Key |
|-------|---------|-----|
| Attempts per client address | 60 per sliding minute | right-most `X-Forwarded-For` entry (the address the ingress saw), else the TCP peer |
| Concurrent attempts per account | 1 (parallel attempts are refused) | `login`: the user name; `ldap-login`: scheme + user name; second factor / recovery: the user of the two-factor cookie, or the source user of a pending cross-tenant challenge |
| Attempts per account | 10 per sliding minute | as above |

A refused attempt is answered `429` with `Retry-After: 60` and a body `{ success: false, errorMessage, message }`
("Too many sign-in attempts. Please wait a minute and try again."); the SPA shows `message`. The user-name key is the same
for every tenant, so guessing a parent user's password through several child tenants shares one budget. The limits are in
memory per pod: with N identity pods an account can be tried N times in parallel at most, which the atomic counter still
counts. Settings: `Identity:SignInRateLimit` (see `configuration.md`).

Tests: `SignInAttemptConcurrencyTests` (real MongoDB: parallel failures all counted, threshold reached in parallel locks the
user out, reset of a stale copy, parallel recovery-code redemption succeeds once, parallel wrong TOTP codes over HTTP, lockout
through a child tenant, 429 per account and per client), `SignInRateLimiterTests`, `CrossTenantAuthenticationServiceTests`.

### Password Change Ends Existing Sessions (AB#7765)

Every REST password change (`change-password`, `set-password`, administrator `ResetPassword`, token
`reset-password`) rotates the user's security stamp and revokes all refresh tokens and authorizations the
user holds **in that tenant**. A client presenting an old refresh token gets `invalid_grant` and the user
signs in again with the new password; other users and the same user in another tenant are not affected.
One audit log line records tenant, subject, acting user and path (no password or token value). The logic
lives in `IUserCredentialChangeService`, which any new password path must call.

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
        ├── SignInAsync() (writes the tenant-scoped Identity.Application cookie)
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

5. **Provider-name character safety**: The generated username embeds the provider's configured `Name` (`{Name}_{email}`). ASP.NET Identity's `UserValidator` only accepts a limited character set, so a provider named with spaces or other special characters (e.g. `Microsoft Entra ID`) would make `UserManager.CreateAsync` fail with `InvalidUserName`, surfacing to the end user as **"Failed to create user account"** *after* an otherwise successful external login. Two defenses:
   - **At configuration time**: `IdentityProvidersController` (the single write path used by the Studio UI, `octo-cli` and the MCP server) rejects a provider `Name` that is not `^[A-Za-z0-9._-]+$` with a `400 Bad Request`, so the problem is caught when the provider is created/updated.
   - **At login time**: `AuthApiController.CreateUserFromExternalProvider` additionally sanitizes the provider label (`SanitizeUserNameComponent`) down to letters/digits/`. _ -` as a safety net for providers that were configured before this validation existed.

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
        ├── OidcTenantResolutionMiddleware captures user_code → tenant and rewrites
        │   verification_uri to the SPA page /{tenantId}/device (with ?userCode= for
        │   verification_uri_complete)
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
GET /connect/deviceverification?user_code={userCode}
        │   (OpenIddict end-user verification endpoint, DeviceVerificationController;
        │    tenant resolved from the user_code → tenant mapping)
        ├── Validates the user code
        ├── Returns: client info, scopes requested
        └── User reviews permissions
        │
        ▼
POST /connect/deviceverification (form-encoded allow/deny, driven by the SPA's
        │   ConsentApiService device methods)
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

The former `DeviceApiController` (`/api/device/*`) now only holds the DTOs — the flow runs through
`/connect/deviceverification`. Code redemption re-validates the user and re-resolves roles in
`TokenEndpointController`.

**Important Notes**:

1. **No Refresh Token**: The device flow does not request `offline_access` scope by default. The returned access token must be used directly. When the token expires, the user must re-authenticate.

2. **URL Parameters**: The device authorization URL supports passing `userCode` as a query parameter (`?userCode=123456`). When present, the Angular SPA automatically navigates to the confirmation page.

3. **CLI Integration**: The `octo-cli` tool's `AuthenticationService` handles both scenarios:
   - With refresh token: Attempts token refresh before expiration
   - Without refresh token: Uses access token directly

## Scheme Creation Patterns

All scheme creators accept an optional `schemeNameOverride` parameter. When provided (e.g., a tenant-prefixed name like `octosystem:Google`), the scheme is registered under that name instead of the provider's `Name` property. The display name remains unchanged.

### Client Secrets of External Providers (AB#5540)

Since `System.Identity-2.25.0` the `ClientSecret` of Google, Microsoft, Facebook and Azure Entra ID
providers is a CK `Secret` attribute (concept AB#5528 in `octo-construction-kit-engine/docs/`): stored
as an `enc:v2:<kid>:…` envelope, never projected by an API, preserved on blueprint re-apply and left
out of `ExportRt`.

- **Reading:** `IIdentityProviderSecretReader` (`Authentication/Secrets/`) is the only place that turns
  it into plaintext, through `ISecretAttributeProtector.Unprotect` with a `SecretAccessContext`
  (tenant, CK type, attribute, service `identity`) — every call counts `octo.secrets.decrypt`. It
  accepts all stored forms: `enc:v2`, legacy clear text (before the encrypt sweep, counted as a
  plaintext read and warned about without the value) and `enc:v1`. The scheme creators receive the
  tenant id as a third `Create` argument for the counter. Nothing logs the value.
- **Key ring:** `AddRuntimeEngine()` binds `SecretEncryption` (`OCTO_SECRETENCRYPTION__KEYS__k1`,
  `__ACTIVEKEYID`, `__LEGACYV1KEY`). Without keys the service starts; legacy clear-text secrets still
  work, writing a new secret throws `SecretEncryptionNotConfiguredException`, and an encrypted one
  is treated like an unknown key id (see below).
- **Unknown key id:** an envelope whose key id is not in the key ring (e.g. after a
  cross-environment restore, or no key ring at all) is kept stored and treated as "not set":
  `IIdentityProviderSecretReader.GetClientSecretState` reports `KeyMissing` from the key id alone
  (`ISecretAttributeProtector.IsKnownKeyId`, no decrypt), `GetClientSecret` returns `null` with an
  error log (key id and provider, never the value), `DynamicAuthSchemeService` skips that provider
  with an error log, and the REST API reports `clientSecretIsSet: false`. It becomes readable again
  once the key is added to the ring; otherwise the secret has to be re-entered.
- **Undecryptable secret:** `DynamicAuthSchemeService` skips only that provider (a damaged value, or
  legacy clear text while `SecretEncryption:StrictMode` is on) and logs the exception type;
  the tenant's other sign-in methods keep working. The secret has to be re-entered.
- **Writing:** `IdentityProvidersController` / `IdentityProviderEntityMapping.ToEntity()` map a non-empty input to
  `RtSecretValue.Pending`, which the engine encrypts on write (there are no placeholder semantics —
  `<...>` / `TODO_SET_*` are ordinary values); null/"" leave the attribute absent, and
  `IdentityProviderStore` carries the stored envelope over on replace (the engine does the same).

- **Rollout:** pilot runbook for test-2 (preconditions, verification, rollback):
  `rollout-identity-secret-phase3-test2.md`.

### OAuth Provider Pattern

```csharp
public class GoogleAuthSchemeCreator : IAuthSchemeCreator<RtGoogleIdentityProvider>
{
    public AuthenticationScheme Create(RtGoogleIdentityProvider provider, string? schemeNameOverride = null,
        string? tenantId = null)
    {
        var schemeName = schemeNameOverride ?? provider.Name;
        var options = _builder.CreateOptions(schemeName);
        options.ClientId = provider.ClientId;
        // Secret value type (AB#5540): counted decrypt via ISecretAttributeProtector
        options.ClientSecret = _secretReader.GetClientSecret(provider, tenantId) ?? string.Empty;

        return new AuthenticationScheme(
            schemeName,
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
    public AuthenticationScheme Create(RtAzureEntraIdIdentityProvider provider, string? schemeNameOverride = null,
        string? tenantId = null)
    {
        var schemeName = schemeNameOverride ?? provider.Name;
        var options = _builder.CreateOptions(schemeName);
        options.Authority = $"https://login.microsoftonline.com/{provider.TenantId}";
        options.ClientId = provider.ClientId;
        options.ClientSecret = _secretReader.GetClientSecret(provider, tenantId);
        options.CallbackPath = "/auth/signin-callback";

        // Configure metadata discovery
        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{options.Authority}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever()
        );

        return new AuthenticationScheme(
            schemeName,
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
    public AuthenticationScheme Create(RtOpenLdapIdentityProvider provider, string? schemeNameOverride = null)
    {
        var schemeName = schemeNameOverride ?? provider.Name;
        var options = _builder.CreateOptions(schemeName);
        options.Host = provider.Host;
        options.Port = provider.Port;
        options.UseTls = provider.UseTls;
        options.UserBaseDn = provider.UserBaseDn;
        options.UserNameAttribute = provider.UserNameAttribute;

        return new AuthenticationScheme(
            schemeName,
            provider.DisplayName ?? provider.Name,
            typeof(OpenLdapAuthenticationHandler)
        );
    }
}
```

## Claims and Roles Synchronization

External providers may include role/group claims. These are synchronized with Octo roles via CK associations:

```csharp
private async Task SynchronizeGroups(IEnumerable<Claim> claims, RtUser user)
{
    // Extract role claims from external identity
    var externalRoles = claims
        .Where(c => c.Type == ClaimTypes.Role)
        .Select(c => c.Value);

    // Validate that roles exist in Octo
    var validRoles = await ValidateRolesExist(externalRoles);

    // Update user's role assignments (via AssignedRole associations)
    var currentRoles = await GetRolesAsync(user);
    var rolesToRemove = currentRoles.Except(validRoles);
    var rolesToAdd = validRoles.Except(currentRoles);

    // Apply changes (creates/deletes AssignedRole associations)
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
2. `IdentityProviderUpdate` event is published with the tenant ID
3. `IdentityProviderUpdateConsumer` receives event
4. `DynamicAuthSchemeService.ConfigureAsync(tenantId)` is called
5. Only schemes for that specific tenant (prefix `{tenantId}:`) are removed and re-added
6. Other tenants' schemes are unaffected

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
| `IExternalTenantUserMappingStore` | `IdentityServerPersistence/SystemStores/` | CRUD for cross-tenant user mappings; `FindBySourceUserAsync` tolerates duplicates (oldest `RtId` wins, WARN once per request scope; AB#6975); effective roles are the union over all matching mappings |
| `ExternalTenantUserMappingsController` | `TenantApi/v1/Controllers/` | REST API for managing mappings; a mapping is unique per (source tenant, source user): creating a second one (here and in `AdminProvisioningController`) answers `409 problem+json`, code `ExternalTenantUserMappingAlreadyExists`, update the existing mapping's roles instead (AB#6975) |

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
                ├── Found, source user has 2FA (AB#7804) ──► requiresTwoFactor
                │       (no session yet; login-2fa / login-2fa-email / login-recovery
                │        verify the SOURCE user's code, then continue below)
                │
                └── Found ──► Find/create ExternalTenantUserMapping
                        │
                        ▼
                Create local session with:
                  - Mapped roles from ExternalTenantUserMapping
                  - "home_tenant_id" claim in token
                  - Username prefixed with "xt_" (cross-tenant)
```

### Cross-Tenant Auto-Login Flow (Token-Based with Redirect)

When a user clicks "LOGIN VIA OCTOSYSTEM" on a child tenant's login page, the UI first attempts a token-based cross-tenant login. If the user has no active session in the parent tenant, the UI redirects to the parent tenant's login page where all authentication methods (Google, Microsoft, Azure Entra ID, LDAP, password) are available. After authenticating there, the user is redirected back and the token flow completes automatically.

```
User clicks "LOGIN VIA OCTOSYSTEM" on child tenant login page
        │
        ▼
POST /{parentTenantId}/api/auth/cross-tenant-token
  (browser sends parent tenant's scoped cookie automatically)
        │
        ├── 401/403 (no parent session)
        │       │
        │       ▼
        │   Redirect to /{parentTenantId}/login
        │     ?returnUrl=/{childTenantId}/login?returnUrl={orig}&crossTenantAutoLogin={parentTenantId}
        │       │
        │       ▼
        │   User authenticates at parent tenant (any method: Google, LDAP, password, etc.)
        │       │
        │       ▼
        │   Parent tenant redirects back to /{childTenantId}/login
        │     ?returnUrl={orig}&crossTenantAutoLogin={parentTenantId}
        │       │
        │       ▼
        │   Login component detects crossTenantAutoLogin query param
        │       │
        │       ▼
        │   Auto-triggers token flow (same as success path below)
        │
        └── 200 { token: "..." } (DataProtection-encrypted, 60s expiry)
                │
                ▼
POST /{childTenantId}/api/auth/cross-tenant-login
  (exchanges token for a session in the child tenant)
        │
        ├── Token invalid/expired ──► Show error
        ├── Target tenant mismatch ──► Show error
        │
        └── Token valid ──► Find/create local xt_ user
                ├── Sign in via SignInManager (writes child-scoped cookie)
                └── Redirect to ReturnUrl or /{childTenantId}/manage
```

**Token payload** (DataProtection-encrypted with purpose `CrossTenantLogin`):
- `SourceTenantId`: The parent tenant that issued the token
- `SourceUserId`: The authenticated user's ID in the parent tenant
- `TargetTenantId`: The child tenant this token is valid for
- `Timestamp`: Token creation time (tokens expire after 60 seconds)

**Edge cases:**
- No parent session (401): Redirects to parent login page; after auth, redirects back with `crossTenantAutoLogin` param for automatic token exchange
- Loop prevention: `crossTenantAutoLogin` param is stripped from the URL immediately; on failure after redirect, an error message is shown without retrying
- Expired token (>60s): Returns error; user can click the button again
- Target tenant mismatch: Returns error (token was issued for a different tenant)
- No cross-tenant mapping: `FindOrCreateCrossTenantUserAsync` creates an empty one (no roles, no groups)
- Self-registration gate (AB#5015): when the `OctoTenantIdentityProvider` has `AllowSelfRegistration=false` and the person has no local shadow user yet, the login is denied — **unless** an `ExternalTenantUserMapping` exists in the target tenant for the source user (matched by `SourceTenantId` + `SourceUserId`, or — AB#5708 — by `SourceTenantId` + `SourceUserName` for any identity of the source's `xt_` chain). A mapping created by an admin (e.g. via `provisionCurrentUser`) is explicit provisioning, not self-registration, so the first login is allowed to create the shadow user. The same rule applies to the cross-tenant **password** login path in `AuthApiController.Login`.

### Second Factor Across Tenant Boundaries (AB#7804, AB#7815)

**Rule:** a user who has two-factor authentication enabled in the source tenant — or whose `xt_` name chain unwinds
to an identity that has it — gets no session and no token in another tenant without second-factor evidence. Before
AB#7804 every cross-tenant path checked only the password (or the source session) and the opt-in second factor could
be skipped through any child tenant.

**Evidence** is the `amr` value `mfa` (`SecondFactorEvidence`, `IdentityServerPersistence/Services/`). ASP.NET Core
Identity stamps it on the session when a sign-in completed a second factor (`amr=pwd` for a password-only sign-in),
`AuthorizeController` copies the session's `amr` into access tokens, and `DeviceVerificationController` now does the
same for device-flow tokens (it used to force `amr=pwd`). Sessions and tokens issued in the target tenant on verified
evidence carry `amr=mfa` on, so a further hop (grandchild tenant, chained exchange) can rely on it. Whether the source
user needs a second factor is decided by `CrossTenantAuthenticationService` (`CrossTenantAuthResult.SourceUserRequiresSecondFactor`:
the user's own `TwoFactorEnabled`, or that of any tier of its `xt_` chain — a shadow user never has 2FA of its own).

| Entry point | Without evidence | How the second factor is proven |
| --- | --- | --- |
| Password login `POST /{B}/api/auth/login` (cross-tenant fallback) | `requiresTwoFactor: true`, no session | The same SPA 2FA step: `login-2fa` (TOTP), `login-2fa-email`, `login-recovery` on `/{B}/…` verify the code of the **source** user in the **source** tenant (`ICrossTenantSecondFactorVerifier`: a `UserManager` over the source tenant's repository — same token providers, time window, recovery-code redemption). A wrong code counts against the source user's lockout; a valid one resets it. The pending state is a data-protected cookie `.AspNetCore.Octo.CrossTenantTwoFactor` (5 min, bound to tenant B, same cookie policy as the framework's two-factor cookie). The B session then carries `amr=mfa`. |
| `POST /{A}/api/auth/cross-tenant-token` | `403` (the SPA sends the user to A's login, which asks for the second factor) | The A session must carry `amr=mfa`; the token payload records `SecondFactorVerified`. |
| `POST /{B}/api/auth/cross-tenant-login` | `Success=false` | Re-checked at redemption: 2FA enabled after the token was minted is caught. |
| `POST /{B}/api/auth/tenant-switch` | `Success=false` | The B session must carry `amr=mfa`. |
| Cross-tenant device approval (`/connect/deviceverification`) | `access_denied` ("Cross-tenant access denied") | The approving session must carry `amr=mfa`. |
| RFC 8693 token exchange | `403 access_denied`, `error_description` starts with `second_factor_required` | The subject token must carry `amr=mfa`; the exchanged token gets `amr=["token_exchange","mfa"]`. |

**No usable second factor (AB#7830):** a source user with two-factor enabled but no authenticator key (e.g. after a tenant clone, `UserTokens` is not exported) gets `secondFactorSetupRequired: true` and no session, on this path and on the local `POST /{tenant}/api/auth/login`. Only an authenticator key counts as usable. Recovery: an admin switches `TwoFactorEnabled` off; the user then enrols again.

Users without 2FA are unaffected. Not covered by the cross-tenant rule: a session that a "remember this machine"
cookie skipped the second factor for, and external-provider sign-ins (Google, Entra ID, …), carry no `amr=mfa`; a 2FA
user signed in that way is refused at the boundary (fail closed) and signs in once more with the second factor.
"Remember this machine" is not offered for the source user's second factor on a child tenant.

**Hardening (AB#7861).**
- *Single-use challenge:* the cross-tenant challenge cookie carries a nonce; completing it (success, lockout, user gone),
  a logout and a successful local sign-in mark the nonce used (`ICrossTenantChallengeReplayGuard`, in process memory for
  the 5-minute cookie lifetime) and delete the cookie, so a copy of the cookie is void too. A challenge without a nonce
  (issued before this change) is void. With several identity pods a copy could still be replayed once on another pod; it
  would still need a valid second factor of the source user.
- *Fail-closed chain:* a gap in a shadow user's `xt_` chain — a tier user that no longer exists (root user renamed or
  deleted), a chain the resolver cannot unwind (deleted tenant, ambiguous prefix), an unreadable tier — now requires the
  second factor instead of adding nothing.
- *Server-only evidence:* `OctoUserStore.GetClaimsAsync` never returns a stored `amr` claim, so nothing that can write
  `RtUser.Claims` (an import, another service) can mint `amr=mfa`; the evidence comes only from the sign-in itself.
- *No cross-tenant provisioning on the device endpoint (AB#7884):* `DeviceVerificationController` used to provision a
  shadow user when the approving session's subject did not exist in the device code's tenant. The branch was unreachable
  (the session cookie is scoped to that tenant) and was removed; such an approval is now refused with `access_denied` and a
  warning. Cross-tenant device logins use a session in the child tenant (cross-tenant login) or the token exchange. The
  approval keeps passing the session's `amr` on, so a 2FA user's device token still carries `amr=mfa`.

**The evidence survives session refresh (AB#7859).** The security-stamp validator rebuilds the cookie principal from the
user every 30 minutes (`SecurityStampValidatorOptions.ValidationInterval`) and used to drop `amr`: after the first
revalidation every new token said `amr=pwd` and a 2FA user was refused at the boundaries above. `SessionClaimPreservation`
(registered as `OnRefreshingPrincipal`) copies the sign-in claims `amr`, `idp` and `sid` from the verified principal onto the
rebuilt one; user claims (roles, tenant) are still re-resolved. The refresh-token grant already kept `amr` (the stored
principal carries it, `TokenEndpointController.CopySessionClaims`); that is now pinned by a test. Tests:
`SecondFactorEvidenceRefreshTests` (the factory's `SecurityStampClock` steps 31 minutes ahead; session, new token and
`cross-tenant-token` after the revalidation; refresh grant), `SessionClaimPreservationTests`.

**Locked-out or disabled source users cross no boundary (AB#7855).** `ValidateCrossTenantAccessAsync` — called on every
crossing (cross-tenant-token, cross-tenant-login, tenant-switch, token exchange, completion of
the cross-tenant second factor) — refuses a source user that is locked out (`LockoutEnabled` and `LockoutEnd` in the future)
or that the sign-in rules refuse (`IdentityOptions.SignIn`: confirmed e-mail / phone / account, the rules
`SignInManager.CanSignInAsync` applies on the token endpoint; `RtUser` has no separate "disabled" flag). A shadow user is
judged with every tier of its `xt_` chain: locking the home user stops its shadows from crossing further. An existing
session, a cross-tenant token minted before the lock and an access token all stop working at the boundary. A chain tier whose
tenant cannot be read blocks nothing here (it already requires the second factor).

Tests: `tests/IdentityServices.IntegrationTests/Api/Auth/CrossTenantSecondFactorTests.cs` (real child tenant, real 2FA
enrollment, real authorization-code tokens; every entry point above, with and without 2FA), plus unit tests in
`CrossTenantAuthenticationServiceTests` and `CrossTenantLoginTests`.

### Cross-Tenant Shadow User Roles and Identity (AB#5708)

**Effective roles are computed at token time, never copied onto the shadow user.** Every token
issuance, refresh redemption and role check reads them through `OctoUserStore.GetRolesAsync` →
`IGroupRoleResolver.ResolveEffectiveUserRoleIdsAsync`:

```
effective roles(shadow user U in tenant B) =
      direct AssignedRole edges of U                       (manual assignments)
    ∪ roles of groups U is a member of
    ∪ for every ExternalTenantUserMapping M in B whose (SourceTenantId, SourceUserName)
      is a tier of U's name chain:
          M.MappedRoleIds
        ∪ roles of groups M is a member of                  (e.g. TenantOwners)
```

The name chain unwinds the `xt_` prefixes (`CrossTenantShadowUserName.GetSourceChain`):
`xt_karlplus_xt_meshmakers_gerald` → `(karlplus, xt_meshmakers_gerald)`, `(meshmakers, gerald)`.
Every tier is the same person — the rule already used by the token exchange (AB#4966) and
`allowed_tenants` — so a mapping an admin created for the home identity also applies when the
person arrives through the parent's shadow user.

**Tenant ids may contain `_`** (`TenantContext.ValidateTenantIdFormat`), so the name alone is
ambiguous: `xt_evil_xt_meshmakers_gerald` is also the shadow of the ordinary user
`meshmakers_gerald` of tenant `evil_xt`. A split at the first `_` would hand that user gerald's
mappings (and gerald's shadow user). The chain is therefore unwound by
`ICrossTenantShadowUserChainResolver`, which splits each tier only after a prefix that is a
**registered** tenant id (`ISystemContext.IsTenantRegisteredAsync`) and stops — fail closed — when
no registered tenant fits (deleted tenant) or more than one does (`a` and `a_b` both exist). This
also makes the mappings of users from underscore tenants resolve at all. **Every** consumer of the
convention uses this resolver — `GroupRoleResolver`, `CrossTenantUserProvisioningService`,
`AllowedTenantsResolver`, `TenantExchangeProcessor` and the `home_tenant_id` claim
(`OctoTokenClaimsService`). On an ambiguous or unregistered prefix each fails closed:

| Consumer | Fail-closed behaviour |
| --- | --- |
| Effective roles (`GroupRoleResolver`) | only mappings of the tiers proven so far count |
| `FindCrossTenantUserAsync` | the candidate is not treated as the same person |
| `allowed_tenants` | the chain ends there: login tenant + tiers proven so far (+ their mapped descendants) |
| Token exchange | no home-tenant candidate; only the immediate source identity is judged |
| `home_tenant_id` | the claim is omitted; consumers fall back to `tenant_id` (user treated as local) |

Normal logins are never affected: the login tenant itself is always allowed, and a well-formed
shadow name of a registered tenant unwinds exactly as before.

**Why tenant ids are not restricted instead.** Forbidding `xt` / `xt_*` (or `_` altogether) in tenant
ids would have to live in the engine (`TenantContext.ValidateTenantIdFormat`, octo-construction-kit-engine)
and would still leave existing underscore tenants ambiguous. The registry-aware split makes it
unnecessary: a tier is only accepted when **exactly one** registered tenant id fits, so a name cannot
unwind into a tenant that does not exist, and a collision between two existing tenants (`a` and `a_b`)
grants nothing instead of the wrong identity. Creating a tenant whose id makes an existing name
ambiguous therefore only *removes* access derived from that name (fail closed) — it never adds any.

Consequences:

- A role a blueprint adds to `TenantOwners` (`IdentityAssociationMigration.EnsureTenantOwnersGroupAsync`)
  or to any group the mapping is in reaches cross-tenant owners on their next token — no manual
  group edit. Before AB#5708 only groups containing the **user** counted, and `MappedRoleIds` (a
  snapshot of the roles that existed at tenant creation) was copied onto the user at login.
- Removing a mapping from a group, a role from a group, or a role from `MappedRoleIds` takes the
  role away on the next token. Manually assigned direct roles and direct group memberships of the
  shadow user are untouched.
- Roles copied onto shadow users by the former `SyncMappedRolesAsync` are ordinary direct
  `AssignedRole` edges and stay until an admin removes them (they cannot be told apart from manual
  assignments).

**One shadow user per person.** The source identity depends on the login path: the password login
unwinds to the home tenant (`xt_meshmakers_gerald`), a tenant switch or auto-login starts at the
parent's shadow user (`xt_karlplus_xt_meshmakers_gerald`). `FindCrossTenantUserAsync` returns the
exactly named shadow user if it exists; otherwise any shadow user whose chain unwinds to the same
home identity (case-insensitive) and that has **no password** — shortest chain first. Only when
none exists is a new one created. Legacy duplicates keep working unchanged: each login path still
finds its own exactly named user, and both now receive the mapping roles.

**Reserved prefix.** Because the name chain is trusted as identity, `xt_` is reserved:
`UsersController` rejects creating a user with it and renaming a user into it, `IdentityProvidersController`
rejects provider names `xt` / `xt_*` (JIT names are `{provider}_{email}`), and the JIT login moves a
legacy provider with such a name out of the namespace (`External_xt…`). Only
`CrossTenantUserProvisioningService` creates `xt_` users.

**No passwords for shadow users.** A shadow user authenticates in its home tenant; a local password
would add a second way into the tenant that bypasses the home tenant's login, MFA and account
lifecycle (and `FindCrossTenantUserAsync` would stop treating the user as the person's shadow user).
`ShadowUserPasswordValidator` is registered as an Identity password validator, so every
`UserManager` path that stores a password fails for `xt_` users — create with password, the admin
`POST users/ResetPassword` (answered up front with `400`), self-service `manage/change-password` and
`manage/set-password` (answered up front with `Success=false`), and the e-mail
`auth/reset-password`. The message is "Cross-tenant users (user names starting with 'xt_') sign in
through their home tenant and cannot have a password."

### Tenant Switch Flow

A user signed in to tenant B as a cross-tenant shadow user can re-establish the B session from one of their own
source identities without re-entering credentials. **The source identity is always the caller's own** (AB#7815): it is
the tier of the signed-in user's `xt_` name chain that lives in `SourceTenantId`; the request may name only that tenant
and, optionally, repeat that tier's user id — any other `SourceUserId` is refused (`Success=false`, a
`Tenant Switch Failure` audit entry). Before AB#7815 the source user was taken from the request body, so any user with
a B session could sign in as the shadow of any user of an ancestor tenant. A local (non-shadow) B user has no source
identity and cannot switch. The second-factor rule above applies. No client in the platform calls this endpoint today
(the SPA uses cross-tenant-token / cross-tenant-login, non-interactive clients the token exchange).

```
GET /{tenantId}/api/auth/accessible-tenants
        │
        └── Returns child tenants where user has role mappings
        │
        ▼
POST /{targetTenantId}/api/auth/tenant-switch
        │
        ├── Source identity = the caller's own xt_ chain tier in SourceTenantId (never the body's user)
        ├── Validate source tenant is ancestor of target
        ├── Find user in source tenant
        ├── Source user has 2FA ──► session must carry amr=mfa
        ├── Return mapped roles for target tenant
        │
        ├── Access denied ──► 200 { success: false }
        │
        └── Access granted ──► 200 { success: true, roles: [...] }
```

### Cross-Tenant Token Exchange (RFC 8693, AB#4338)

For **non-interactive** clients (the MCP server), the browser tenant-switch flow above is replaced by
an OAuth 2.0 Token Exchange grant. It lets an already-authenticated user obtain a **target-tenant (B)
access token** from their current **home-tenant (A) access token** — no browser, no credential prompt —
with roles **re-resolved in B**.

```
POST /connect/token
  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  subject_token={A access token}
  subject_token_type=urn:ietf:params:oauth:token-type:access_token
  acr_values=tenant:{B}
  client_id=octo-mcpServices-device
        │
        ├── OidcTenantResolutionMiddleware reads acr_values=tenant:B and wires B's repo into
        │   HttpContext.Items (same branch as client_credentials)
        ▼
  TokenEndpointController → TenantExchangeProcessor (src/IdentityServices/OpenIddict/;
  RFC 8693 is a first-class OpenIddict flow — replaces the Duende TenantExchangeGrantValidator)
        ├── (a) Validate subject_token → extract A sub, tenant_id=A, username
        ├── (b) Read target B from acr_values; assert HttpContext tenant == B (fail closed → invalid_target)
        ├── (c) ValidateCrossTenantAccessAsync(B, A, subA) → null ⇒ unauthorized_client
        ├── (c2) source user has 2FA and subject token has no amr=mfa ⇒ access_denied
        │       (error_description starts with second_factor_required, AB#7804)
        ├── (d) FindOrCreateCrossTenantUserAsync(result, B) → B-shadow user (xt_A_user)
        │       (AB#4966 dual-candidate source selection preserved)
        └── Build the principal with subject = B-shadow user's RtId
        │
        ▼
  OpenIddict mints the token for the B-shadow sub → OctoTokenClaimsService / OctoUserStore stamp
  tenant_id=B + B's allowed_tenants + B-resolved roles automatically (same claim path as a login)
```

**Security linchpin.** The issued token runs on the **B-shadow user's** `sub` (`xt_{A}_{user}`),
**never** the A user with a swapped `tenant_id`. Because the per-tenant profile / role stores key off
that subject, the token carries B-resolved roles (the subset granted by B's
`RtExternalTenantUserMapping`), so A's roles cannot leak into B. A naive re-scope of the A token would
be a privilege escalation and is rejected by design. This is pinned by the
`Exchange_ResolvesBSubsetRoles_NotParentFullRoles` integration test.

**v1 issues no exchanged refresh token** — B access tokens are short-lived and re-exchanged from the
still-valid A token on expiry, sidestepping cross-tenant refresh-token binding (A stays the single
long-lived credential / root of trust).

**Audit.** `TokenExchangeSuccessEvent` / `TokenExchangeFailureEvent` carry
`{sourceUserId, sourceTenantId, targetTenantId, shadowRtId/reason}`.
Failure events are persisted to the runtime event log by `IIdentityAuditService` (which replaced the
Duende `IEventService`/`OctoEventSink`); success events are log-only — behavior unchanged.

**Client enablement.** The `octo-mcpServices-device` client (rtId 660…034) carries the token-exchange
grant in its `AllowedGrantTypes` via the `System.Identity.Bootstrap` blueprint. This is additive client
config — no CK schema change. The MCP server performs ALL exchanges with the device client, regardless
of how the user originally logged in (device flow or a DCR-registered client) — the subject_token is
validated context-free with `ValidateAudience=false`, so it is not bound to the exchanging client. The
interim `octo-mcpServices-interactive` client (rtId 660…035) was removed again in blueprint 1.1.5:
interactive MCP clients self-register via Dynamic Client Registration (`octo-dcr-*`), and nothing
ever consumed the static client (its fixed `:8976` loopback redirects never matched Claude Code's
random-port callbacks).

**octo-cli (AB#6839, blueprint 1.8.0).** The `octo-cli` client (rtId 660…31, public, no secret) carries
the token-exchange grant next to `device_code`, so an operator signed in to the root tenant can
exchange that token for a child-tenant token (`acr_values=tenant:{child}`, `client_id=octo-cli`) instead
of presenting the root token to a child route. Child tenants get the grant from their own seeded
`octo-cli` and from the `AutoProvisionInChildTenants` mirror (which copies `AllowedGrantTypes`).

*Existing tenants (AB#6839).* The seed alone does not reach a tenant that already has the client:
`Client.AllowedGrantTypes` is `TenantOwned` (AB#6324), so the blueprint import keeps the stored value and
the 1.8.0 apply logs `updated=0` for it. Identity therefore runs a one-time, additive step per tenant at
every start (`OctoCliTokenExchangeGrant`, called from `SetupTenantAsync` after the blueprint apply and the
client-mirror provisioning): it appends the token-exchange URN to `AllowedGrantTypes` of the `octo-cli`
client and changes nothing else (no other grant, attribute or client). It logs one line per tenant
(`AB#6839 octo-cli token-exchange grant: tenant=… result=Added|AlreadyPresent|ClientMissing|AlreadyDone`)
and records a run-once marker (tenant configuration `OctoCliTokenExchangeGrant`) once the client was handled,
so a grant an administrator removes later stays removed. A tenant without an `octo-cli` client records no
marker and is retried on the next setup. Root and child tenants both run the step; a child whose
`octo-cli` is a mirror ends with the grant even when its parent is not fixed yet (the step runs after the
mirror copy). Mirrors are re-synced from the root on every identity start and on every client update.

**Ancestry is not authority — provisioning is a required operator step.** The exchange proves that the
caller's tenant is an ancestor of the target; it grants no role. The roles of the issued token are those
of the B-shadow user in B: an explicit `ExternalTenantUserMapping` (roles or groups), a group membership
or a direct role. For an operator this means **`octo-cli ProvisionCurrentUser -ttid {child}` once per child
tenant, also for newly created tenants**; there is no implicit admin role for ancestor users (decision
2026-10-17). A caller that is an ancestor user but holds no role in the target is refused at the exchange:

```
HTTP 403
{ "error": "access_denied",
  "error_description": "tenant_not_provisioned: the user holds no role in tenant '{child}'; ..." }
```

Clients match on `error=access_denied` plus the `tenant_not_provisioned` prefix of the description (a stable
marker; the text after it may change). A caller whose tenant is not an ancestor still gets
`unauthorized_client`, an invalid subject token `invalid_grant`. Exchanged tokens never carry a refresh
token — re-exchange from the root token. Every refusal is persisted as a `Token Exchange Failure` audit event.

#### Only access tokens are subject tokens (AB#7860)

Both `subject_token` consumers — the token exchange (`TenantExchangeProcessor`) and the on-behalf-of grant
(`OnBehalfOfProcessor`) — validate with `SubjectTokenValidation.ForAccessToken`: signature, issuer, lifetime **and** the JWT
header `typ` = `at+jwt` (RFC 9068; OpenIddict writes access tokens that way, id_tokens with `typ: JWT`). An id_token of a
client with `AlwaysIncludeUserClaimsInIdToken` carries `sub`, `tenant_id` and `amr` like an access token and travels in
places access tokens do not (e.g. `id_token_hint`). For the RFC 8693 exchange OpenIddict already refuses it before the
processor runs ("The specified token is not an access token", verified over HTTP for a declared `access_token`, a declared
`id_token` and no declared type); the processor check is defence in depth. The on-behalf-of grant is a custom flow
OpenIddict does not validate, so there the processor check is the only one. The audience stays unchecked (platform
convention). Tests: `CrossTenantSecondFactorTests.TokenExchange_IdTokenAsSubjectToken_IsRefused`,
`TenantExchangeSubjectTokenTypeTests`, `OnBehalfOfProcessorTests.IdTokenAsSubjectToken_IsRejectedAsInvalidGrant`.

### Delegation / On-Behalf-Of (AB#5026)

A **service account** (a machine-to-machine `Client`) can obtain an access token that runs on a
**user's** identity, so work it performs on that user's behalf is attributable to the user and bounded
by what *both* parties may do. This is the non-interactive counterpart of "act as this user" — it is
**not** an impersonation grant: the service account can never exceed its own authority.

```
POST /connect/token
  grant_type=urn:meshmakers:params:oauth:grant-type:on-behalf-of
  client_id={service account}          ← authenticated with its own client credentials
  client_secret={...}
  subject_token={the user's access token}
  subject_token_type=urn:ietf:params:oauth:token-type:access_token
  acr_values=tenant:{tenantId}
        │
        ├── OidcTenantResolutionMiddleware reads acr_values=tenant:{tenantId} and wires that
        │   tenant's repository into HttpContext.Items (same branch shape as client_credentials)
        ▼
  TokenEndpointController → OnBehalfOfProcessor (OpenIddict custom flow, AllowCustomFlow)
        ├── (a) Reject offline_access → invalid_scope (a refreshed token could not re-evaluate
        │       the intersection; see "Refresh tokens are rejected" below)
        ├── (b) Validate subject_token out-of-context (signature + issuer + lifetime,
        │       ValidateAudience=false) → extract sub + tenant_id
        ├── (c) Same-tenant gate: acr_values tenant == HttpContext tenant == subject_token tenant_id,
        │       else fail closed → invalid_target
        ├── (d) IDelegatedIdentityResolver.ResolveAsync(client_id, sub)
        │        ├── service-account roles: IClientRoleStore.GetEffectiveRoleNamesAsync
        │        ├── user roles:            OctoUserStore.GetRolesAsync (IUserRoleStore<RtUser>)
        │        └── effective = INTERSECTION (case-insensitive on role names)
        └── DelegationOutcome(userSubjectId, tenantId, effectiveRoleNames)
        │
        ▼
  TokenEndpointController.HandleOnBehalfOfAsync:
        populates the USER's claims (IOctoTokenClaimsService.PopulateUserClaimsAsync), then
        OnBehalfOfProcessor.ApplyDelegationClaims strips the naturally resolved role claims,
        emits the intersection as `role` and `act` = the service account's client_id;
        amr = "delegation", offline_access scope removed
```

**The intersection is the whole point.** The delegated token carries
`role = serviceAccountRoles ∩ userRoles`. A broadly privileged service account acting for a
low-privilege user gets the user's narrow set; a narrow service account acting for an administrator
gets the service account's narrow set. Both sides are resolved with the platform's normal effective-role
machinery, so **group-inherited roles (including nested groups) count on both sides**.

**Why the role replacement has to intervene.** The token is issued for the *user's* `sub`, and
`PopulateUserClaimsAsync` resolves that user's **full** role set — exactly as for a login. Left in
place, those claims would make the intersection a no-op and the grant a placebo that hands out the
user's full authority. `OnBehalfOfProcessor.ApplyDelegationClaims` therefore **replaces** every
`role` claim on the issued identity with the intersection. This is pinned by
`tests/IdentityServices.UnitTests/Services/DelegationClaimCompositionTests.cs`.

**Empty intersection ⇒ a token with no roles.** This is a successful grant, not an error: the token is
issued, carries `act` and `sub` but no `role` claim, and every role-gated consumer therefore fails
closed. Keeping the failure at the authorization boundary (where it is diagnosable) is deliberate;
turning a role misconfiguration into an opaque token-endpoint error is not.

**`act` claim.** Carries the service account's `client_id` as a flat string (RFC 8693 models `act` as a
nested object; the flat form is what the consuming pipelines need — widening it later is a breaking
change for consumers). It is added unconditionally to `IssuedClaims`, the same mechanism that gets
`tenant_id` / `allowed_tenants` into tokens although neither appears in the `octoAPI` ApiResource's
user claims — its access-token destination comes from `OctoClaimsDestinations`, so **no blueprint
or resource-claim change is required** for it.

**Own grant-type URN — deliberately not the RFC 8693 token-exchange one.** The grant type is the
per-client opt-in surface (`AllowedGrantTypes` → grant-type permission), so a shared URN would also
share the opt-in — and the RFC 8693 URN already belongs to the cross-tenant exchange.
The only client carrying `urn:ietf:params:oauth:grant-type:token-exchange` today is
`octo-mcpServices-device`, a **public client with no secret** (`RequireClientSecret: false`, empty
`Secrets`) — under a shared URN that secretless client could mint delegated tokens. Separate URNs keep
the two capabilities as separate, individually auditable `AllowedGrantTypes` entries.

**Same tenant only (v1).** The tenant in `acr_values`, the `tenant_id` of the `subject_token` and the
tenant the request was wired to must all match (case-insensitively); any divergence is rejected with
`invalid_target`. Cross-tenant delegation (v2) would have to answer which tenant's role catalogue the
intersection is taken in and how the service account proves reach into the other tenant. To move a
user identity across tenants today, use the cross-tenant **token exchange** grant above.

**Client enablement.** The calling client must list
`urn:meshmakers:params:oauth:grant-type:on-behalf-of` in its `AllowedGrantTypes` —
`ClientPermissionsMapper` turns that into the custom-flow grant permission, and OpenIddict rejects
the request before the token controller runs otherwise. Seeding the actual pipeline service account (client,
secret and roles) is **AB#5027** — AB#5026 ships the grant only.

**Refresh tokens are rejected, not merely discouraged.** A delegation request that carries
`offline_access` among its scopes is refused with `invalid_scope`, and the rejection is persisted
to the runtime event log as a delegation-failure audit entry. Delegated tokens are short-lived and re-minted from the still-valid user
token instead.

*Why it has to be a hard refusal.* The role intersection is computed **at issuance**, inside
`OnBehalfOfProcessor`. A later `grant_type=refresh_token` request rebuilds the access token from the
**stored principal** and, by design, never re-enters this processor — there is no `subject_token` to
re-validate and no hook to recompute anything. The intersection would therefore be frozen at first
issuance, and a role revoked on **either** side (service account or user) would keep working for the
refresh token's whole lifetime — exactly the authority creep the intersection exists to prevent. A
documented warning is not an invariant, so the grant enforces it by construction.

*Two layers enforce it.* The processor refuses an explicit `offline_access` request with an
explained `invalid_scope` (an unexplained missing `refresh_token` in the response would cost the
integrator an afternoon of guessing), and `HandleOnBehalfOfAsync` additionally removes the
`offline_access` scope from the issued principal, so OpenIddict never mints a refresh token even if a
future change lets the scope slip through. Relying instead on `AllowOfflineAccess=false` on every
delegating client would be a seeding convention, not an invariant — any operator can flip it back on.
Pinned by `tests/IdentityServices.UnitTests/Services/OnBehalfOfProcessorTests.cs`.

**Error mapping:**

| Condition | OAuth error |
|---|---|
| No authenticated client on the request | `invalid_client` |
| `offline_access` among the requested scopes | `invalid_scope` |
| Missing `subject_token`, wrong `subject_token_type`, missing `acr_values` | `invalid_request` |
| `subject_token` invalid/expired, or lacking `sub` / `tenant_id` | `invalid_grant` |
| Request tenant ≠ `acr_values` tenant, or `subject_token` tenant ≠ requested tenant | `invalid_target` |
| Service account not provisioned in the tenant | `invalid_client` |
| Subject does not resolve to a user in the tenant | `invalid_grant` |
| Empty role intersection | *no error* — token issued without `role` claims |

**Audit.** A delegation failure is persisted to the runtime event log by `IIdentityAuditService` as a
"Delegation Failure" entry carrying `{actorClientId, userSubjectId, tenantId, reason}`; success is
log-only, matching the audit behaviour of the other grants. (The Duende-era `DelegationSuccessEvent` /
`DelegationFailureEvent` pair and the `OctoEventSink` that expanded their structured fields were
removed with the OpenIddict migration.) A successful grant with **zero** effective roles is still
logged as a success carrying `effectiveRoleCount = 0`.

**Key files:**

| File | Purpose |
|---|---|
| `src/IdentityServerPersistence/Services/IDelegatedIdentityResolver.cs` | Result / denial-reason contract |
| `src/IdentityServerPersistence/Services/DelegatedIdentityResolver.cs` | The protocol-free intersection policy |
| `src/IdentityServices/Services/DelegationConstants.cs` | Grant URN, `act` claim type |
| `src/IdentityServices/OpenIddict/OnBehalfOfProcessor.cs` | Protocol adapter + `ApplyDelegationClaims` (role replacement) |
| `src/IdentityServices/Controllers/Protocol/TokenEndpointController.cs` | `HandleOnBehalfOfAsync` — issues the delegated principal |
| `src/IdentityServices/Middleware/OidcTenantResolutionMiddleware.cs` | `acr_values` → tenant for the new grant |

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

When `/connect/authorize` determines the user isn't authenticated (or consent is required), the passthrough `AuthorizeController` (`Controllers/Protocol/`) issues the login/consent redirect **directly with the correct tenant prefix**, e.g. `/{tenantId}/login?ReturnUrl=...`. The tenant comes from `acr_values=tenant:{tenantId}` (resolved by `OidcTenantResolutionMiddleware`).

The former `TenantLoginRedirectMiddleware` — which intercepted Duende IdentityServer's hard-coded 302 redirects to `/{systemTenantId}/login` and rewrote the tenant prefix — was **deleted** in the OpenIddict migration: since the redirects are now built by our own controller, there is nothing to rewrite.

**Without `acr_values`:** The `OidcTenantResolutionMiddleware` redirects to `/tenant-discovery?returnUrl={authorizeUrl}` where the user can enter their email/username to discover their tenant. After tenant selection, the flow restarts with `acr_values` appended. A `octo_last_tenant` cookie shortcuts this on repeat visits.

**Configuration:** The system tenant ID comes from `IOptions<OctoSystemConfiguration>`. A server-side redirect in `Program.cs` routes the root path `/` to `/{systemTenantId}/login`.

### Auto-Creation of OctoTenantIdentityProvider

When a child tenant has a `ParentTenantId` set on its `RtTenant` record, the `RtOctoTenantIdentityProvider` is automatically created:

- **New tenants**: During `SetupTenantAsync`, after CK model import and role creation
- **Existing tenants**: Via the `OctoTenantIdentityProviderMigration` (migration version 8→9)

Both mechanisms are idempotent — they check for an existing provider before creating one.

## Per-Tenant Identity Data Provisioning

### Problem

The identity service resolves clients, API scopes, API resources, and identity resources from the **current tenant's database**. When a user accesses a child tenant (e.g., `meshtest`), the OAuth flow calls `/{tenantId}/connect/authorize` which looks up the client in that tenant's MongoDB. If the client doesn't exist there, the flow fails.

### Solution

Identity data is automatically provisioned to **all tenants** (not just the system tenant) during service startup:

**Identity Service** (`DefaultConfigurationCreatorService`):
- Creates identity resources (`openid`, `profile`, `email`, `role`), API scopes, API resources, and clients (`octo-cli`, swagger, `octo-data-refinery-studio`) directly in each child tenant's database during `SetupTenantAsync`
- Uses the child tenant's repository for direct writes (not via the message bus)

**Other Services** (Asset Repository, Communication Controller, Bot, Reporting):
- Send their client, scope, and resource definitions to the Identity Service via `CreateIdentityDataCommandRequest` messages on the Distribution Event Hub
- The `DefaultConfigurationCreatorServiceStandardized` base class sends these messages for **every tenant** during startup
- The `CreateIdentityDataCommandRequestConsumer` in the Identity Service creates the data in the correct tenant's database

### Data Created Per Tenant

| Entity Type | Created By | Examples |
|-------------|-----------|----------|
| Identity Resources | Identity Service | `openid`, `profile`, `email`, `role` |
| Identity API Scopes | Identity Service | `identityAPI.full_access`, `identityAPI.read_only` |
| Identity Clients | Identity Service | `octo-cli`, `octo-idenityServices-swagger`, `octo-data-refinery-studio`* |
| Asset Repo Clients | Asset Repository Service | `octo-assetRepositoryServices`, swagger client |
| Communication Clients | Communication Controller | swagger client |
| Bot Clients | Bot Service | `octo-botServices`, swagger client |
| Reporting Clients | Reporting Service | `octo-reportingServices`, swagger client |

*\* Only provisioned when `RefineryStudioUrl` is configured in `OctoIdentityServicesOptions`.*

### Refinery Studio Client

The `octo-data-refinery-studio` client is a public SPA (no client secret) using Authorization Code + PKCE. Unlike other service clients, the Refinery Studio has no .NET backend that auto-provisions itself. The identity service provisions this client directly when `RefineryStudioUrl` is configured:

- **Environment variable**: `OCTO_IDENTITY__RefineryStudioUrl=https://studio.example.com`
- **Grant type**: Authorization Code with PKCE
- **Scopes**: `openid`, `profile`, `email`, `role`, `assetSystemAPI.full_access`, `identityAPI.full_access`, `botAPI.full_access`, `communicationSystemAPI.full_access`, `communicationTenantAPI.full_access`, `reportingSystemAPI.full_access`, `reportingTenantAPI.full_access`
- **Offline access**: Enabled (refresh tokens)
- **Front-channel logout**: `{RefineryStudioUrl}/logout/callback`

### Version Tracking

- **System tenant**: Uses a configuration version key to avoid re-sending data on every restart
- **Child tenants**: Always ensures data exists (the consumer is idempotent — creates if missing, replaces if existing)

## Per-Tenant Cookie Scoping

### Problem

Without cookie scoping, all tenants share a single `Identity.Application` auth cookie at path `/`. When a user logs into tenant "sbeg", the cookie is sent for all tenant routes. Navigating to `/octosystem/manage` sends the same cookie, but `UserManager` looks up the user in octosystem's database — user not found — 404.

### Solution: TenantCookieManager

A custom `ICookieManager` (`src/IdentityServices/Cookies/TenantCookieManager.cs`) wraps `ChunkingCookieManager` and appends `.{tenantId}` (lowercased) to scoped cookie names based on `HttpContext.Items["tenantId"]`.

Cookie schemes are defined in `OctoAuthSchemes` (`src/Authentication/`): `Identity.Application` (the tenant-scoped session cookie) and `Identity.External` (external-login handshake). The Duende-era `idsrv` / `idsrv.session` / `idsrv.external` cookies **no longer exist** since the OpenIddict migration.

**Scoped cookies** (tenant suffix added):
- `.AspNetCore.Identity.Application` → `.AspNetCore.Identity.Application.sbeg`

**Global cookies** (unchanged):
- `Identity.External` — written at `/signin-google` (no tenant in URL)
- `Identity.TwoFactorUserId`, `Identity.TwoFactorRememberMe` — short-lived, single login flow

### Server-Side Session Tickets

Auth cookies carry only a short **server-side session key** (hundreds of bytes) rather than the full encrypted ticket (~3 KB per tenant). The ticket itself is stored server-side in MongoDB per tenant via the CK runtime (`RtServerSideSession`). This was introduced to fix cookie-bloat on OAuth loopback-callback servers (e.g., the CLI device-auth flow and backend OIDC clients) that rejected responses containing several large per-tenant cookies.

Since the OpenIddict migration, the store is `OctoTicketStore : ITicketStore` (`src/IdentityServices/OpenIddict/`) — standard ASP.NET Core machinery. It persists data-protected tickets in the same per-tenant `RtServerSideSession` CK type (new serialization; the Duende `ServerSideSessionStore` was deleted). The `sid` claim is stamped at session creation. Expired sessions are swept by `TokenCleanupHostService` (system tenant + all child tenants).

`TenantCookieManager` naming convention (`.AspNetCore.Identity.Application.{tenantId}`) is **unchanged** — browsers and clients see the same cookie name as before.

Session lifetime is controlled by `ExpireTimeSpan = 7 days` sliding on `ConfigureApplicationCookie`. Both the browser cookie and the server-side record share this window, so sliding expiry (activity extends the session) behaves identically to the old full-ticket approach from a user perspective. Logout and inactivity expiry semantics are unchanged: explicit logout removes the session record immediately; an expired record is treated as missing on the next request, causing re-authentication.

### OIDC Endpoint Tenant Resolution

OIDC endpoints (`/connect/*`) don't include a `{tenantId}` route segment. The `OidcTenantResolutionMiddleware` resolves the tenant before authentication:

| Endpoint | Tenant Source |
|----------|--------------|
| `/connect/par` | `acr_values=tenant:{tenantId}` from form body (RFC 9126 Pushed Authorization Request); captures `request_uri` from JSON response → tenant mapping |
| `/connect/authorize` | `request_uri` query parameter → tenant mapping (captured during PAR); fallback to `acr_values=tenant:{tenantId}` from query string; captures `code` → tenant mapping from both 302 redirects (`response_mode=query`) and 200 HTML responses (`response_mode=form_post`) |
| `/connect/token` (authorization_code, device_code, refresh_token) | Authorization code / device code / refresh token → tenant mapping (captured earlier); for refresh tokens, `acr_values=tenant:{tenantId}` from the form body is **preferred** when the client sends it; sets tenant context for user/client lookups |
| `/connect/token` (client_credentials, token exchange) | `acr_values=tenant:{tenantId}` from form body — **required**; without it the client lookup falls back to the system tenant, so tenant-registered clients fail with `invalid_client`, and a **mirrored** client id is refused outright with `invalid_request` (AB#5058, see below) |
| `/connect/deviceauthorization` | `acr_values` / client context; captures `user_code` → tenant mapping and rewrites `verification_uri` to the SPA page `/{tenantId}/device` (with `?userCode=`) |
| `/connect/deviceverification` | `user_code` (query or form body) → tenant mapping captured during device authorization |
| `/connect/endsession` | `id_token_hint` JWT payload → `tenant_id` claim; fallback to `acr_values` |

**Pushed Authorization Request (PAR, RFC 9126):** When the client uses PAR, it POSTs the full set of authorization parameters (including `acr_values=tenant:{tenantId}`) to `/connect/par`. The server returns a `request_uri` (e.g., `urn:ietf:params:oauth:request_uri:...`); the subsequent `/connect/authorize` call carries only `request_uri` on the URL, no `acr_values`. The middleware extracts the tenant from the form body during `/connect/par`, captures the issued `request_uri` from the JSON response, and stores the mapping (5-minute lifetime). On `/connect/authorize?request_uri=...`, the middleware looks up the tenant from this mapping before falling back to query-string `acr_values`. PAR is enabled automatically by `Microsoft.AspNetCore.Authentication.OpenIdConnect` (.NET 9+) when the IdP advertises `pushed_authorization_request_endpoint` in its discovery document — which OpenIddict does (as Duende did before). This capture stage, like the authorization-code and refresh-token stages, is golden-verified against OpenIddict's response shapes.

**Authorization code → tenant mapping:** During `/connect/authorize`, the middleware wraps the response body to capture the authorization code and maps it to the resolved tenant ID in an in-memory `ConcurrentDictionary`. This supports both `response_mode=query` (code extracted from the 302 redirect `Location` header) and `response_mode=form_post` (code extracted from the hidden `<input name='code'>` field in the 200 HTML response). The `form_post` mode is used by server-side OIDC clients such as the Asset Repository Services' GraphQL Playground. When `/connect/token` is called with `grant_type=authorization_code`, the middleware reads the `code` from the form body, looks up the tenant from the mapping, and sets the correct tenant context. This ensures `OctoUserStore`, `ClientStore`, and other per-tenant stores use the correct tenant database during the token exchange. The mapping entries expire after 10 minutes and are cleaned up opportunistically.

**Refresh token → tenant mapping (in-memory only, preferring `acr_values`):** Clients that know their tenant (the SPAs) send `acr_values=tenant:{tenantId}` with every refresh-token request — the preferred, restart-safe path. As a fallback, when `/connect/token` returns a successful response containing a `refresh_token`, the middleware captures the token and maps it to the current tenant ID in the in-memory cache (entries expire after 30 days) and looks it up on the next refresh. There is **no persistent hash fallback anymore** — the former SHA-256 lookup against the system-tenant `RtPersistedGrant` store was retired together with centralized grant storage (grants now live per tenant in `RtOAuthAuthorization`/`RtOAuthToken` via the OpenIddict stores).

The middleware runs after routing, before the OpenIddict endpoints handle the request:

```
UseRouting()
→ inline middleware (re-resolve tenant from route values)
→ UseOidcTenantResolution()
→ authentication / OpenIddict server endpoints (passthrough protocol controllers)
```

### tenant_id Claim

`OctoTokenClaimsService` (`src/IdentityServices/OpenIddict/`) adds a `tenant_id` claim to identity tokens. This claim is used by `OidcTenantResolutionMiddleware` to extract the tenant from `id_token_hint` during logout (`/connect/endsession`).

### OIDC Session Management (check_session_iframe)

Logout propagation to other tabs and SPAs works via OIDC Session Management (Duende parity —
OpenIddict has no built-in support): the server-side session issues a browser-readable
`idsrv.session[.tenant]` cookie (`SessionCheckCookie`, managed by `OctoTicketStore`), authorize
responses carry a `session_state` hash (`OctoSessionStateHandler`), and RPs poll the
`/connect/checksession` iframe (`CheckSessionController`), which recomputes the hash from the
cookie. A logout deletes the cookie, the iframe answers `changed`, and polling clients
(angular-oauth2-oidc with `sessionChecksEnabled: true`) end their session. The hash formula in
handler and iframe script must stay in sync.

### Claim Destinations

`OctoClaimsDestinations.ForClient(bool alwaysIncludeUserClaimsInIdToken)` decides which claims flow into the access token vs. the id token. For clients with `AlwaysIncludeUserClaimsInIdToken = true` (e.g. Refinery Studio), the user claims (`role`, `tenant_id`, `allowed_tenants`, `home_tenant_id`, `name`, `preferred_username`, `email`, `family_name`, `given_name`) are additionally emitted into the id token — SPAs based on angular-oauth2-oidc read the user identity from id-token claims and enter a login redirect loop if they are missing.

**Client-credentials tokens (AB#5032).** The `tenant_id` claim has a single producer, the user claims
path, which a `client_credentials` token never reaches because it has no subject — so such a token
carried no `tenant_id` at all, which is why the backend tenant gates skipped them entirely, letting
any client-credentials client of this authority address any tenant.
`ClientCredentialsTenantProcessor` (`IdentityServices/OpenIddict/`) now decides the issuing tenant and
`TokenEndpointController.HandleClientCredentialsAsync` stamps it onto the issued identity: the tenant
from `acr_values=tenant:{tenantId}` when present, otherwise the system tenant (the directory the
client store actually resolved the client from). It is stamped before the roles, so a client without
roles gets it too, and `OctoClaimsDestinations` routes it into the **access** token. Pinned on the
wire by the golden baseline (`client-credentials-access-token.json`). Consumers narrow their exemption
behind `TenantAuthorizationOptions.ServiceTokenEnforcement` in octo-common-services — default
`Enforce` since AB#5077, i.e. a service token addressing a foreign tenant is answered with 403.
Setting `LogOnly` restores the migration behaviour: unchanged request outcomes plus an audit line
per foreign-tenant access.

**Ambiguous tenant binding is refused, not guessed (AB#5058).** The "otherwise the system tenant"
half of the rule above rested on the idea that the directory which resolved the client is also the
tenant the client belongs to. Client mirroring breaks that: `AutoProvisionInChildTenants` provisions
the **same** `ClientId` with the **same** secret into every child tenant, so for a mirrored client id
"found in the system tenant" says nothing about where the caller belongs — a caller holding a child
tenant's credentials could omit `acr_values` and receive a system-tenant token, making every
"is the caller in the system tenant" gate satisfiable with a service token.

`ClientCredentialsTenantProcessor` therefore decides the binding **server-side** before any claim is
composed, from state the caller cannot influence:

| Signal | Source | Verdict |
|---|---|---|
| `RtClient.AutoProvisionInChildTenants` | the resolved client record | ambiguous — declared fleet credential |
| `RtClient.ProvisionedByParentTenantId` | the resolved client record | ambiguous — the record *is* a mirror |
| `RtClientMirror` rows for the client id | system tenant | ambiguous — mirrors already materialized |
| none of the above | — | unambiguous — system tenant stamped, as before |

An ambiguous request is answered with `invalid_request` and the description
*"acr_values=tenant:{tenantId} is required for this client: its client id exists in more than one
tenant, so the issuing tenant cannot be determined from the request."*, and is audited as a
"Client Credentials Tenant Ambiguity" entry which `IIdentityAuditService` persists to the runtime
event log (carrying the client id and the machine-readable reason). A failure of the mirror lookup itself **fails
closed** — falling back to "system" there would reopen the hole. The probe runs only on the
no-`acr_values` path, so callers that name their tenant (mesh adapter, AI services, octo-cli, the
token-exchange and on-behalf-of grants) are untouched, as are unmirrored clients that omit it.

⚠️ **Residual risk.** A mirror shares the parent's secret, so whoever holds a mirror's credentials
also holds the parent's and can request the system tenant *explicitly*. No check at the token
endpoint can tell those callers apart; the credential is instance-wide by construction of the
mirroring feature. The processor logs a warning whenever a mirroring source obtains a system-tenant
token, and system-route authorization must not treat `tenant_id == systemTenant` on a
client-credentials token as proof of provenance on its own. A real fix requires per-tenant mirror
secrets — **started in AB#5061, see below; still open.**

### Per-Tenant Mirror Secrets (AB#5061) — step 1 of 2

Every mirror of a **confidential** parent client now additionally carries its **own** generated
secret, marked `Description = "octo:mirror-own-secret"`. Possession of it proves exactly one tenant,
which is what the residual risk above needs. Public clients — which is every mirrored client in the
shipped `System.Identity.Bootstrap` seed, plus every `octo-dcr-*` registration — are mirrored
unchanged and get no secret.

**Distribution.** Stored secrets are SHA-256 hashed and unrecoverable, so a secret that is never
handed out is a credential nobody can use. It is therefore issued on demand and returned exactly
once:

```
POST {parentTenantId}/v1/clients/{clientId}/mirrors/{childTenantId}/secret
→ 200 { "clientId": "...", "childTenantId": "...", "secret": "<plaintext, shown once>" }
→ 400 the parent client is public — nothing to issue
→ 404 no mirror is tracked for that pair
```

Requires `IdentityApiFullAccess` in the **parent** tenant. Calling it again rotates and retires the
previous value. Parent → child is legitimate delegation; the escalation being closed is the opposite
direction. Nothing recoverable is persisted, and no endpoint reads a mirror secret back.

🔴 **The own secret is preserved** across re-provisioning and across parent-side secret rotation.
Both paths rewrite the mirror from the parent's state, so without preservation every service restart
would silently invalidate every per-tenant credential issued so far.

⚠️ **The gap is not closed yet.** The inherited copy of the parent secret is *still accepted*,
because live fleet credentials authenticate with it against child tenants today — `ci-deploy` /
`ci-deploy-{cluster}` (the workload-deployment pipeline, one Vault credential pair per cluster),
`octo-ai-adapter` (`McpTokenIssuer`) and `claude-agent`. Removing it in the same step would break
every workload rollout on every cluster. **Until the follow-up step removes the inherited secret,
`tenant_id == systemTenant` on a client-credentials token remains unproven and AB#5055 stays
blocked.** The migration sequence and the open end-state decision are in
`docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md`.

Tests: `tests/IdentityServerPersistence.UnitTests/Services/ClientMirrorOwnSecretTests.cs` (own secret
distinct from the parent's, public client untouched, preservation across re-provisioning and parent
rotation, no sibling-tenant secret leak, no secret in the rendered log output, and an explicit
assertion that the inherited secret is *still* there),
`ClientMirrorSecretsTests.cs` (hash convention pinned against published SHA-256 digests — a
divergence would store rotated secrets in a shape the token endpoint cannot match) and
`tests/IdentityServices.IntegrationTests/Persistence/ClientMirrorProvisioningIntegrationTests.cs`
(the same over real MongoDB, plus rotation retiring the previous value).

**Integrator note.** If a `client_credentials` request that used to work now returns
`invalid_request`, add `acr_values=tenant:{tenantId}` to the token request — for example:

```bash
curl -s https://connect.example.com/connect/token \
  -d grant_type=client_credentials \
  -d client_id=<client-id> \
  -d client_secret=<secret> \
  -d scope=octo_api \
  -d acr_values=tenant:<tenantId>
```

### Client Mirroring — What It Is For, and What a Mirrored Credential Proves

Mirroring (`AutoProvisionInChildTenants`) is a **deliberate design property, not a defect**. A client
is described **once**, in one tenant, and thereby made available to that tenant's children.
Maintaining the same client per tenant instead would be a substantial configuration burden — every
redirect URI, scope, grant type and lifetime, repeated and kept in step across every tenant on the
instance, with a new tenant silently missing whatever was forgotten.

**Today it is used for OAuth clients — the interactive ones — not for authentication.** Every
client that carries the flag in the shipped `System.Identity.Bootstrap` seed
(`octo-data-refinery-studio`, `octo-cli`, the three Swagger clients, `octo-mcpServices-device`) and
every `octo-dcr-*` dynamic registration is a **public client with no secret at all**. What mirroring
distributes for them is a *login surface* — where users may sign in and where they get redirected
back to — not a credential. None of them can obtain a `client_credentials` token.

**Roles are not mirrored.** `ClientMirrorProvisioningService` copies `RtClient` *attributes*; it
touches no `AssignedRole` edge and no group membership. A mirrored client therefore arrives in the
child tenant **authenticated but without any rights**, until somebody grants it roles *there*
(`PUT {tenantId}/v1/clients/{clientId}/roles/{roleName}`, or `octo-cli AddClientToRole`). That is the
real boundary downwards, and it is the one to reason about: the mirror can prove who it is, and can
do nothing until the child tenant says what it may do.

🔴 **What a mirrored credential does *not* prove, while the inherited secret is still accepted.**
A confidential mirror carries both the copy of its parent's secret and (since AB#5061) one of its
own. As long as the inherited copy is valid, holding a *child's* credentials is indistinguishable
from holding the *parent's* — so **a `tenant_id` claim on a client-credentials token does not
establish which tenant the caller came from.** It records which tenant the token was *issued for*,
not which tenant the caller belongs to.

Consequences for anyone writing authorization:

- **Do not authorize on the tenant claim of a service token.** In particular, `tenant_id ==
  systemTenant` is not proof of system-tenant provenance — that is why the system-route hardening
  (**AB#5055**) is blocked on this and must not be built on the claim alone.
- **Authorize service tokens on roles instead** — the roles assigned to that client **in the tenant
  being addressed**. Those are per-tenant by construction (they are not mirrored, see above), so they
  say what this caller may do *here*, which is the question authorization actually asks.
- The claim remains correct and useful for *routing* and for the tenant gate's "is this token even
  addressed at this tenant" check. It is provenance that it cannot carry.

This is measured, not assumed: **AB#5065** records which of the two secrets each caller actually
uses (below). Once the inherited copy is gone, the tenant claim on a client-credentials token becomes
provenance and AB#5055 unblocks.

### Which Mirror Secret Was Used? (AB#5065) — step 3 of the migration

Step 4 — dropping the inherited secret from every mirror — is only defensible once it is *known* that
nobody authenticates with it any more, and until AB#5061 split the secrets there was nothing to tell
apart. `MirrorSecretUsageTelemetry` (`IdentityServices/OpenIddict/`) is that measurement.

**Where it hangs.** Under Duende this decorated `ISecretsListValidator`, the one service that saw the
presented credential and the client's whole secret list together. OpenIddict has no such service:
client authentication runs through `OpenIddictApplicationManager.ValidateClientSecretAsync`, so
`OctoApplicationManager` is now that place — it already owns the legacy-hash comparison and is the
only code that knows *which* stored `RtSecretRecord` matched. It calls the telemetry after the match;
nothing is accepted or rejected that would not have been before, and a failed authentication is
silent. The classification is then the marker on the matched record: `octo:mirror-own-secret` means
the caller holds the mirror's own secret, anything else means it matched an inherited one.

🔴 **The move came with a fix that is load-bearing on its own.** OpenIddict's application model
carries exactly **one** client secret, and `OpenIddictApplicationStore.GetClientSecretAsync` can only
project the *first* stored record. Duende validated against the whole list.
`OctoApplicationManager.ValidateClientSecretAsync(RtClient, secret, ct)` therefore iterates the stored
records itself — without it, whichever of a mirror's two secrets happened to be second would silently
stop authenticating, and which one that is depends on list order. The same applies to any client
mid-rotation.

Cost on the authentication hot path is bounded by design — **no store lookup and no new allocation
for anyone else**. The marker travels on the `RtSecretRecord` the manager already read, so the
decision is a string comparison over ≤2 records. A credential that is not a shared secret (private key
JWT, mTLS) never reaches this path at all — under Duende that had to be guarded explicitly, because
misreporting one as inherited use would have blocked step 4 forever.

Each use is recorded as:

```
MirrorSecretUsage secretKind=inherited clientId=ci-deploy tenantId=customer-a
```

with `MirrorSecretKind` / `ClientId` / `TenantId` as structured fields and event id `50650`.
Inherited use is logged at **Warning**, own use at Information — the inherited count is the number
that has to reach zero. Per environment (Dash0 dataset = cluster name, via the Dash0 UI or the
`mcp__dash0__sql` tool):

```sql
SELECT count() FROM logs
WHERE resource_attributes['k8s.container.name'] = 'identity'
  AND body LIKE '%MirrorSecretUsage%' AND body LIKE '%secretKind=inherited%'
```

answers *“does anybody still authenticate with the inherited secret?”*; grouping the same lines by
`clientId` / `tenantId` names who and where, which is the migration list for step 2.

🔴 **No secret material is ever written** — not the credential, not the stored hash, not a prefix of
either. Only the client id, the tenant and the literal `own` / `inherited`.

⚠️ **Blind spot, and it is a precondition rather than a false clean bill.** Mirror-ness is inferred
from the *presence* of an own secret, because reading `ProvisionedByParentTenantId` from a freshly
loaded record would be a database round trip
on every token request. A mirror that has no own secret yet — a public parent, or a confidential one
whose provisioning loop has not run since AB#5061 shipped — produces no record. Step 4 must not be
executed in that state anyway: every mirror holding its own secret is already the first row of the
migration table in `docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md`. **A zero inherited-use count is only
evidence once that precondition is verified per environment.**

Tests: `tests/IdentityServices.UnitTests/Services/MirrorSecretUsageTelemetryTests.cs` (both
classifications over the real `OctoApplicationManager` and real SHA-256 matching against real
`RtClient` records, the second-stored-secret regression, an expired record, no record for an ordinary
client or for a non-marker description, unchanged failure path, unresolved tenant marked rather than
guessed, a measurement failure not failing the authentication, no secret material in the *rendered*
log) and
`tests/IdentityServices.IntegrationTests/Persistence/ClientMirrorProvisioningIntegrationTests.cs`
(`MirrorSecretUsage_DistinguishesInheritedFromOwn_ThroughTheRealStoredRecords` — a mirror provisioned
into real MongoDB, read back through the repository and authenticated with **both** credentials
through the production manager, so a provisioning change that dropped `Description` cannot make the
measurement silently read zero).

### Key Behaviors

| Scenario | Behavior |
|----------|----------|
| External login (`/signin-google`) | External cookie remains global; auth cookie scoped at callback |
| Tenant switch | New tenant-scoped cookie written; old tenant cookie unaffected |
| Concurrent sessions | Each tenant has its own cookie; user can be logged into multiple tenants |
| `/connect/authorize` without `acr_values` | Redirects to `/tenant-discovery` for email-first tenant lookup |
| `/connect/endsession` without `id_token_hint` | No tenant; user appears unauthenticated |
| Existing global cookies after deploy | Not found by TenantCookieManager; users re-login (one-time) |

### Key Files

| File | Purpose |
|------|---------|
| `src/IdentityServices/Cookies/TenantCookieManager.cs` | Cookie name scoping by tenant |
| `src/IdentityServices/Middleware/OidcTenantResolutionMiddleware.cs` | Tenant resolution for `/connect/*` endpoints |
| `src/Authentication/OctoAuthSchemes.cs` | Cookie scheme definitions (`Identity.Application`, `Identity.External`) |
| `src/IdentityServices/OpenIddict/OctoTokenClaimsService.cs` | Adds `tenant_id`, `allowed_tenants`, `home_tenant_id`, roles, `aud` to tokens |
| `src/IdentityServices/OpenIddict/OctoTicketStore.cs` | Server-side session tickets (`RtServerSideSession`) |

## Group-Based Role Inheritance

### Overview

Groups provide an organizational unit for role management. Instead of assigning roles directly to each user, roles can be assigned to groups. Users who are members of a group inherit all roles assigned to that group. Groups can also contain other groups (nested groups), enabling hierarchical role inheritance.

All group relationships are stored as **CK associations** (not denormalized StringArray attributes), which is the idiomatic Octo CK approach for entity relationships.

### Data Model

The `RtGroup` CK type has:
- **Attributes**: `GroupName` / `NormalizedGroupName` (display/lookup), `GroupDescription` (optional)
- **Associations**:
  - `AssignedRole` → `RtRole`: Roles assigned to the group (N:N)
  - `GroupMember` → `RtUser`: Internal user members (N:N)
  - `GroupMember` → `RtExternalTenantUserMapping`: External tenant user members (N:N)
  - `ChildGroup` → `RtGroup`: Nested child groups (N:N)

The `RtUser` CK type also uses:
- `AssignedRole` → `RtRole`: Directly assigned roles (N:N)

### Role Resolution

During token issuance, `OctoUserStore.GetRolesAsync()` resolves both direct and group-inherited roles:

1. Query the user's outbound `AssignedRole` associations for directly assigned role IDs
2. Call `IGroupRoleResolver.ResolveEffectiveRoleIdsAsync(userRtId)`:
   - Load all groups and check `GroupMember` associations to find groups containing the user
   - Recursively follow `ChildGroup` associations to collect all `AssignedRole` targets from parent groups
   - Use a visited set and max depth (10) to prevent circular traversal
3. Merge both sets and resolve role IDs to role names
4. All resolved role names are included as JWT `role` claims

### Default TenantOwners Group

Every tenant is provisioned with a `TenantOwners` group that has all default roles assigned (via `AssignedRole` associations). This provides a convenient way to grant full permissions: add a user to `TenantOwners` instead of assigning 10+ roles individually.

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `IdentityAssociationConstants` | `IdentityServerPersistence/` | Association role ID constants (`AssignedRoleId`, `GroupMemberId`, `ChildGroupId`) |
| `IGroupStore` / `GroupStore` | `IdentityServerPersistence/SystemStores/` | CRUD + association-based relationship management for groups |
| `IGroupRoleResolver` / `GroupRoleResolver` | `IdentityServerPersistence/Services/` | Resolves effective role IDs from group memberships via associations |
| `GroupsController` | `IdentityServices/TenantApi/v1/Controllers/` | REST API for group management |
| `IdentityAssociationMigration` | `IdentityServerPersistence/Services/Migrations/` | Converts StringArray relationships to associations; creates TenantOwners group |

## Multi-Tenant Token Validation

### Overview

Access tokens contain `allowed_tenants` claims that list all tenants a user is authorized to access. Backend middleware validates the route tenant against these claims, ensuring tokens are only valid for authorized tenants.

### Architecture

```
Token Issuance (Login)
        │
        ▼
OctoTokenClaimsService (src/IdentityServices/OpenIddict/)
        │
        ▼
AllowedTenantsResolver.ResolveAsync()
        │
        ├── Always include the login tenant
        ├── For cross-tenant users (xt_): include home tenant
        ├── Get all child tenants from system context
        ├── For each child: check RtExternalTenantUserMapping
        └── Walk up ancestor chain via OctoTenantIdentityProvider.ParentTenantId
        │
        ▼
Access token includes: allowed_tenants: ["tenant1", "tenant2", ...]
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `IAllowedTenantsResolver` | `IdentityServerPersistence/Services/` | Resolves allowed tenants for a user |
| `AllowedTenantsResolver` | `IdentityServerPersistence/Services/` | Default implementation using cross-tenant mappings |
| `OctoTokenClaimsService` | `IdentityServices/OpenIddict/` | Stamps `tenant_id`, `allowed_tenants`, `home_tenant_id`, roles, `aud` on issued tokens |
| `TenantAuthorizationMiddleware` | `octo-common-services` | Validates route tenant against claims |

### AllowedTenantsResolver Algorithm

1. **Always include the login tenant** (the tenant the user authenticated against)
2. **Cross-tenant users** (`xt_{homeTenant}_{username}`): include the home tenant of every tier, split
   against the tenant registry (`ICrossTenantShadowUserChainResolver`, AB#5708); an ambiguous or
   unregistered prefix ends the chain (fail closed)
3. **Walk up ancestor chain**: Starting from the login tenant, query `RtOctoTenantIdentityProvider.ParentTenantId`, add each ancestor (max depth: 10, with circular reference protection)
4. **BFS down through descendants**: Starting from the source tenant (with original username) and login tenant (with login username), check child tenants for `ExternalTenantUserMapping` matching `SourceTenantId` + `SourceUserName`
5. **Follow the xt_ username chain**: When a child match is found, the user's username in the child tenant follows the pattern `xt_{parentTenantId}_{parentUsername}`. This propagated username is used to check further descendants.

This ensures cascading tenant hierarchies work correctly. Example: `octosystem → meshtest → subtenant1`:
- Mapping in meshtest: `sourceTenantId=octosystem, sourceUserName=admin`
- Mapping in subtenant1: `sourceTenantId=meshtest, sourceUserName=xt_octosystem_admin`
- User "admin" logging into octosystem → BFS finds meshtest (sourceUserName=admin), then subtenant1 (sourceUserName=xt_octosystem_admin)
- User "xt_octosystem_admin" logging into meshtest → BFS finds subtenant1 (sourceUserName=xt_octosystem_admin), ancestors add octosystem
- User logging into subtenant1 → ancestors add meshtest and octosystem

**Cost and caching (AB#6307, AB#6308):**
- Results are cached in `IMemoryCache` for 45 s (`CacheTtl`): the tenant registry list and every mapping probe
  (tenant, source tenant, source user → bool), negative results included, failures not.
- A mapping probe opens the child tenant's repository with `ISystemContext.GetRegisteredTenantRepository(OctoTenant)`
  from the cached registry entry. Unlike `FindTenantRepositoryAsync`, this does no I/O (no system-tenant existence
  probe with `listDatabases`/`listCollections`, no admin session, no system CK auto-import); a cache miss costs one
  query per child tenant.
- The probes of one BFS tier run with a parallelism of 8 (`MaxParallelProbes`); the matches are consumed in registry
  order, so the traversal — which parent claims a child first and thereby decides the `xt_` shadow user name of its
  descendants — is deterministic.

**Cross-tenant login, switch and exchange (AB#6393):** `CrossTenantAuthenticationService` only knows tenant ids
(password login walks the parent providers, `ValidateCrossTenantAccessAsync` and the `tenant_exchange` lookups walk
the provider graph and open the source tenant), so it used `FindTenantRepositoryAsync` per hop — the same 7–9
round trips. It now opens every tenant through `ITenantRegistry.TryGetRepositoryAsync(tenantId)`
(`TenantRegistry`): the registry list is read once per 45 s (`IMemoryCache`, shared with `AllowedTenantsResolver`)
and `GetRegisteredTenantRepository` builds the repository from the entry without I/O. The system tenant is not a
registry entry; its database name comes from the system context.
- **Fail closed:** a tenant id that is not in the registry yields no repository, so user lookups return `null`, the
  provider list is empty and the ancestor proof fails — nobody gains access through an unknown or unregistered
  tenant. A failing registry read is handled like any failed lookup (logged, `null`/empty).
- **Freshness:** a tenant created within the last 45 s is found because an unknown id triggers one registry re-read,
  at most once per 5 s (`TenantRegistry.MissRefreshInterval`), so a flood of unknown ids cannot amplify into a flood of
  registry reads. A tenant deleted within the TTL is still resolvable until the snapshot expires; its database is
  gone, so the lookup finds nothing.
- Sessions are now disposed after each lookup.

### TenantAuthorizationMiddleware

Placed after `UseAuthentication()` + `UseAuthorization()` in each service's pipeline:

- **Skips unauthenticated requests** (let auth middleware handle 401)
- **Skips client-credentials tokens** (no `sub` claim = service-to-service calls)
- **Skips requests without a route tenant** (system endpoints)
- **Denies access if no `allowed_tenants` claims** (old tokens before this feature)
- **Validates route tenant** against allowed list (case-insensitive comparison)

### Token Claims

```json
{
  "sub": "user-id",
  "tenant_id": "meshtest",
  "allowed_tenants": ["meshtest", "sbeg", "octosystem"],
  "home_tenant_id": "octosystem"
}
```

### Frontend Integration

The `AuthorizeService` in `@meshmakers/shared-auth`:
- Parses `allowed_tenants` from the access token JWT payload
- Exposes `allowedTenants` signal and `isTenantAllowed(tenantId)` method
- The tenant list data source filters tenants by `allowed_tenants`
- The HTTP error interceptor shows a user-friendly message on 403 responses

### Performance

The resolver runs **only at token issuance time** (login, token refresh), not per-request. The number of tenants is typically small (< 100), making the per-tenant mapping query acceptable.

## Dynamic Client Registration (RFC 7591) — AB#4338

Spec-compliant interactive MCP clients (e.g. Claude Code) require **RFC 7591 Dynamic Client
Registration** — they self-register a client at a `registration_endpoint` and do not accept a
pre-registered `client_id`. A hand-rolled `POST /connect/register` endpoint supports this. It is
**enabled by default** (`OCTO_IDENTITY__DYNAMICCLIENTREGISTRATION__ENABLED`, default `true`); set it to
`false` to disable per deployment, in which case the endpoint returns 404 and `registration_endpoint`
is not advertised in discovery. Default-on is acceptable because the gate below is strict (loopback-only
redirects → no phishing vector) and a registration alone grants no token.

**Endpoint:** `POST /connect/register` (anonymous, per-IP rate-limited). Runs in the **system tenant**
context. Returns 201 (created) / 200 (existing re-issued) / 400 (`invalid_redirect_uri` /
`invalid_client_metadata`) / 403 (per-tenant cap) / 404 (disabled).

**Security gate** (`DynamicClientRegistrationService`): registration is open (Claude Code sends no
initial access token) but hard-constrained — **loopback redirect URIs only** (`127.0.0.1` / `[::1]` /
`localhost`, http), **PKCE required**, **public client** (`token_endpoint_auth_method=none`, no secret),
grant fixed to `authorization_code` (+`refresh_token`), and a **server-fixed scope allow-list** (client
scopes are ignored). Per-IP rate limit + per-tenant cap + bounded TTL bound abuse.

**Tenant model — reuses the shipped tenant-specific auth, no new machinery:**
- The client is created in the **system tenant** with `DynamicRegistration=true` and
  `AutoProvisionInChildTenants=true`, then mirrored into every tenant (via
  `ClientMirrorProvisioningService`) — identical to the built-in `octo-mcpServices-*` clients.
- The client is tenant-agnostic; the **user's** `allowed_tenants` (not the client) grants tenant access.
  A DCR client sends `/connect/authorize` with no `acr_values`, so **§9 Email-First Tenant-Discovery**
  resolves the tenant; the mirrored client is found in whatever tenant the user selects. Switching
  tenants afterwards is the usual token + per-call tenant selection, not a new login.

**Lifecycle:** `DynamicRegistrationExpiresAt` (registration + `ClientTtlDays`, default 90d) bounds
lifetime. An expired dynamic client is not resolved for protocol purposes — `OpenIddictApplicationStore`
applies the same enabled + DCR-TTL gate that `ClientStore.FindClientByIdAsync` applied under Duende
(immediate enforcement → `unauthorized_client`) — and `TokenCleanupHostService` erases expired dynamic clients +
their mirrors each cleanup interval. `PreBlueprintCleanupMigration` never sweeps a
`DynamicRegistration=true` client. Registrations with an identical redirect-URI set are **deduped**
(the existing non-expired client is re-issued) to avoid per-launch accumulation.

**Management-surface exposure:** `ClientsController.CreateClientDto` emits `DynamicRegistration` +
`DynamicRegistrationExpiresAt` read-only on the shared `ClientDto` (SDK ≥ the AB#4338 bump), so
Studio / octo-cli / MCP tools can mark dynamic clients. `ApplyToClient` never reads them back —
accepting them would let a caller move an ordinary client into (or a dynamic client out of) the
DCR TTL lifecycle, bypassing the hard gate.

**Scopeless authorize requests are defaulted:** some interactive MCP clients (observed with Claude
Code) send `GET /connect/authorize` without a `scope` parameter even though the protected-resource
metadata advertises `scopes_supported`; without a default, such a request would yield no usable
scopes (under Duende it was hard-rejected with "scope is missing").
`DcrDefaultScopeMiddleware` (registered before the OpenIddict endpoints handle the request) injects the server-fixed DCR
scope set (`DynamicClientRegistration.AllowedScopes`) into the query string when an `octo-dcr-*`
client omits `scope` — permitted by RFC 6749 §3.3 (server-defined default scope) and grants nothing
the client could not have requested, since DCR scopes are server-fixed at registration anyway.
Non-DCR clients are never touched.

See `docs/CONCEPT-MCP-DYNAMIC-CLIENT-REGISTRATION.md` for the full design and phasing.

## Authorize Error Page (AB#4950)

When `/connect/authorize` fails validation, the browser is redirected to
`{tenantId}/error?errorId=<opaque>`. The `errorId` is a self-contained DataProtection-protected
payload — it carries the error, not a database key — and is resolved through
`IOctoInteractionService.GetErrorContext` (`src/IdentityServices/OpenIddict/Interaction/`), which is a
non-destructive read, so the page survives a reload and is multi-pod safe (no server-side message
store).

`GET {tenantId}/api/auth/error-context?errorId=…` (`AuthApiController.GetErrorContext`, anonymous)
resolves it and classifies the failure into `ErrorContextDto.Kind`:

| Kind | Condition | What the page says |
|---|---|---|
| `unknown` | No id, or the id no longer resolves | Generic text; nothing is looked up |
| `clientNotRegistered` | `ClientId` is set but no **enabled** client of that id exists in the route tenant | The application is not registered, or not enabled, for this workspace |
| `invalidRedirectUri` | Client is known and the failure names `redirect_uri` | The application sent a return address not registered for it here |
| `generic` | Anything else | The protocol error's own wording |

Two rules this endpoint deliberately follows:

- **The back-link comes only from the registered client's `ClientUri`, never from the failed request's
  `redirect_uri`.** The cases that land here are exactly "this client could not be validated" and "this
  redirect_uri is not registered", so rendering the caller-supplied address as a link would make the
  identity domain an open redirect and a phishing surface. The error payload deliberately never
  carries the caller-supplied `redirect_uri` — that omission is load-bearing, do not change it. A
  disabled client is not offered as a destination either.
- **Classification comes from the client lookup, not from matching the English description.**
  `unauthorized_client` is emitted for unrelated causes too. The lookup stays inside the route tenant;
  whether the same client exists in another tenant is never revealed, and the wording merges
  "not registered" with "not enabled" because the enabled-filtering lookup cannot tell them apart.

The SPA (`features/error/error.component.ts`) calls the endpoint only when an `errorId` is present and
falls back to the pre-existing `?error=`/`?errorDescription=` query parameters — which the external-login
callback still produces — whenever it is absent or the call fails. Raw OAuth codes, the description and
the request/activity ids live in a collapsed "Technical details" block rather than in the headline.

## Resource Indicators (RFC 8707) — AB#5193

Clients that discover this authority through RFC 9728 protected-resource metadata — today the
interactive MCP clients (Claude Code) talking to `octo-mcp-service` — send a `resource` parameter
naming the API they want the token for, on `/connect/authorize`, `/connect/par` and
`/connect/token` (including the silent refresh).

The parameter is validated against the **requesting tenant's API resources**, not against a static
list. `OctoResourceValidationHandlers` (`IdentityServices/OpenIddict/`) replaces OpenIddict's three
built-in `ValidateResources` handlers and resolves each indicator through
`IOpenIddictResourceStore<RtApiResource>` → `OpenIddictResourceStore`
(`IdentityServerPersistence/SystemStores/OpenIddict/`) → `IOctoResourceStore`. An indicator is
accepted when it is statically registered (`RegisterResources(...)`, unused today), or names an
**enabled** `RtApiResource` of that tenant that carries at least one of the **requested scopes**;
a request without a `scope` parameter (refresh renewal) is judged on registration alone. Anything
else is rejected with `invalid_target` / OpenIddict's ID2190 wording.

A **trailing slash is insignificant** in that comparison — the blueprint seeds the MCP resource
with one, the MCP metadata advertises it without — but nothing else is normalized.

There is **no cache and no invalidation event**: entity caching is off process-wide, so a resource
created or disabled through the TenantApi or a blueprint apply takes effect on the next request.

OpenIddict's companion check `ValidateResourcePermissions` (ID2192) is removed along with them: it
looks for a per-client `rsrc:{resource}` permission, and `RtClient` has no allowed-resources field
that `ClientPermissionsMapper` could project one from, so it could only ever reject. The rule it
would have enforced — a client reaches an API resource through its scopes — is the scope relation
above.

🔴 The indicator does **not** shape the issued token. Audiences come from the granted scopes
(`OctoTokenClaimsService.ResolveAudiencesAsync`), the pre-migration format pinned by the golden
baseline. If that ever changes, the per-client resource allow-list becomes load-bearing again.

Full rationale, the OpenIddict 8.x upgrade path and the measured before/after baseline:
`docs/CONCEPT-RESOURCE-INDICATORS.md`.


## Security Considerations

### Scheme Isolation
Authentication schemes are tenant-prefixed (`{tenantId}:{providerName}`) so each tenant's identity providers are isolated in the singleton `IAuthenticationSchemeProvider`. The `AuthApiController` filters schemes by tenant prefix, ensuring that only the current tenant's providers are shown on the login page. External authentication uses a temporary cookie scheme (`IdentityConstants.ExternalScheme`) that is cleared after processing.

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
