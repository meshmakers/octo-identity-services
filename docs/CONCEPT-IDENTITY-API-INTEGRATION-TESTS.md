# Concept: Identity API Integration Tests

This document describes the concept for integration tests that verify all Identity Server API endpoints.

## 1. Overview

### 1.1 Purpose

The integration tests ensure that all Identity Server API endpoints work correctly. This includes authentication, authorization, consent flows, device authorization, grants management, and user profile management.

### 1.2 API Controllers to Test

| Controller | Route | Purpose |
|------------|-------|---------|
| `AuthApiController` | `/{tenantId}/api/auth` | Login, Logout, External Login, Password Reset |
| `ConsentApiController` | `/{tenantId}/api/consent` | OAuth consent flow (grant/deny) |
| `DeviceApiController` | `/{tenantId}/api/device` | Device authorization flow |
| `GrantsApiController` | `/{tenantId}/api/grants` | View and revoke client grants |
| `ManageApiController` | `/{tenantId}/api/manage` | User profile, password, external logins |

## 2. Test Infrastructure

### 2.1 Existing Infrastructure (Reuse)

- **`CustomWebApplicationFactory`**: WebApplicationFactory with MongoDB TestContainer
- **`IntegrationTestBase`**: Base class with HTTP client and helper methods
- **`TestAuthHandler`**: Custom authentication handler for simulating authenticated users
- **`TestSigningCredentialStore`**: In-memory RSA key for token signing
- **Builders**: `RtUserBuilder`, `RtClientBuilder` for test data creation

### 2.2 Required Extensions

#### 2.2.1 Extended IntegrationTestBase

```csharp
public abstract class IntegrationTestBase : IClassFixture<CustomWebApplicationFactory>
{
    // Existing members...

    /// <summary>
    /// Creates an HTTP client that simulates an authenticated user
    /// </summary>
    protected HttpClient CreateAuthenticatedClient(
        string userId = "test-user-id",
        string userName = "testuser",
        string email = "test@example.com",
        IEnumerable<string>? roles = null,
        IEnumerable<string>? scopes = null);

    /// <summary>
    /// Creates an unauthenticated HTTP client (no Bearer token)
    /// </summary>
    protected HttpClient CreateAnonymousClient();

    /// <summary>
    /// Creates a test user in the database
    /// </summary>
    protected Task<RtUser> CreateTestUserAsync(
        string userName,
        string email,
        string password,
        bool emailConfirmed = true);

    /// <summary>
    /// Creates a test OAuth client in the database
    /// </summary>
    protected Task<RtClient> CreateTestClientAsync(
        string clientId,
        string? frontChannelLogoutUri = null,
        IEnumerable<string>? allowedScopes = null);

    /// <summary>
    /// Creates a persisted grant (refresh token) in the database
    /// </summary>
    protected Task<RtPersistedGrant> CreatePersistedGrantAsync(
        string subjectId,
        string clientId,
        string grantType = "refresh_token");
}
```

#### 2.2.2 New Builders

**RtPersistedGrantBuilder**

```csharp
public class RtPersistedGrantBuilder
{
    public RtPersistedGrantBuilder WithKey(string key);
    public RtPersistedGrantBuilder WithSubjectId(string subjectId);
    public RtPersistedGrantBuilder WithClientId(string clientId);
    public RtPersistedGrantBuilder WithGrantType(string grantType);
    public RtPersistedGrantBuilder WithExpiration(DateTime expiration);
    public RtPersistedGrantBuilder WithSessionId(string sessionId);
    public RtPersistedGrant Build();
}
```

## 3. Test Categories by Controller

---

### 3.1 AuthApiController Tests

Location: `tests/IdentityServices.IntegrationTests/Api/Auth/`

#### 3.1.1 AuthApiLoginTests.cs

```csharp
public class AuthApiLoginTests : IntegrationTestBase
{
    // === Login Context ===

    [Fact]
    public async Task GetLoginContext_WithoutReturnUrl_ReturnsDefaultContext()

    [Fact]
    public async Task GetLoginContext_WithValidReturnUrl_ReturnsClientInfo()

    [Fact]
    public async Task GetLoginContext_WithClientRestrictions_ReturnsFilteredProviders()

    [Fact]
    public async Task GetLoginContext_WhenAuthenticated_ReturnsAuthenticatedStatus()

    // === Login ===

    [Fact]
    public async Task Login_WithValidCredentials_ReturnsSuccessWithRedirectUrl()

    [Fact]
    public async Task Login_WithInvalidPassword_ReturnsErrorMessage()

    [Fact]
    public async Task Login_WithUnknownUser_ReturnsErrorMessage()

    [Fact]
    public async Task Login_WithEmptyCredentials_ReturnsValidationError()

    [Fact]
    public async Task Login_WithLockedOutUser_ReturnsLockedOutStatus()

    [Fact]
    public async Task Login_WithTwoFactorRequired_ReturnsTwoFactorStatus()

    [Fact]
    public async Task Login_WithRememberMe_SetsRememberLoginFlag()

    // === External Login ===

    [Fact]
    public async Task GetExternalProviders_ReturnsConfiguredProviders()

    [Fact]
    public async Task ExternalLogin_WithValidScheme_ReturnsChallengeResult()

    [Fact]
    public async Task ExternalLogin_WithInvalidScheme_ReturnsBadRequest()
}
```

#### 3.1.2 AuthApiLogoutTests.cs

```csharp
public class AuthApiLogoutTests : IntegrationTestBase
{
    // === Logout Context ===

    [Fact]
    public async Task GetLogoutContext_WithValidLogoutId_ReturnsContext()

    [Fact]
    public async Task GetLogoutContext_WithoutLogoutId_ReturnsDefaultContext()

    [Fact]
    public async Task GetLogoutContext_WithClientName_ReturnsClientInfo()

    // === Logout ===

    [Fact]
    public async Task Logout_WithAuthenticatedUser_ReturnsSuccessAndRevokesTokens()

    [Fact]
    public async Task Logout_WithMultipleRefreshTokens_RevokesAllTokens()

    [Fact]
    public async Task Logout_WithNoRefreshTokens_CompletesSuccessfully()

    [Fact]
    public async Task Logout_ReturnsSignOutIframeUrl()

    [Fact]
    public async Task Logout_ReturnsPostLogoutRedirectUri()

    [Fact]
    public async Task Logout_WithUnauthenticatedUser_ReturnsSuccess()
}
```

#### 3.1.3 AuthApiPasswordResetTests.cs

```csharp
public class AuthApiPasswordResetTests : IntegrationTestBase
{
    // === Forgot Password ===

    [Fact]
    public async Task ForgotPassword_WithValidEmail_ReturnsSuccess()

    [Fact]
    public async Task ForgotPassword_WithUnknownEmail_ReturnsSuccessToPreventEnumeration()

    [Fact]
    public async Task ForgotPassword_WithEmptyEmail_ReturnsError()

    [Fact]
    public async Task ForgotPassword_GeneratesResetToken()

    // === Reset Password ===

    [Fact]
    public async Task ResetPassword_WithValidToken_ResetsPassword()

    [Fact]
    public async Task ResetPassword_WithInvalidToken_ReturnsError()

    [Fact]
    public async Task ResetPassword_WithExpiredToken_ReturnsError()

    [Fact]
    public async Task ResetPassword_WithMismatchedPasswords_ReturnsError()

    [Fact]
    public async Task ResetPassword_WithEmptyFields_ReturnsError()

    [Fact]
    public async Task ResetPassword_WithWeakPassword_ReturnsValidationErrors()

    // === Validate Reset Token ===

    [Fact]
    public async Task ValidateResetToken_WithValidToken_ReturnsTrue()

    [Fact]
    public async Task ValidateResetToken_WithInvalidToken_ReturnsFalse()

    [Fact]
    public async Task ValidateResetToken_WithExpiredToken_ReturnsFalse()

    [Fact]
    public async Task ValidateResetToken_WithEmptyParams_ReturnsFalse()
}
```

---

### 3.2 ConsentApiController Tests

Location: `tests/IdentityServices.IntegrationTests/Api/Consent/`

#### 3.2.1 ConsentApiTests.cs

```csharp
public class ConsentApiTests : IntegrationTestBase
{
    // === Get Consent Context ===

    [Fact]
    public async Task GetConsentContext_WithValidReturnUrl_ReturnsClientAndScopes()

    [Fact]
    public async Task GetConsentContext_WithInvalidReturnUrl_ReturnsNotFound()

    [Fact]
    public async Task GetConsentContext_ReturnsIdentityScopes()

    [Fact]
    public async Task GetConsentContext_ReturnsApiScopes()

    [Fact]
    public async Task GetConsentContext_RequiresAuthentication()

    // === Grant Consent ===

    [Fact]
    public async Task GrantConsent_WithValidScopes_ReturnsSuccessAndRedirectUrl()

    [Fact]
    public async Task GrantConsent_WithNoScopes_ReturnsValidationError()

    [Fact]
    public async Task GrantConsent_WithInvalidReturnUrl_ReturnsError()

    [Fact]
    public async Task GrantConsent_WithRememberConsent_PersistsConsent()

    [Fact]
    public async Task GrantConsent_RaisesConsentGrantedEvent()

    // === Deny Consent ===

    [Fact]
    public async Task DenyConsent_WithValidReturnUrl_ReturnsSuccessAndRedirectUrl()

    [Fact]
    public async Task DenyConsent_WithInvalidReturnUrl_ReturnsError()

    [Fact]
    public async Task DenyConsent_RaisesConsentDeniedEvent()
}
```

---

### 3.3 DeviceApiController Tests

Location: `tests/IdentityServices.IntegrationTests/Api/Device/`

#### 3.3.1 DeviceApiTests.cs

```csharp
public class DeviceApiTests : IntegrationTestBase
{
    // === Get Device Context ===

    [Fact]
    public async Task GetContext_WithValidUserCode_ReturnsDeviceContext()

    [Fact]
    public async Task GetContext_WithInvalidUserCode_ReturnsNotFound()

    [Fact]
    public async Task GetContext_WithExpiredUserCode_ReturnsNotFound()

    [Fact]
    public async Task GetContext_WithoutUserCode_ReturnsBadRequest()

    [Fact]
    public async Task GetContext_RequiresAuthentication()

    [Fact]
    public async Task GetContext_ReturnsClientInfoAndScopes()

    // === Authorize Device ===

    [Fact]
    public async Task Authorize_WithValidUserCode_ReturnsSuccess()

    [Fact]
    public async Task Authorize_WithInvalidUserCode_ReturnsError()

    [Fact]
    public async Task Authorize_WithSelectedScopes_GrantsOnlySelectedScopes()

    [Fact]
    public async Task Authorize_WithRememberConsent_PersistsConsent()

    [Fact]
    public async Task Authorize_RaisesConsentGrantedEvent()

    // === Deny Device ===

    [Fact]
    public async Task Deny_WithValidUserCode_ReturnsSuccess()

    [Fact]
    public async Task Deny_WithInvalidUserCode_ReturnsError()

    [Fact]
    public async Task Deny_RaisesConsentDeniedEvent()
}
```

---

### 3.4 GrantsApiController Tests

Location: `tests/IdentityServices.IntegrationTests/Api/Grants/`

#### 3.4.1 GrantsApiTests.cs

```csharp
public class GrantsApiTests : IntegrationTestBase
{
    // === Get Grants ===

    [Fact]
    public async Task GetGrants_WithNoGrants_ReturnsEmptyList()

    [Fact]
    public async Task GetGrants_WithGrants_ReturnsGrantInfo()

    [Fact]
    public async Task GetGrants_ReturnsClientNameAndLogo()

    [Fact]
    public async Task GetGrants_ReturnsIdentityAndApiScopes()

    [Fact]
    public async Task GetGrants_ReturnsCreatedAndExpirationDates()

    [Fact]
    public async Task GetGrants_RequiresAuthentication()

    // === Revoke Grant ===

    [Fact]
    public async Task RevokeGrant_WithValidClientId_ReturnsSuccess()

    [Fact]
    public async Task RevokeGrant_WithEmptyClientId_ReturnsError()

    [Fact]
    public async Task RevokeGrant_RemovesGrantFromList()

    [Fact]
    public async Task RevokeGrant_RaisesGrantsRevokedEvent()

    [Fact]
    public async Task RevokeGrant_WithNonExistentClientId_ReturnsSuccess()
}
```

---

### 3.5 ManageApiController Tests

Location: `tests/IdentityServices.IntegrationTests/Api/Manage/`

#### 3.5.1 ManageApiProfileTests.cs

```csharp
public class ManageApiProfileTests : IntegrationTestBase
{
    // === Get Profile ===

    [Fact]
    public async Task GetProfile_WithAuthenticatedUser_ReturnsProfileInfo()

    [Fact]
    public async Task GetProfile_ReturnsExternalLogins()

    [Fact]
    public async Task GetProfile_ReturnsHasPasswordFlag()

    [Fact]
    public async Task GetProfile_ReturnsTwoFactorStatus()

    [Fact]
    public async Task GetProfile_RequiresAuthentication()

    // === Get External Logins ===

    [Fact]
    public async Task GetExternalLogins_WithNoLogins_ReturnsEmptyList()

    [Fact]
    public async Task GetExternalLogins_WithLogins_ReturnsLoginInfo()

    // === Get Available Providers ===

    [Fact]
    public async Task GetAvailableProviders_ReturnsConfiguredProviders()

    [Fact]
    public async Task GetAvailableProviders_ExcludesProvidersWithNoDisplayName()
}
```

#### 3.5.2 ManageApiPasswordTests.cs

```csharp
public class ManageApiPasswordTests : IntegrationTestBase
{
    // === Change Password ===

    [Fact]
    public async Task ChangePassword_WithValidCurrentPassword_ReturnsSuccess()

    [Fact]
    public async Task ChangePassword_WithInvalidCurrentPassword_ReturnsError()

    [Fact]
    public async Task ChangePassword_WithMismatchedPasswords_ReturnsError()

    [Fact]
    public async Task ChangePassword_WithWeakPassword_ReturnsValidationErrors()

    [Fact]
    public async Task ChangePassword_RefreshesSignIn()

    // === Set Password ===

    [Fact]
    public async Task SetPassword_WithNoExistingPassword_ReturnsSuccess()

    [Fact]
    public async Task SetPassword_WithExistingPassword_ReturnsError()

    [Fact]
    public async Task SetPassword_WithMismatchedPasswords_ReturnsError()

    [Fact]
    public async Task SetPassword_WithWeakPassword_ReturnsValidationErrors()

    [Fact]
    public async Task SetPassword_RefreshesSignIn()
}
```

#### 3.5.3 ManageApiExternalLoginTests.cs

```csharp
public class ManageApiExternalLoginTests : IntegrationTestBase
{
    // === Add External Login ===

    [Fact]
    public async Task AddExternalLogin_WithValidScheme_ReturnsChallengeResult()

    [Fact]
    public async Task AddExternalLoginCallback_WithValidInfo_AddsLogin()

    [Fact]
    public async Task AddExternalLoginCallback_WithInvalidInfo_RedirectsWithError()

    // === Remove External Login ===

    [Fact]
    public async Task RemoveExternalLogin_WithValidLogin_ReturnsSuccess()

    [Fact]
    public async Task RemoveExternalLogin_WithOnlyLogin_ReturnsErrorIfNoPassword()

    [Fact]
    public async Task RemoveExternalLogin_WithPasswordSet_AllowsRemoval()

    [Fact]
    public async Task RemoveExternalLogin_RefreshesSignIn()
}
```

---

## 4. Unit Tests

Location: `tests/IdentityServerPersistence.UnitTests/Stores/`

### 4.1 PersistentGrantStoreTests.cs

```csharp
public class PersistentGrantStoreTests
{
    // === StoreAsync ===

    [Fact]
    public async Task StoreAsync_WithNewGrant_InsertsGrant()

    [Fact]
    public async Task StoreAsync_WithExistingGrant_UpdatesGrant()

    // === GetAsync ===

    [Fact]
    public async Task GetAsync_WithExistingKey_ReturnsGrant()

    [Fact]
    public async Task GetAsync_WithNonExistentKey_ReturnsNull()

    // === GetAllAsync ===

    [Fact]
    public async Task GetAllAsync_WithSubjectFilter_ReturnsMatchingGrants()

    [Fact]
    public async Task GetAllAsync_WithClientFilter_ReturnsMatchingGrants()

    [Fact]
    public async Task GetAllAsync_WithTypeFilter_ReturnsMatchingGrants()

    [Fact]
    public async Task GetAllAsync_WithMultipleFilters_ReturnsMatchingGrants()

    // === RemoveAsync ===

    [Fact]
    public async Task RemoveAsync_WithExistingKey_RemovesGrant()

    [Fact]
    public async Task RemoveAsync_WithNonExistentKey_DoesNotThrow()

    // === RemoveAllAsync ===

    [Fact]
    public async Task RemoveAllAsync_WithSubjectFilter_RemovesAllMatchingGrants()

    [Fact]
    public async Task RemoveAllAsync_WithNoMatchingGrants_DoesNotThrow()

    [Fact]
    public async Task RemoveAllAsync_WithMultipleGrants_RemovesAll()

    [Fact]
    public async Task RemoveAllAsync_WithSubjectAndClientFilter_RemovesOnlyMatching()

    // === RemoveExpiredGrantsAsync ===

    [Fact]
    public async Task RemoveExpiredGrantsAsync_RemovesExpiredGrants()

    [Fact]
    public async Task RemoveExpiredGrantsAsync_KeepsValidGrants()

    [Fact]
    public async Task RemoveExpiredGrantsAsync_HandlesConcurrentDeletion()
}
```

---

## 5. Test Data Factories

Location: `tests/IdentityServices.IntegrationTests/Helpers/`

### 5.1 TestUsers.cs

```csharp
public static class TestUsers
{
    public const string DefaultPassword = "Test123!";
    public const string DefaultPasswordHash = "..."; // Pre-computed hash

    public static RtUser CreateStandardUser(string userName = "testuser") =>
        new RtUserBuilder()
            .WithUserName(userName)
            .WithEmail($"{userName}@example.com")
            .WithPasswordHash(DefaultPasswordHash)
            .WithEmailConfirmed()
            .Build();

    public static RtUser CreateLockedOutUser() =>
        new RtUserBuilder()
            .WithUserName("lockeduser")
            .WithEmail("locked@example.com")
            .WithLockedOut(DateTimeOffset.UtcNow.AddHours(1))
            .Build();

    public static RtUser CreateTwoFactorUser() =>
        new RtUserBuilder()
            .WithUserName("2fauser")
            .WithEmail("2fa@example.com")
            .WithTwoFactorEnabled()
            .Build();

    public static RtUser CreateExternalOnlyUser() =>
        new RtUserBuilder()
            .WithUserName("externaluser")
            .WithEmail("external@example.com")
            .WithLogin("Google", "google-id-123")
            .Build();
}
```

### 5.2 TestClients.cs

```csharp
public static class TestClients
{
    public static RtClient CreateSpaClient(string clientId = "test-spa") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithGrantTypes("authorization_code")
            .WithRedirectUris("https://localhost:4200/callback")
            .WithPostLogoutRedirectUris("https://localhost:4200/")
            .WithFrontChannelLogoutUri("https://localhost:4200/logout-callback")
            .WithScopes("openid", "profile", "email")
            .RequirePkce()
            .Build();

    public static RtClient CreateDeviceFlowClient(string clientId = "test-device") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
            .WithScopes("openid", "profile")
            .Build();

    public static RtClient CreateMachineClient(string clientId = "test-machine") =>
        new RtClientBuilder()
            .WithClientId(clientId)
            .WithGrantTypes("client_credentials")
            .WithSecret("secret")
            .WithScopes("api.read", "api.write")
            .RequireClientSecret()
            .Build();
}
```

### 5.3 TestGrants.cs

```csharp
public static class TestGrants
{
    public static RtPersistedGrant CreateRefreshToken(
        string subjectId,
        string clientId,
        TimeSpan? lifetime = null) =>
        new RtPersistedGrantBuilder()
            .WithKey(Guid.NewGuid().ToString())
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .WithGrantType("refresh_token")
            .WithExpiration(DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromDays(30)))
            .Build();

    public static RtPersistedGrant CreateAuthorizationCode(
        string subjectId,
        string clientId) =>
        new RtPersistedGrantBuilder()
            .WithKey(Guid.NewGuid().ToString())
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .WithGrantType("authorization_code")
            .WithExpiration(DateTime.UtcNow.AddMinutes(5))
            .Build();

    public static RtPersistedGrant CreateExpiredGrant(
        string subjectId,
        string clientId) =>
        new RtPersistedGrantBuilder()
            .WithKey(Guid.NewGuid().ToString())
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .WithGrantType("refresh_token")
            .WithExpiration(DateTime.UtcNow.AddDays(-1))
            .Build();
}
```

---

## 6. File Structure

```
tests/
├── IdentityServices.IntegrationTests/
│   ├── Api/
│   │   ├── Auth/
│   │   │   ├── AuthApiLoginTests.cs
│   │   │   ├── AuthApiLogoutTests.cs
│   │   │   └── AuthApiPasswordResetTests.cs
│   │   ├── Consent/
│   │   │   └── ConsentApiTests.cs
│   │   ├── Device/
│   │   │   └── DeviceApiTests.cs
│   │   ├── Grants/
│   │   │   └── GrantsApiTests.cs
│   │   ├── Manage/
│   │   │   ├── ManageApiProfileTests.cs
│   │   │   ├── ManageApiPasswordTests.cs
│   │   │   └── ManageApiExternalLoginTests.cs
│   │   └── HealthCheckTests.cs (existing)
│   ├── Helpers/
│   │   ├── TestUsers.cs
│   │   ├── TestClients.cs
│   │   └── TestGrants.cs
│   ├── Infrastructure/
│   │   ├── CustomWebApplicationFactory.cs (existing, extend)
│   │   ├── IntegrationTestBase.cs (existing, extend)
│   │   └── TestAuthHandler.cs (existing)
│   └── appsettings.test.json
│
├── IdentityServerPersistence.UnitTests/
│   └── Stores/
│       ├── ClientStoreTests.cs (existing)
│       └── PersistentGrantStoreTests.cs (new)
│
└── Shared.TestUtilities/
    └── Builders/
        ├── RtUserBuilder.cs (existing)
        ├── RtClientBuilder.cs (existing, extend)
        └── RtPersistedGrantBuilder.cs (new)
```

---

## 7. Implementation Phases

### Phase 1: Infrastructure & Unit Tests (Priority: High)

1. Create `RtPersistedGrantBuilder` in Shared.TestUtilities
2. Extend `RtClientBuilder` with SLO-related methods
3. Implement `PersistentGrantStoreTests` unit tests
4. Extend `IntegrationTestBase` with helper methods

**Estimated effort:** 2-3 hours

### Phase 2: Auth API Tests (Priority: High)

1. Create `AuthApiLoginTests.cs`
2. Create `AuthApiLogoutTests.cs`
3. Create `AuthApiPasswordResetTests.cs`
4. Create test data factories (`TestUsers`, `TestClients`, `TestGrants`)

**Estimated effort:** 4-5 hours

### Phase 3: Consent & Device API Tests (Priority: Medium)

1. Create `ConsentApiTests.cs`
2. Create `DeviceApiTests.cs`

**Estimated effort:** 3-4 hours

### Phase 4: Grants & Manage API Tests (Priority: Medium)

1. Create `GrantsApiTests.cs`
2. Create `ManageApiProfileTests.cs`
3. Create `ManageApiPasswordTests.cs`
4. Create `ManageApiExternalLoginTests.cs`

**Estimated effort:** 4-5 hours

---

## 8. Test Scenarios (Examples)

### 8.1 Login Flow

```gherkin
Scenario: Successful login with valid credentials
  Given a registered user "testuser" with password "Test123!"
  When I POST to /System/api/auth/login with:
    | username | testuser  |
    | password | Test123!  |
  Then the response status is 200 OK
  And the response contains:
    | success     | true                |
    | redirectUrl | /connect/authorize  |
```

### 8.2 Logout with Token Revocation

```gherkin
Scenario: Logout revokes all refresh tokens
  Given an authenticated user with SubjectId "user-123"
  And the user has 3 refresh tokens
  When I POST to /System/api/auth/logout
  Then the response contains success = true
  And the user has 0 refresh tokens
```

### 8.3 Consent Flow

```gherkin
Scenario: Grant consent for requested scopes
  Given an authenticated user
  And a pending authorization request for client "test-client"
  When I POST to /System/api/consent/grant with:
    | scopesConsented | ["openid", "profile"] |
    | rememberConsent | true                  |
  Then the response contains success = true
  And the response contains a redirectUrl
```

### 8.4 Device Authorization

```gherkin
Scenario: Authorize device with user code
  Given an authenticated user
  And a pending device authorization with userCode "ABCD-1234"
  When I POST to /System/api/device/authorize with:
    | userCode        | ABCD-1234             |
    | scopesConsented | ["openid", "profile"] |
  Then the response contains success = true
```

### 8.5 Grant Revocation

```gherkin
Scenario: Revoke client access
  Given an authenticated user with grants for client "test-client"
  When I POST to /System/api/grants/revoke with:
    | clientId | test-client |
  Then the response contains success = true
  And the user has no grants for "test-client"
```

---

## 9. Test Configuration

### 9.1 appsettings.test.json

```json
{
  "integrationTest": {
    "tenantId": "test-tenant",
    "mongoDbImage": "mongo:8.0.15",
    "adminUser": "octo-system-admin",
    "adminUserPassword": "OctoAdmin1",
    "databaseUserPassword": "OctoUser1",
    "useDirectConnection": true
  },
  "testUsers": {
    "defaultPassword": "Test123!",
    "defaultPasswordHash": "AQAAAAIAAYagAAAAE..."
  }
}
```

### 9.2 Test Execution Commands

```bash
# Run all Identity Server tests
dotnet test Octo.Identity.sln -c DebugL

# Run only integration tests
dotnet test tests/IdentityServices.IntegrationTests -c DebugL

# Run specific test class
dotnet test --filter "FullyQualifiedName~AuthApiLogoutTests" -c DebugL

# Run tests with coverage
dotnet test -c DebugL --collect:"XPlat Code Coverage"

# Run tests in parallel (faster)
dotnet test -c DebugL --parallel
```

---

## 10. Success Criteria

### 10.1 Coverage Targets

| Component | Target |
|-----------|--------|
| `AuthApiController` | >= 90% |
| `ConsentApiController` | >= 85% |
| `DeviceApiController` | >= 85% |
| `GrantsApiController` | >= 90% |
| `ManageApiController` | >= 85% |
| `PersistentGrantStore` | 100% |

### 10.2 Quality Requirements

- All tests must be deterministic (no flaky tests)
- Tests must be isolated (no shared state)
- Integration tests should complete in < 10 seconds each
- Full test suite should complete in < 5 minutes

---

## 11. Next Steps

1. **Review and approve** this concept
2. **Phase 1**: Create infrastructure extensions and unit tests
3. **Phase 2**: Implement Auth API integration tests
4. **Phase 3**: Implement Consent & Device API tests
5. **Phase 4**: Implement Grants & Manage API tests
6. **Add to CI pipeline** with coverage reporting
