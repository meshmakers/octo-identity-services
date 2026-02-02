# Single Logout (SLO) Implementation

This document describes the Single Logout (SLO) implementation for the Octo Mesh Platform, enabling coordinated logout across multiple browser tabs and client applications.

## Overview

Single Logout ensures that when a user logs out from one application or browser tab, all other sessions are terminated as well. This includes:

- **Cross-tab logout**: Other browser tabs with the same application are logged out
- **Cross-client logout**: Other registered clients receive logout notifications via front-channel logout
- **Token revocation**: All refresh tokens are invalidated on the server

## Architecture

### Components Involved

```
┌─────────────────────┐     ┌─────────────────────┐
│   Refinery Studio   │     │   Refinery Studio   │
│      (Tab 1)        │     │      (Tab 2)        │
│                     │     │                     │
│  AuthorizeService   │     │  AuthorizeService   │
│         │           │     │         ▲           │
└─────────┼───────────┘     └─────────┼───────────┘
          │                           │
          │ 1. Logout Request         │ 5. BroadcastChannel
          ▼                           │    Message
┌─────────────────────────────────────┼───────────┐
│              Identity Server                    │
│                                                 │
│  ┌─────────────────┐    ┌─────────────────────┐ │
│  │ AuthApiController│    │ PersistentGrantStore│ │
│  │                 │    │                     │ │
│  │ 2. Revoke Tokens├───►│ DeleteManyAsync()   │ │
│  └────────┬────────┘    └─────────────────────┘ │
│           │                                     │
│           │ 3. Sign-out Iframe                  │
│           ▼                                     │
│  ┌─────────────────────────────────────────┐    │
│  │ Front-Channel Logout URL (per client)   │    │
│  │ https://localhost:4200/logout-callback  │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
          │
          │ 4. Iframe loads LogoutCallbackComponent
          ▼
┌─────────────────────────────────────────────────┐
│           LogoutCallbackComponent               │
│                                                 │
│  - Clears localStorage tokens                   │
│  - Sends BroadcastChannel message               │
└─────────────────────────────────────────────────┘
```

### Flow Description

1. **User initiates logout** in Tab 1 via the Refinery Studio UI
2. **AuthorizeService** calls `oauthService.logOut(false)` which redirects to Identity Server
3. **Identity Server** (`AuthApiController.Logout`):
   - Revokes all persisted grants (refresh tokens) for the user
   - Signs out the user from the Identity Server session
   - Returns the sign-out iframe URL for front-channel logout
4. **Front-channel logout iframe** is loaded by the Angular logout component
5. **LogoutCallbackComponent** (loaded in iframe):
   - Clears all OAuth tokens from localStorage
   - Sends a BroadcastChannel message to notify other tabs
6. **Other tabs** receive the BroadcastChannel message via `AuthorizeService`
7. **AuthorizeService** in other tabs clears local state and reloads the page

## Implementation Details

### Identity Server (Backend)

#### AuthApiController.cs

The logout endpoint revokes all refresh tokens before signing out:

```csharp
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
```

#### PersistentGrantStore.cs

The `RemoveAllAsync` method uses `DeleteManyRtEntitiesAsync` to handle multiple grants:

```csharp
public async Task RemoveAllAsync(PersistedGrantFilter filter)
{
    var session = await _tenantRepository.GetSessionAsync();
    session.StartTransaction();

    var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And);
    if (!string.IsNullOrWhiteSpace(filter.SubjectId))
    {
        fieldFilterCriteria.FieldEquals(nameof(RtPersistedGrant.SubjectId), filter.SubjectId);
    }
    // ... additional filters ...

    // Use DeleteManyRtEntitiesAsync to handle 0 or more matching grants
    await _tenantRepository.DeleteManyRtEntitiesAsync<RtPersistedGrant>(
        session, fieldFilterCriteria, DeleteOptions.Erase);

    await session.CommitTransactionAsync();
}
```

### Angular Frontend

#### AuthorizeService (shared-auth library)

The service listens for logout events from other tabs via two mechanisms:

**1. BroadcastChannel (primary mechanism)**

```typescript
if (typeof BroadcastChannel !== 'undefined') {
  console.debug("AuthorizeService: Setting up BroadcastChannel listener for 'octo-auth-logout'");
  const logoutChannel = new BroadcastChannel('octo-auth-logout');
  logoutChannel.onmessage = (event) => {
    console.debug("AuthorizeService: BroadcastChannel message received", event.data);
    if (event.data?.type === 'logout' && this._isAuthenticated()) {
      console.debug("AuthorizeService: Logout broadcast received - reloading");
      this._accessToken.set(null);
      this._user.set(null);
      this._isAuthenticated.set(false);
      window.location.reload();
    }
  };
}
```

**2. Storage Events (fallback mechanism)**

```typescript
window.addEventListener('storage', (event) => {
  console.debug("AuthorizeService: Storage event received", event.key, event.newValue);
  // Check if access_token was removed (logout in another tab)
  // Note: OAuth library may set to empty string or null when clearing
  if (event.key === 'access_token' &&
      (event.newValue === null || event.newValue === '') &&
      this._isAuthenticated()) {
    console.debug("AuthorizeService: Access token removed in another tab - logging out and reloading");
    this._accessToken.set(null);
    this._user.set(null);
    this._isAuthenticated.set(false);
    window.location.reload();
  }
});
```

#### LogoutCallbackComponent

This component is loaded in an iframe during the front-channel logout flow:

```typescript
@Component({
  selector: 'app-logout-callback',
  standalone: true,
  imports: [CommonModule],
  template: `<div class="logout-callback">{{ message }}</div>`
})
export class LogoutCallbackComponent implements OnInit {
  message = 'Processing logout...';

  ngOnInit(): void {
    this.performLogout();
  }

  private performLogout(): void {
    // Clear all OAuth tokens from storage
    this.clearStorage();

    // Notify other tabs via BroadcastChannel
    this.notifyParent();

    this.message = 'Logged out successfully';
  }

  private clearStorage(): void {
    const keysToRemove = Object.keys(localStorage).filter(key =>
      key.startsWith('access_token') ||
      key.startsWith('id_token') ||
      key.startsWith('refresh_token') ||
      // ... other OAuth-related keys
    );
    keysToRemove.forEach(key => localStorage.removeItem(key));
  }

  private notifyParent(): void {
    if (typeof BroadcastChannel !== 'undefined') {
      const logoutChannel = new BroadcastChannel('octo-auth-logout');
      logoutChannel.postMessage({ type: 'logout', source: 'refinery-studio' });
      setTimeout(() => logoutChannel.close(), 100);
    }
  }
}
```

### Client Configuration (Identity Server)

Clients must have the front-channel logout URL configured:

```csharp
new Client
{
    ClientId = "octo-data-refinery-studio",
    // ... other settings ...

    // Front-channel logout configuration
    FrontChannelLogoutUri = "https://localhost:4200/logout-callback",
    FrontChannelLogoutSessionRequired = true,
}
```

### Route Configuration (Angular)

The logout callback route must skip OAuth initialization:

```typescript
// app.routes.ts
{
  path: 'logout-callback',
  component: LogoutCallbackComponent,
  data: { skipOAuthInit: true }  // Important: Skip OAuth init on this route
}

// app.config.ts - Check for skipOAuthInit in APP_INITIALIZER
if (route.data?.['skipOAuthInit']) {
  console.log('[SLO] Skipping OAuth initialization on logout callback route');
  return;
}
```

## Session Check Behavior

The `angular-oauth2-oidc` library performs periodic session checks (configured via `sessionCheckIntervall`):

```typescript
const config: AuthConfig = {
  // ... other settings ...
  sessionChecksEnabled: true,
  sessionCheckIntervall: 60 * 1000,  // Check every 60 seconds
};
```

When the session check detects a session change:

1. The library attempts to refresh the token
2. If refresh tokens have been revoked, the refresh fails
3. A `session_terminated` event is fired
4. `AuthorizeService` handles this event and reloads the page

```typescript
this.oauthService.events.subscribe((e) => {
  if (e.type === "session_terminated") {
    console.debug("Your session has been terminated!");
    this._accessToken.set(null);
    this._user.set(null);
    this._isAuthenticated.set(false);
    window.location.reload();
  }
});
```

## Testing SLO

### Manual Test Steps

1. **Open Refinery Studio** in two browser tabs
2. **Login** in one tab (the other tab will also be authenticated via shared storage)
3. **Click Logout** in Tab 1
4. **Verify** that Tab 2 is immediately redirected to the login page

### Expected Console Output (Tab 1)

```
[SLO] Logout result: {...}
[SLO] Creating sign-out iframe with URL: https://...
[SLO] Sign-out iframe loaded successfully
[SLO Callback] Refinery Studio logout callback triggered
[SLO Callback] Clearing storage...
[SLO Callback] Logout completed successfully
[SLO Callback] Broadcast logout message sent to channel octo-auth-logout
```

### Expected Console Output (Tab 2)

```
AuthorizeService: BroadcastChannel message received {type: 'logout', source: 'refinery-studio'}
AuthorizeService: Logout broadcast received - reloading
```

## Troubleshooting

### Issue: Cross-tab logout not working

**Symptoms**: Logging out in one tab does not affect other tabs.

**Possible causes**:

1. **BroadcastChannel not supported**: Check browser compatibility
2. **Storage event condition**: Ensure the condition checks for both `null` and empty string `''`
3. **Iframe blocked**: Check if the front-channel logout iframe is being blocked by CSP or browser settings

### Issue: Token refresh succeeds after logout

**Symptoms**: After logging out, other tabs can still refresh tokens.

**Possible causes**:

1. **Refresh tokens not revoked**: Verify that `RemoveAllAsync` is called in `AuthApiController.Logout`
2. **Wrong delete method**: Ensure `DeleteManyRtEntitiesAsync` is used (not `DeleteOneRtEntityAsync`)

### Issue: Identity Server error on logout

**Error**: `TenantRepositoryException: Entity filter returns not exactly one entity`

**Solution**: Use `DeleteManyRtEntitiesAsync` instead of `DeleteOneRtEntityAsync` in `PersistentGrantStore.RemoveAllAsync`

## Files Modified

| File | Purpose |
|------|---------|
| `src/IdentityServices/Controllers/Api/AuthApiController.cs` | Added refresh token revocation on logout |
| `src/IdentityServerPersistence/SystemStores/PersistentGrantStore.cs` | Fixed `RemoveAllAsync` to use `DeleteManyRtEntitiesAsync` |
| `projects/meshmakers/shared-auth/src/lib/authorize.service.ts` | Added BroadcastChannel and storage event listeners |
| `src/app/logout-callback/logout-callback.component.ts` | Front-channel logout callback component |

## Related Documentation

- [OpenID Connect Front-Channel Logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [Duende IdentityServer - End Session Endpoint](https://docs.duendesoftware.com/identityserver/v7/ui/logout/)
- [angular-oauth2-oidc - Session Checks](https://github.com/manfredsteyer/angular-oauth2-oidc)
