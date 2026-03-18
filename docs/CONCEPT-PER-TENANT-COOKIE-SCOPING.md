# Concept: Per-Tenant Cookie Scoping

## Status: Ready for Implementation

## 1. Problem Statement

IdentityServer uses a single auth cookie (`Identity.Application`) at path `/` for all tenants. When a user logs into tenant "sbeg", the cookie is sent for all tenant routes. Navigating to `/octosystem/manage` sends the same cookie, but `UserManager` looks up the user in octosystem's database — user not found — 404.

### Root Cause

- The `Identity.Application` cookie is global (path `/`)
- Any request to any tenant route sends the same cookie
- `OctoUserStore` resolves the user against the current tenant's database
- If the user exists only in tenant A but the cookie is sent to tenant B, the user lookup fails

## 2. Goals

1. **Tenant-isolated sessions**: Login in "sbeg" must not affect "octosystem"
2. **Concurrent multi-tenant sessions**: A user can be logged into multiple tenants simultaneously
3. **No breaking changes**: External login flows, 2FA, and OIDC must continue to work
4. **Minimal invasiveness**: Reuse existing middleware patterns; no IdentityServer fork

## 3. Approach: Custom `ICookieManager` with Tenant-Scoped Cookie Names

Create a `TenantCookieManager` that wraps `ChunkingCookieManager` and appends `.{tenantId}` to cookie names based on `HttpContext.Items["tenantId"]`.

### Cookie Scoping Matrix

| Cookie | Scoped? | Reason |
|--------|---------|--------|
| `Identity.Application` | **Yes** | Main auth cookie — primary source of cross-tenant leak |
| `idsrv` | **Yes** | IdentityServer session cookie |
| `Identity.External` | No | Written at `/signin-google` (no tenant in URL); scoping would break external login |
| `Identity.TwoFactorUserId` | No | Short-lived, single login flow |
| `Identity.TwoFactorRememberMe` | No | Short-lived, single login flow |

### How It Works

1. `TenantCookieManager` implements `ICookieManager`
2. For `GetRequestCookie`, `AppendResponseCookie`, `DeleteCookie`:
   - Read tenant from `HttpContext.Items[InfrastructureCommon.TenantIdName]`
   - Append `.{tenantId}` (lowercased) to cookie key for scoped cookies
   - Fall back to unscoped key when no tenant is resolved
3. Delegate to `ChunkingCookieManager` for actual I/O

## 4. OIDC Endpoint Tenant Resolution

For `/connect/*` OIDC endpoints (no `{tenantId}` in URL), resolve tenant BEFORE authentication:

| Endpoint | Tenant Source |
|----------|--------------|
| `/connect/authorize` | `acr_values=tenant:{tenantId}` from query string |
| `/connect/endsession` | `id_token_hint` JWT payload → `tenant_id` claim; fall back to `acr_values` |
| `/connect/token` | Not needed (no cookies) |

### OidcTenantResolutionMiddleware

- Runs after routing, before authentication
- Must override TenantMiddleware's system-tenant default for `/connect/*` paths
- Also resolves and sets `TenantRepositoryName` via `ISystemContext.TryFindTenantRepositoryAsync()` (needed by `OctoUserStore`)

### tenant_id Claim in Identity Tokens

`UserProfileService.GetUserClaimsAsync()` adds a `tenant_id` claim to identity tokens so `/connect/endsession` can extract the tenant from `id_token_hint`.

## 5. Implementation Steps

### Step 1: `TenantCookieManager.cs` (NEW)

Custom `ICookieManager` as described in Section 3.

### Step 2: `OidcTenantResolutionMiddleware.cs` (NEW)

Middleware as described in Section 4.

### Step 3: `Program.cs` (MODIFY)

Register `TenantCookieManager` on `Identity.Application` and `idsrv` cookie schemes. Add `OidcTenantResolutionMiddleware` to the pipeline.

### Step 4: `UserProfileService.cs` (MODIFY)

Add `tenant_id` claim to identity tokens.

### Step 5: `CustomWebApplicationFactory.cs` (MODIFY)

Register `TenantCookieManager` in test services.

### Step 6: Unit Tests (NEW)

- `TenantCookieManagerTests.cs`
- `OidcTenantResolutionMiddlewareTests.cs`

### Step 7: Documentation (UPDATE)

- `docs/authentication.md` — cookie scoping architecture
- `CLAUDE.md` — per-tenant cookie section

## 6. Middleware Pipeline Order

```
UseRouting()
→ inline middleware (re-resolve tenant from route values)
→ UseOidcTenantResolution()       ← NEW
→ UseTenantLoginRedirect()
→ UseIdentityServer()
```

## 7. Edge Cases

| Case | Behavior |
|------|----------|
| External login (`/signin-google`) | External cookie global; auth cookie scoped at `/{tenantId}/api/auth/external-callback` |
| Tenant switch | `SignInAsync()` writes new tenant-scoped cookie; old tenant cookie remains |
| Concurrent sessions | Each tenant has its own cookie; user logged into multiple tenants |
| `/connect/authorize` without `acr_values` | Falls back to system tenant cookie |
| `/connect/endsession` without `id_token_hint` | No tenant; user appears unauthenticated; generic logout prompt |
| Existing global cookies after deploy | Not found by TenantCookieManager; users re-login (acceptable) |
| TenantMiddleware sets system tenant before OIDC resolution | `OidcTenantResolutionMiddleware` overrides for `/connect/*` |

## 8. Files Summary

| File | Action |
|------|--------|
| `src/IdentityServices/Cookies/TenantCookieManager.cs` | **NEW** |
| `src/IdentityServices/Middleware/OidcTenantResolutionMiddleware.cs` | **NEW** |
| `src/IdentityServices/Program.cs` | **MODIFY** |
| `src/IdentityServices/Services/UserProfileService.cs` | **MODIFY** |
| `tests/.../CustomWebApplicationFactory.cs` | **MODIFY** |
| `tests/.../Cookies/TenantCookieManagerTests.cs` | **NEW** |
| `tests/.../Middleware/OidcTenantResolutionMiddlewareTests.cs` | **NEW** |
| `docs/authentication.md` | **MODIFY** |
| `CLAUDE.md` | **MODIFY** |

## 9. Verification

1. `dotnet build Octo.Identity.sln -c DebugL` — 0 errors
2. `dotnet test Octo.Identity.sln -c DebugL` — all tests pass
3. Login to sbeg → navigate to `/octosystem/manage` → should redirect to login (not 404)
4. Login to octosystem → profile shows octosystem tenant
5. Navigate back to `/sbeg/manage` → still logged in (separate cookie)
6. OIDC flow with `acr_values=tenant:sbeg` → correct tenant login
