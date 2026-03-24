# Concept: Tenant-Specific OAuth Authentication via acr_values

## Status: Implemented (existing capability)

## 1. Overview

External OAuth clients (datasource plugins, third-party integrations, custom applications) can authenticate users against a specific OctoMesh tenant by including `acr_values=tenant:{tenantId}` in the `/connect/authorize` request. This ensures the issued token carries the correct `tenant_id`, roles, and scopes for the target tenant.

This is not a new feature -- it is an existing capability of the Identity Server, documented here for consumer reference.

## 2. Problem

OctoMesh is multi-tenant. Each tenant has its own users, roles, scopes, and data. The `TenantAuthorizationMiddleware` enforces that the token's `tenant_id` claim matches the API route's tenant. A token issued for tenant A cannot access tenant B's API -- the request fails with 403.

OAuth clients that need to access a specific tenant's API must obtain a token scoped to that tenant. Without specifying the tenant in the authorize request, the Identity Server defaults to the System-Tenant, which may not contain the user or the correct role assignments.

## 3. Authorize Request

Include `acr_values=tenant:{tenantId}` as a query parameter in the OAuth authorize request:

```
GET /connect/authorize?
    response_type=code
    &client_id={clientId}
    &redirect_uri={redirectUri}
    &scope=openid profile email role octo_api
    &acr_values=tenant:{tenantId}
    &code_challenge={challenge}
    &code_challenge_method=S256
    &state={state}
```

The `acr_values` parameter is defined in the OpenID Connect specification (Section 3.1.2.1) and is the standard mechanism for requesting specific authentication contexts.

## 4. Authentication Flow

```
OAuth Client                Identity Server              Tenant "{tenantId}"
  |                              |                            |
  |-- /connect/authorize ------->|                            |
  |   acr_values=tenant:meshtest |                            |
  |                              |                            |
  |                              |-- Redirect to ------------>|
  |                              |   /{tenantId}/login        |
  |                              |                            |
  |                              |   User authenticates       |
  |                              |   (local, LDAP, external   |
  |                              |    IdP -- whatever the     |
  |                              |    tenant has configured)  |
  |                              |                            |
  |                              |<-- Authenticated ----------|
  |                              |                            |
  |<-- Authorization code -------|                            |
  |                              |                            |
  |-- /connect/token ----------->|                            |
  |   (code exchange)            |                            |
  |                              |                            |
  |<-- Access token -------------|                            |
  |   tenant_id = meshtest       |                            |
  |   roles from meshtest        |                            |
  |   allowed_tenants = [...]    |                            |
```

### Issued Token Claims

The issued access token contains tenant-specific claims:

- `tenant_id`: The tenant the user authenticated against (matches the `acr_values` parameter)
- `allowed_tenants`: All tenants the user is authorized to access (resolved via cross-tenant mappings)
- `role`: Roles assigned to the user in the login tenant (direct + group-inherited)
- `sub`: The user's unique identifier within the tenant

## 5. Identity Server Components

| Component | Responsibility |
|-----------|---------------|
| `OidcTenantResolutionMiddleware` | Parses `acr_values=tenant:{tenantId}` from the authorize request and sets the tenant context |
| `TenantLoginRedirectMiddleware` | Rewrites the login redirect from `/System/login` to `/{tenantId}/login` |
| `UserProfileService` | Adds `tenant_id` and `allowed_tenants` claims to the issued token |
| `OctoUserStore` | Resolves user identity and roles from the correct tenant database |
| `TenantCookieManager` | Scopes auth cookies per tenant to prevent cross-tenant session conflicts |
| `PersistentGrantStore` | Stores grants centrally with tenant ID for refresh token resolution |

## 6. OAuth Client Configuration

Clients using tenant-specific authentication must be registered as OIDC clients in the Identity Server. The client can be created via the System API (`/{tenantId}/v1/clients`) or the Refinery Studio UI.

The client must be provisioned in **each tenant** where users should be able to authenticate. The Identity Server's `DefaultConfigurationCreatorService` auto-provisions built-in clients to all tenants, but custom clients must be provisioned manually or via the System API.

### Example Client Configuration

```json
{
  "clientId": "my-application",
  "clientName": "My Application",
  "allowedGrantTypes": ["authorization_code"],
  "requirePkce": true,
  "requireClientSecret": false,
  "allowedScopes": ["openid", "profile", "email", "role", "octo_api"],
  "redirectUris": ["https://my-app.example.com/callback"],
  "postLogoutRedirectUris": ["https://my-app.example.com/"],
  "accessTokenType": 0
}
```

## 7. Refresh Token Handling

When `AllowOfflineAccess: true` is configured on the client, refresh tokens are issued alongside access tokens. The Identity Server tracks the tenant context for refresh tokens:

1. During token issuance, `OidcTenantResolutionMiddleware` captures the refresh token and maps it to the tenant in an in-memory cache (30-day expiry)
2. `PersistentGrantStore` stores the tenant ID in the `Description` field of the persisted grant
3. On refresh, the middleware resolves the tenant from the cache or falls back to the persistent grant store

This ensures refresh token exchanges continue to use the correct tenant context, even after Identity Server restarts.

## 8. Multi-Tenant Considerations

### Users Exist Only in Their Tenant

Users typically exist only in their respective tenant, not in the System-Tenant. The `acr_values` parameter directs the login to the correct tenant where the user actually exists.

### Per-Tenant Authentication Methods

Each tenant can configure its own set of identity providers (local credentials, Google, Microsoft, Azure Entra ID, LDAP, etc.). The login page displayed to the user shows only the providers configured for the target tenant.

### Concurrent Multi-Tenant Sessions

Per-tenant cookie scoping (`TenantCookieManager`) allows users to be authenticated in multiple tenants simultaneously without session conflicts. Each tenant's auth cookie is suffixed with the tenant ID (e.g., `.AspNetCore.Identity.Application.meshtest`).

## 9. Home Realm Discovery When No `acr_values` Provided

### Problem

Some OAuth clients cannot include `acr_values` in the authorize request. For example, Grafana's built-in OAuth login has a single, global `auth_url` -- there is no way to dynamically set `acr_values` per user or per organization. Since users exist only in their respective tenants (not in the System-Tenant), the authorize request fails without tenant context.

A naive solution would be a tenant selector dropdown, but this exposes tenant names to unauthenticated users -- an information disclosure risk that enables targeted attacks.

### Solution: Email-Based Home Realm Discovery

When `/connect/authorize` is called **without** `acr_values=tenant:{tenantId}`, the Identity Server prompts the user for their email address and resolves the tenant from the email domain. No tenant names are ever exposed to the browser.

This follows the industry-standard Home Realm Discovery (HRD) pattern used by Microsoft, Google, and Okta.

### Flow

```
OAuth Client                Identity Server
  |                              |
  |-- /connect/authorize ------->|
  |   (no acr_values)            |
  |                              |
  |                              |-- Show "Enter your email" page
  |                              |
  |                              |<-- User enters: gerald@meshmakers.com
  |                              |
  |                              |-- Lookup: meshmakers.com → meshtest
  |                              |
  |                              |-- Redirect to /connect/authorize
  |                              |   with acr_values=tenant:meshtest
  |                              |   (re-enters standard flow)
  |                              |
  |                              |-- Redirect to /meshtest/login
  |                              |
  |                              |   ... normal login flow ...
  |                              |
  |<-- Token -------------------|
  |   tenant_id = meshtest       |
```

### Data Model: `TenantEmailDomain`

A new CK type in the Identity CK Model that maps email domains to tenants. Stored in the **system tenant database** (global scope, not per-tenant).

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `EmailDomain` | String | Email domain (lowercase, unique index) | `meshmakers.com` |
| `TenantId` | String | Target tenant ID | `meshtest` |

Multiple domains can map to the same tenant (e.g., `meshmakers.com` and `meshmakers.de` both map to `meshtest`).

### Multi-Tenant Users

If a user's email domain maps to multiple tenants (e.g., an admin with access to `meshtest` and `sbeg`), the HRD page shows **only those matched tenants** -- not the full tenant list. This is safe because the attacker would need a valid email domain to trigger the disambiguation, and even then only sees tenants associated with that domain.

For the common case (one domain → one tenant), the user sees no tenant selection at all.

### Implementation Requirements

| Component | Change |
|-----------|--------|
| `OidcTenantResolutionMiddleware` | When no `acr_values` tenant is found, redirect to HRD page instead of defaulting to System-Tenant |
| **New: HRD Page** | Angular component with email input. Calls backend API to resolve tenant from email domain. On success, redirects back to `/connect/authorize` with `acr_values=tenant:{resolved}` |
| **New: `TenantEmailDomain` CK Type** | CK model definition in `ConstructionKit/` with `EmailDomain` and `TenantId` attributes |
| **New: `TenantEmailDomainStore`** | Persistence store for email domain → tenant mappings (system tenant database) |
| **New: `HrdApiController`** | API endpoint `POST /api/auth/resolve-tenant` accepting `{ email }` and returning `{ tenantId }` or `{ tenants: [...] }` for disambiguation |
| **New: `TenantEmailDomainsController`** | System API CRUD at `{tenantId}/v1/tenantEmailDomains` for managing domain mappings |
| `TenantLoginRedirectMiddleware` | No change -- receives the selected tenant via the existing `acr_values` mechanism |

### Preserving the OIDC Request

After the user enters their email and the tenant is resolved, the Identity Server redirects the browser back to `/connect/authorize` with the original parameters plus `acr_values=tenant:{resolvedTenant}`. This re-enters the standard flow with no middleware changes.

The original authorize request URL (including `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`) is passed to the HRD page as a `returnUrl` query parameter, identical to how the existing login page receives it.

### Security Considerations

| Concern | Mitigation |
|---------|------------|
| **Tenant name enumeration** | No tenant names are shown. The HRD page only accepts an email and returns a redirect -- the tenant ID appears only in the server-side redirect URL, not in the API response to the browser |
| **Email enumeration** | The API should return the same response shape regardless of whether the email domain is recognized. For unknown domains, show a generic "No account found" error without revealing whether the domain exists |
| **Brute-force domain probing** | Rate-limit the `/api/auth/resolve-tenant` endpoint. Consider CAPTCHA after repeated failures from the same IP |
| **Timing attacks** | Ensure consistent response times for known and unknown domains |

### Relationship to `EmailDomainGroupRule`

The existing `EmailDomainGroupRule` maps email domains to **groups within a tenant** (for auto-assignment on first login). The new `TenantEmailDomain` maps email domains to **tenants** (for HRD). These are separate concerns at different levels:

- `TenantEmailDomain`: "Which tenant does this user belong to?" (system-level, used before login)
- `EmailDomainGroupRule`: "Which group should this user join?" (tenant-level, used during login)

## 10. Grafana Integration: Tenant-to-Organization Mapping

### Architecture

Grafana uses a single OAuth login for all users. With Home Realm Discovery (Section 9), users enter their email during login and are automatically directed to the correct tenant. The resulting token contains a `tenant_id` claim that Grafana uses to assign the user to the correct Grafana Organization.

### Grafana Configuration

```yaml
auth.generic_oauth:
  # Standard OAuth settings
  auth_url: https://connect.example.com/connect/authorize
  token_url: https://connect.example.com/connect/token
  api_url: https://connect.example.com/connect/userinfo

  # Map tenant_id claim to Grafana Organization
  org_attribute_path: tenant_id
  org_mapping: "meshtest:1:Editor sbeg:2:Viewer"
```

The `org_mapping` format is `tenantId:grafanaOrgId:role`, space-separated for multiple mappings. This maps each `tenant_id` value to a specific Grafana Organization with a default role.

### Two-Token Architecture

Grafana requires two separate OAuth flows with different purposes:

| Token | Purpose | Client ID | Scopes | How Obtained |
|-------|---------|-----------|--------|--------------|
| **Grafana Login Token** | Grafana session + org mapping | `grafana` | `openid profile email role` (read-only) | Grafana built-in OAuth login (with HRD email prompt) |
| **Plugin Tenant Token** | OctoMesh API calls with `tenant_id` claim | `grafana-datasource` | `openid profile email assetTenantAPI.full_access offline_access` | Plugin backend via popup (with `acr_values`) |

The Grafana Login Token is obtained once during Grafana login (tenant resolved via email-based HRD). The Plugin Tenant Token is obtained per datasource when the user first queries data -- because the user already has an SSO cookie from the Grafana login, this popup completes silently without a password prompt.

### Grafana OctoMesh Datasource Plugin

The datasource plugin includes a Go backend that manages tenant-specific OAuth tokens independently from Grafana's built-in OAuth. See `grafana-octo-mesh-datasource/docs/grafana-tenant-auth.md` for the plugin architecture.

### Organization Switching

When a user needs to access a different tenant:

1. User switches Grafana Organization (UI menu)
2. The OctoMesh datasource in that org has a different `tenantId`
3. Plugin backend checks token cache -- if no token for this tenant, shows "Authenticate" prompt
4. User clicks Authenticate -- popup opens with `acr_values=tenant:{newTenantId}`
5. If SSO cookie exists for that tenant: token issued silently (no login)
6. If no SSO cookie: full login for the new tenant (one-time)
