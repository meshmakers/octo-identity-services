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
