# Architecture Overview

## System Architecture

Octo Identity Services is an OAuth 2.0 / OpenID Connect identity provider built on **OpenIddict 7.6** (migrated from Duende IdentityServer 8.0.6, Epic AB#4989 — see [CONCEPT-OPENIDDICT-MIGRATION.md](CONCEPT-OPENIDDICT-MIGRATION.md)). It provides centralized authentication and authorization for the Octo platform with support for multiple identity providers. Endpoint paths, discovery, JWKS, and token/claims shapes are kept Duende-compatible so consumers work unchanged; the remaining discovery differences are documented in [openiddict-discovery-diff.md](openiddict-discovery-diff.md).

```
                                    ┌─────────────────────────────────────┐
                                    │         Client Applications         │
                                    │   (Web, Mobile, Machine-to-Machine) │
                                    └──────────────────┬──────────────────┘
                                                       │
                                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                           Octo Identity Services                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         IdentityServices (Web App)                      │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │  │
│  │  │   Account    │  │   Consent    │  │   System     │  │   Device   │  │  │
│  │  │  Controller  │  │  Controller  │  │  API (v1)    │  │ Controller │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                      │                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         Authentication Library                          │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │  Google  │  │ Facebook │  │Microsoft │  │Azure     │  │  LDAP    │  │  │
│  │  │  OAuth   │  │  OAuth   │  │  OAuth   │  │Entra OIDC│  │ OpenLDAP │  │  │
│  │  │          │  │          │  │          │  │          │  │ MS AD    │  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                      │                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                    IdentityServerPersistence                            │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────────┐  │  │
│  │  │ClientStore │  │ResourceStr │  │GrantStore  │  │IdentityProvider  │  │  │
│  │  │            │  │            │  │            │  │     Store        │  │  │
│  │  └────────────┘  └────────────┘  └────────────┘  └──────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                      │                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │              Persistence.IdentityCkModel (Code Generation)              │  │
│  │                    YAML Models → C# Runtime Types                       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │     MongoDB     │
                              │   (via Octo     │
                              │  Runtime Engine)│
                              └─────────────────┘
```

## Project Structure

### IdentityServices (`src/IdentityServices/`)

The main ASP.NET Core web application and system entry point.

**Responsibilities:**
- Host the OpenIddict server middleware
- Build token principals via passthrough protocol controllers
- Provide login/logout UI (Angular SPA + API controllers)
- Expose the System API for administrative operations
- Configure dependency injection and middleware pipeline

**Key Components:**
- `Program.cs` - Application startup and DI configuration
- `Configuration/OpenIddictConfiguration.cs` - OpenIddict server setup (endpoint URIs pinned to the previous Duende paths, enabled flows, signing/encryption credentials, `DisableAccessTokenEncryption`, `DisableEntityCaching`)
- `Controllers/Protocol/` - Passthrough protocol controllers: `TokenEndpointController` (client_credentials, token exchange, code/refresh/device redemption), `AuthorizeController` (cookie auth, tenant-scoped login/consent redirects), `EndSessionController` (logout + front-channel logout callback), `DeviceVerificationController` (`/connect/deviceverification`)
- `OpenIddict/` - Integration layer: `OctoTokenClaimsService` (tenant/role/audience claims), `OctoClaimsDestinations`, `OctoAccessTokenShapeHandler` (Duende-compatible wire format), `OctoApplicationManager`/`OctoSecretHasher` (legacy secret-hash validation), `OctoTicketStore` (server-side sessions), `TenantExchangeProcessor` (RFC 8693), `IdentityAuditService`, `Interaction/` (`IOctoInteractionService` facade for the SPA API controllers)
- `Controllers/Api/` - SPA API controllers (login, consent, device, manage, grants)
- `TenantApi/v1/Controllers/` - REST API for identity management

### Authentication (`src/Authentication/`)

Razor class library providing dynamic authentication scheme management.

**Responsibilities:**
- Dynamically register authentication schemes at runtime
- Support multiple identity provider types
- Handle LDAP authentication (OpenLDAP, Microsoft AD)

**Key Components:**
- `DynamicAuth/` - Framework for runtime scheme registration
- `Google/`, `Facebook/`, `Microsoft/` - OAuth provider implementations
- `AzureEntraId/` - OpenID Connect provider for Azure AD
- `OpenLdap/`, `MicrosoftAd/` - LDAP authentication handlers

### IdentityServerPersistence (`src/IdentityServerPersistence/`)

Data access layer with Octo-native stores and the custom OpenIddict store implementations.

**Responsibilities:**
- Persist clients, resources, grants, and identity providers
- Implement the OpenIddict application/scope/authorization/token stores over the existing CK entities
- Implement ASP.NET Core Identity stores (users, roles)
- Handle data migrations

**Key Components:**
- `SystemStores/` - Store implementations (ClientStore, ResourceStore, OctoUserStore, GroupStore, etc.)
- `SystemStores/OpenIddict/` - `OpenIddictApplicationStore` (read-only `RtClient` projection), `ClientPermissionsMapper`, `OpenIddictScopeStore` (`RtApiScope`/`RtIdentityResource` projection with scope→audience via `RtApiResource`), `OpenIddictAuthorizationStore`/`OpenIddictTokenStore` (per-tenant `RtOAuthAuthorization`/`RtOAuthToken`)
- `Services/Migrations/` - Database migration classes
- `Configuration/` - DI extension methods

### Persistence.IdentityCkModel (`src/Persistence.IdentityCkModel/`)

Construction Kit model definitions for code generation.

**Responsibilities:**
- Define entity schemas in YAML format
- Generate C# runtime types at compile time
- Provide type-safe entity definitions

**Key Components:**
- `ConstructionKit/` - YAML model definitions
  - `types/` - Entity type definitions (Client, User, Role, etc.)
  - `records/` - Nested value object definitions
  - `enums/` - Enumeration definitions
  - `attributes/` - Attribute type definitions

### IdentityServices.Resources (`src/IdentityServices.Resources/`)

Localized string resources for the application.

**Responsibilities:**
- Provide localized UI strings
- Support English and German locales

## Dependency Flow

```
IdentityServices (Web App)
    │
    ├── Authentication (Razor Class Library)
    │       │
    │       ├── IdentityServerPersistence
    │       │       │
    │       │       └── Persistence.IdentityCkModel
    │       │
    │       └── IdentityServices.Resources
    │
    └── Meshmakers.Octo.* packages
            │
            └── MongoDB Driver
```

## Multi-Tenancy Architecture

The service supports multi-tenant deployments with tenant isolation at the data level.

**Route Pattern:** `{tenantId:tenantId=System}/{controller=Home}/{action=Index}/{id?}`

- Default tenant is `System`
- Each tenant has isolated data in MongoDB
- Tenant resolution occurs via URL path prefix
- All data operations are scoped to the current tenant

## Key Design Decisions

### 1. Dynamic Authentication Schemes

Authentication providers are configured in the database and loaded at runtime. This allows:
- Adding/removing providers without code changes
- Per-tenant provider configuration
- Runtime provider updates via event distribution

### 2. Construction Kit Code Generation

Entity models are defined in YAML and compiled to C# at build time. Benefits:
- Single source of truth for entity definitions
- Automatic MongoDB serialization
- Compile-time type safety
- Generated documentation

### 3. OpenIddict Integration (Epic AB#4989)

Custom stores replace OpenIddict's default EF Core / MongoDB stores and project the existing CK entities — no data migration was needed:
- `OpenIddictApplicationStore` - read-only projection of `RtClient` (application id = client_id; enabled + DCR-TTL gates), permissions derived by `ClientPermissionsMapper`
- `OpenIddictScopeStore` - projects `RtApiScope` + `RtIdentityResource`; scope→audience via `RtApiResource`
- `OpenIddictAuthorizationStore` / `OpenIddictTokenStore` - grants over the **per-tenant** CK types `RtOAuthAuthorization`/`RtOAuthToken`
- `IdentityProviderStore` - External provider configuration (Octo-native, unchanged)

OpenIddict's process-wide entity caching is disabled (`DisableEntityCaching`) — the stores are per-tenant, so cached entities would leak across tenants. Client secret validation (`OctoApplicationManager` + `OctoSecretHasher`) keeps the stored Duende hash format (Base64 SHA-256/512), so no secret rotation was needed. Token wire compatibility is pinned by golden baseline tests (`tests/IdentityServices.IntegrationTests/Api/Protocol/TokenShapeGoldenTests.cs`): token shapes recorded from Duende are verified byte-identical against OpenIddict.

### 4. Event-Driven Cache Invalidation

Write operations publish events via the distribution event hub:
- `CorsClientsUpdate` - Client configuration changes
- `IdentityProviderUpdate` - Provider configuration changes

This ensures cache consistency across multiple service instances.
