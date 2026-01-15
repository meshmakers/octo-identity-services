# Architecture Overview

## System Architecture

Octo Identity Services is an OAuth 2.0 / OpenID Connect identity provider built on Duende IdentityServer. It provides centralized authentication and authorization for the Octo platform with support for multiple identity providers.

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
- Host the IdentityServer middleware
- Provide login/logout UI (MVC controllers and Razor views)
- Expose the System API for administrative operations
- Configure dependency injection and middleware pipeline

**Key Components:**
- `Program.cs` - Application startup and DI configuration
- `Controllers/Account/` - Login, logout, password management
- `Controllers/Consent/` - OAuth consent flow UI
- `Controllers/Device/` - Device authorization flow
- `SystemApi/v1/Controllers/` - REST API for identity management

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

Data access layer implementing IdentityServer store interfaces.

**Responsibilities:**
- Persist clients, resources, grants, and identity providers
- Implement ASP.NET Core Identity stores (users, roles)
- Handle data migrations

**Key Components:**
- `SystemStores/` - Store implementations (ClientStore, ResourceStore, etc.)
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

### 3. Duende IdentityServer Integration

Custom stores replace IdentityServer's default in-memory or EF Core stores:
- `ClientStore` - OAuth/OIDC client management
- `ResourceStore` - API resources and scopes
- `PersistentGrantStore` - Tokens and grants
- `IdentityProviderStore` - External provider configuration

### 4. Event-Driven Cache Invalidation

Write operations publish events via the distribution event hub:
- `CorsClientsUpdate` - Client configuration changes
- `IdentityProviderUpdate` - Provider configuration changes

This ensures cache consistency across multiple service instances.
