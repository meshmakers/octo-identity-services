# Tech Stack and Architecture

## Tech Stack
- **.NET Version**: 9.0
- **Framework**: ASP.NET Core
- **Identity Server**: Duende IdentityServer 7.3.2
- **Database**: MongoDB
- **Code Generation**: Construction Kit (CK) - YAML-based source generation
- **Language**: C# (Latest major version)
- **Logging**: NLog (configured via nlog.config)
- **Runtime**: Meshmakers.Octo.Runtime.Engine.MongoDb

## Project Structure

```
src/
├── IdentityServices/              # Main ASP.NET Core application (entry point)
│   ├── TenantApi/v1/Controllers/  # REST API endpoints (versioned)
│   ├── Services/                  # Business logic services
│   ├── Configuration/             # Options and configuration classes
│   └── Program.cs                 # Application entry point
├── Authentication/                # Reusable authentication library (Razor SDK)
│   ├── DynamicAuth/               # Pluggable auth provider framework
│   └── Providers/                 # Google, Microsoft, Azure, LDAP, AD, Facebook
├── IdentityServerPersistence/     # Duende IdentityServer store implementations
│   └── SystemStores/              # MongoDB-backed stores for clients, resources, etc.
├── Persistence.IdentityCkModel/   # Construction Kit model definitions
│   └── ConstructionKit/           # YAML model definitions (source generation)
└── IdentityServices.Resources/    # Localization resources
```

## Layer Dependencies
```
IdentityServices (entry point)
  ↓
├─→ Authentication (auth providers)
├─→ IdentityServerPersistence (data stores)
└─→ Persistence.IdentityCkModel (entity models)
```

## Key Architectural Patterns

### 1. Construction Kit (CK) Pattern
- Domain models defined in YAML under `Persistence.IdentityCkModel/ConstructionKit/`
- Source generators create `Rt*` prefixed classes at compile time (e.g., `RtUser`, `RtClient`, `RtRole`)
- Generated classes appear in `Generated/System.Identity.v1/` namespace
- Model ID: `System.Identity-1.0.0`
- Current schema version: 9

**Adding new entity types:**
1. Create YAML definition in `src/Persistence.IdentityCkModel/ConstructionKit/types/`
2. Build project to trigger source generation
3. Use generated `Rt*` class in stores and services

### 2. Dynamic Authentication
Fluent builder pattern for registering auth providers:
```csharp
builder.Services.AddDynamicAuthentication()
    .AddGoogle()
    .AddAzureEntraId()
    .AddOpenLdapAuthentication();
```

### 3. Options Pattern
Configuration managed via `IOptions<T>` and `ConfigureOptions<T>` classes.

### 4. Multi-Tenancy
- Tenant context flows through `ITenantContext`
- Route constraint: `{tenantId:tenantId}`
- Tenant-specific authentication and configuration

### 5. Store Pattern
IdentityServer persistence abstracted through store interfaces:
- `IClientStore` - OAuth2/OIDC clients
- `IResourceStore` - API resources and scopes
- `IPersistedGrantStore` - Tokens and grants
- Custom stores in `src/IdentityServerPersistence/SystemStores/`

### 6. Distributed Events
- **Command/Response pattern**: Queue-based consumption
- **Event Hub**: Cross-service communication
- **Commands**: `CreateIdentityDataCommandRequest`
- **Messages**: `IdentityProviderUpdate`
- **Registration**: Consumers in `Program.cs` via `AddRuntimeEngine().AddOctoIdentityPersistence()`

## API Structure

### Base Configuration
- **Base Path**: `system/v{version:apiVersion}`
- **Current Version**: 1.0
- **Full path**: `/system/v1/`
- **Authentication**: JWT Bearer tokens or Cookie-based

### Authorization Policies
- `IdentityApiReadOnlyPolicy`: Read-only access
- `IdentityApiReadWritePolicy`: Full access (requires scope claim)

### Key API Resources
- Users: `/system/v1/users`
- Roles: `/system/v1/roles`
- Clients: `/system/v1/clients`
- API Resources: `/system/v1/apiresources`
- API Scopes: `/system/v1/apiscopes`
- Identity Providers: `/system/v1/identityproviders`

## Configuration

### Configuration Sources (in order of precedence)
1. Command-line arguments
2. Environment variables (prefix: `OCTO_`)
3. User secrets (Development only)
4. appsettings.{Environment}.json
5. appsettings.json

### Key Configuration Sections
- `Identity`: Authority URL, licensing (`OctoIdentityServicesOptions`)
- `System`: System-wide configuration (`OctoSystemConfiguration`)
- `Logging`: NLog configuration in `nlog.config` file
- `Runtime:MongoDb:ConnectionString`: MongoDB connection string

### Environment Variable Example
```bash
export OCTO_Identity__Authority=https://identity.example.com
export OCTO_Runtime__MongoDb__ConnectionString="mongodb://localhost:27017"
```

## Database

### MongoDB
- **Connection**: Via `Runtime:MongoDb:ConnectionString` configuration
- **Schema Version**: Tracked with key `"IdentityService"`, current version: 9
- **Migrations**: Automatically applied on startup via `IServiceCollection.AddMigrations()`
- **Collections**: Users, Roles, Clients, API Resources, Scopes, Identity Providers, etc.

## Email Notifications
- **Service**: `Meshmakers.Octo.Services.Notifications`
- **Configuration**: Via `RtMailNotificationConfiguration` entity
- **Templates**: Welcome, Password Reset, Welcome (without password)
- **Interface**: `IUserEmailInteractionService`
