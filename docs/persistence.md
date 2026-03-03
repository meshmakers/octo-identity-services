# Persistence Architecture

## Overview

The persistence layer uses the Octo Construction Kit (CK) code generation system to define entities in YAML, which are compiled to C# at build time. Data is stored in MongoDB via the Octo Runtime Engine.

## Construction Kit Model System

### What is the Construction Kit?

The Construction Kit is Octo's code generation framework that:
- Converts YAML model definitions into C# runtime entities
- Provides compile-time type safety
- Generates automatic MongoDB serialization
- Creates documentation from model definitions

### Model Location

Models are defined in `src/Persistence.IdentityCkModel/ConstructionKit/`:

```
ConstructionKit/
├── ckModel.yaml                 # Model metadata and dependencies
├── associations/
│   └── identity-associations.yaml  # Association role definitions
├── attributes/
│   ├── configuration-attributes.yaml
│   └── identity-attributes.yaml
├── types/
│   ├── ck-client.yaml
│   ├── ck-user.yaml
│   ├── ck-role.yaml
│   ├── ck-group.yaml
│   ├── ck-apiResource.yaml
│   ├── ck-apiScope.yaml
│   ├── ck-identityResource.yaml
│   ├── ck-identityProvider.yaml
│   ├── ck-persistedGrant.yaml
│   └── ... (provider subtypes)
├── records/
│   ├── ck-clientClaim.yaml
│   ├── ck-userClaim.yaml
│   ├── ck-secret.yaml
│   └── ...
└── enums/
    ├── ck-tokenExpiration.yaml
    ├── ck-tokenType.yaml
    └── ck-tokenUsage.yaml
```

### Model Metadata

`ckModel.yaml` defines the model identity:

```yaml
"$schema": "https://schemas.meshmakers.cloud/construction-kit-meta.schema.json"
modelId: "System.Identity-2.3.0"
dependencies:
  - "System-(,2.0)"
```

### Attribute Definitions

Attributes define reusable property types:

```yaml
# identity-attributes.yaml
- id: ClientId
  valueType: String

- id: AllowedGrantTypes
  valueType: StringArray

- id: UserClaims
  valueType: RecordArray
  valueCkRecordId: ${this}/UserClaim
```

**Value Types:**
- `String` - Single string value
- `StringArray` - Collection of strings
- `Boolean` - True/false
- `DateTime` / `DateTimeOffset` - Timestamps
- `Int` - Integer
- `RecordArray` - Collection of nested records
- Enum references

### Type Definitions

Types define entities that map to MongoDB collections:

```yaml
# ck-client.yaml
typeId: Client
baseTypeId: ${System}/Entity
isCollectionRoot: true
attributes:
  - id: ${this}/ClientId
    indexes:
      - indexType: Ascending
  - id: ${this}/ClientName
  - id: ${this}/AllowedGrantTypes
  - id: ${this}/RedirectUris
  - id: ${this}/ClientSecrets
  # ... many more attributes
```

Key properties:
- `isCollectionRoot: true` - Entity has its own MongoDB collection
- `baseTypeId` - Inheritance from base entity type
- `indexes` - MongoDB index definitions (supports `Ascending`, `UniqueNotDeleted`, etc.)

**User Entity Indexes:**
- `Ascending` on `NormalizedEmail` - Efficient email lookups. Note: Multiple users can share the same email (e.g., a local user and external provider users). External logins create dedicated user accounts with provider-prefixed usernames to prevent privilege escalation (Bug 3430).
- `Ascending` on `NormalizedUserName` - Efficient username lookups.

**Group Entity (`ck-group.yaml`):**

Groups are organizational units that can be assigned roles. Users and other groups can be members, enabling hierarchical role inheritance. All relationships are modeled as CK associations (not denormalized attributes).

| Attribute | ValueType | Description |
|-----------|-----------|-------------|
| `GroupName` | String | Display name |
| `NormalizedGroupName` | String | Uppercase for case-insensitive lookup |
| `GroupDescription` | String (optional) | Purpose description |

| Association | Target Type | Description |
|-------------|-------------|-------------|
| `AssignedRole` | Role | Assigned roles (N:N) |
| `GroupMember` | User | Internal user members (N:N) |
| `GroupMember` | ExternalTenantUserMapping | External tenant user members (N:N) |
| `ChildGroup` | Group | Nested child groups (N:N) |

**Group Entity Indexes:**
- `Ascending` on `NormalizedGroupName` - Efficient name lookups.

**User Entity Associations:**

| Association | Target Type | Description |
|-------------|-------------|-------------|
| `AssignedRole` | Role | Directly assigned roles (N:N) |

### Record Definitions

Records define nested value objects (not separate collections):

```yaml
# ck-userClaim.yaml
recordId: UserClaim
attributes:
  - id: ${this}/ClaimType
  - id: ${this}/ClaimValue
  - id: ${this}/ClaimValueType
```

Records are embedded within parent entities as arrays.

## Code Generation Pipeline

### Build Configuration

In `Persistence.IdentityCkModel.csproj`:

```xml
<PropertyGroup>
    <OctoGenerateCkModelServiceClass>true</OctoGenerateCkModelServiceClass>
    <OctoPublishCkModel>true</OctoPublishCkModel>
    <OctoGenerateCkDocumentation>true</OctoGenerateCkDocumentation>
</PropertyGroup>

<ItemGroup>
    <PackageReference Include="Meshmakers.Octo.ConstructionKit.SourceGeneration"
                      OutputItemType="Analyzer"
                      ReferenceOutputAssembly="false" />
</ItemGroup>
```

### Generation Process

1. **Source Generation** - Roslyn analyzer processes YAML at compile time
2. **Type Creation** - Generates C# classes with `Rt` prefix (Runtime)
3. **Compilation** - Standard .NET compilation with generated code
4. **Output** - Compiled assembly with runtime types

### Generated Types

All generated entities:
- Inherit from `RtEntity` base class
- Have immutable `CkTypeId` property
- Use `OctoObjectId` for primary keys (`RtId`)
- Support nested records with `AttributeRecordValueList<T>`
- Are fully serializable to/from MongoDB BSON

**Namespace:** `Persistence.IdentityCkModel.Generated.System.Identity.v2`

**Examples:**
- `RtClient` - OAuth/OIDC client
- `RtUser` - User identity
- `RtRole` - Role definition
- `RtGroup` - Role group with user/group members
- `RtPersistedGrant` - OAuth tokens/grants
- `RtApiResource`, `RtApiScope`, `RtIdentityResource`
- `RtIdentityProvider` and subtypes

## System Stores

### Store Implementations

Located in `src/IdentityServerPersistence/SystemStores/`:

| Store | Interface | Purpose |
|-------|-----------|---------|
| `ClientStore` | `IOctoClientStore` | OAuth/OIDC clients |
| `ResourceStore` | `IOctoResourceStore` | API resources, scopes, identity resources |
| `PersistentGrantStore` | `IOctoPersistentGrantStore` | Tokens, grants, consent |
| `IdentityProviderStore` | `IOctoIdentityProviderStore` | External identity providers |
| `OctoUserStore` | `IUserStore<RtUser>` | ASP.NET Identity users |
| `OctoRoleStore` | `IRoleStore<RtRole>` | ASP.NET Identity roles |
| `PermissionStore` | `IOctoPermissionStore` | Custom permissions |
| `GroupStore` | `IGroupStore` | Role groups with member management |

### ClientStore

Manages OAuth 2.0 / OIDC client configurations:

```csharp
public class ClientStore : IOctoClientStore
{
    public async Task<RtClient?> FindRtClientByIdAsync(string clientId)
    {
        var session = await _tenantRepository.GetSessionAsync();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

        var results = await _tenantRepository
            .GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);

        return results.FirstOrDefault();
    }
}
```

### PersistentGrantStore

Handles OAuth tokens with expiration and cleanup. **Grants are always stored in the system tenant database**, regardless of which tenant the OIDC request targets. This avoids mismatches between the `/connect/authorize` endpoint (which resolves tenant from `acr_values`) and the `/connect/token` endpoint (which has no tenant context). The `TokenCleanupHostService` also runs without HTTP context, so centralizing grants ensures expired grants are always cleaned up.

```csharp
public class PersistentGrantStore(ISystemContext systemContext, IMapper mapper)
    : IOctoPersistentGrantStore
{
    // Always use system tenant — grants are transient, keyed by unique keys,
    // and must be accessible across authorize and token endpoints.
    private readonly ITenantRepository _tenantRepository = systemContext.GetSystemTenantRepository();

    public async Task RemoveExpiredGrantsAsync()
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtPersistedGrant.ExpirationDate),
                FieldFilterOperator.LessEqualThan,
                DateTimeOffset.UtcNow);

        // Batch deletion in chunks of 50
        var expired = await _tenantRepository
            .GetRtEntitiesByTypeAsync<RtPersistedGrant>(session, queryOptions, 0, 50);

        foreach (var grant in expired)
        {
            await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(
                session, grant.RtId, DeleteOptions.Erase);
        }

        await session.CommitTransactionAsync();
    }
}
```

### OctoUserStore

Implements full ASP.NET Core Identity interfaces:

```csharp
public class OctoUserStore :
    IUserStore<RtUser>,
    IUserPasswordStore<RtUser>,
    IUserEmailStore<RtUser>,
    IUserRoleStore<RtUser>,
    IUserClaimStore<RtUser>,
    IUserLoginStore<RtUser>,
    IUserLockoutStore<RtUser>,
    IUserTwoFactorStore<RtUser>,
    IUserAuthenticatorKeyStore<RtUser>,
    IUserTwoFactorRecoveryCodeStore<RtUser>,
    IQueryableUserStore<RtUser>
{
    // Full user lifecycle management
}
```

## MongoDB Integration

### Repository Pattern

All stores use `ITenantRepository` for data access:

```csharp
// Query with filters
var queryOptions = RtEntityQueryOptions.Create()
    .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);
var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);

// Insert
await _tenantRepository.InsertOneRtEntityAsync(session, entity);

// Update (replace)
await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, entity.RtId, entity);

// Delete
await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtClient>(session, rtId, DeleteOptions.Erase);
```

### Query Options

`RtEntityQueryOptions` provides fluent query building:

```csharp
var options = RtEntityQueryOptions.Create()
    // Exact match
    .FieldFilter(nameof(RtUser.NormalizedEmail), FieldFilterOperator.Equals, email)
    // Array contains
    .FieldFilter(nameof(RtClient.AllowedScopes), FieldFilterOperator.AnyEq, scope)
    // Range query
    .FieldFilter(nameof(RtPersistedGrant.ExpirationDate),
        FieldFilterOperator.LessEqualThan, DateTimeOffset.UtcNow)
    // Nested record matching
    .MatchField(nameof(RtUser.Claims), nestedCriteria);
```

**Filter Operators:**
- `Equals` - Exact match
- `In` - Match any in collection
- `LessEqualThan` / `GreaterEqualThan` - Range queries
- `AnyEq` - Array contains element

### Transaction Support

ACID transactions for multi-document operations:

```csharp
var session = await _tenantRepository.GetSessionAsync();
session.StartTransaction();

try
{
    await _tenantRepository.InsertOneRtEntityAsync(session, entity1);
    await _tenantRepository.InsertOneRtEntityAsync(session, entity2);
    await session.CommitTransactionAsync();
}
catch
{
    await session.AbortTransactionAsync();
    throw;
}
```

## Entity Relationships

### Relationship Patterns

```
RtUser
├── AssignedRole → RtRole       # Many-to-Many via CK association
├── Claims: RtUserClaimRecord[]  # One-to-Many embedded
├── UserLogins: RtUserLoginRecord[]
└── UserTokens: RtUserTokenRecord[]

RtGroup
├── AssignedRole → RtRole                    # Many-to-Many via CK association
├── GroupMember → RtUser                     # Many-to-Many via CK association
├── GroupMember → RtExternalTenantUserMapping # Many-to-Many via CK association
└── ChildGroup → RtGroup                     # Many-to-Many via CK association

RtClient
├── ClientSecrets: RtSecretRecord[]
├── ClientClaims: RtClientClaimRecord[]
└── AllowedScopes: string[]

RtRole
└── Claims: RtRoleClaimRecord[]

RtApiResource
├── Scopes: string[]
└── ApiSecrets: RtSecretRecord[]
```

### Child Tenant Role Provisioning

All 10 default roles (TenantManagement, UserManagement, CommunicationManagement, Development, AdminPanelManagement, BotManagement, DashboardManagement, DashboardViewer, ReportingManagement, ReportingViewer) are provisioned to child tenants during `EnsureIdentityDataInChildTenantAsync()`. This uses the same `childRepo` pattern as clients and resources — querying by `NormalizedName` and inserting if missing. Roles are required in child tenants for per-tenant user management and cross-tenant role mapping.

### User-Role Relationship

User roles are modeled as `AssignedRole` CK associations (not embedded arrays):

```csharp
// Add role to user (via OctoUserStore / IUserRoleStore)
await userManager.AddToRoleAsync(user, roleName);
// Internally creates an AssignedRole association: User → Role

// Query user's roles (via association queries)
var roles = await userManager.GetRolesAsync(user);
// Queries outbound AssignedRole associations + group-inherited roles
```

### Association-Based Relationships

All identity relationships use CK associations defined in `identity-associations.yaml`:

| Association Role | Origin | Target | Description |
|-----------------|--------|--------|-------------|
| `AssignedRole` | User or Group | Role | Role assignments (N:N) |
| `GroupMember` | Group | User or ExternalTenantUserMapping | Group membership (N:N) |
| `ChildGroup` | Parent Group | Child Group | Nested group hierarchy (N:N) |

Association constants are defined in `IdentityAssociationConstants`:
- `AssignedRoleId`: `System.Identity/AssignedRole`
- `GroupMemberId`: `System.Identity/GroupMember`
- `ChildGroupId`: `System.Identity/ChildGroup`

**Group Role Resolution** (`IGroupRoleResolver` / `GroupRoleResolver`):

When `OctoUserStore.GetRolesAsync()` is called during token issuance, it:
1. Queries the user's direct `AssignedRole` associations for directly assigned roles
2. Calls `IGroupRoleResolver.ResolveEffectiveRoleIdsAsync(userRtId)` to find all groups where the user is a member (via `GroupMember` associations)
3. Recursively traverses `ChildGroup` associations, collecting all `AssignedRole` targets from parent groups
4. Uses a visited set and max depth of 10 to prevent circular traversal
5. Returns the union of direct and group-inherited role IDs

The same logic applies to `IsInRoleAsync`. For external cross-tenant users, `ResolveEffectiveRoleIdsForExternalUserAsync` checks `GroupMember` associations targeting `ExternalTenantUserMapping` entities instead.

### Default TenantOwners Group

Every tenant is provisioned with a `TenantOwners` group that has all 10 default roles assigned (via `AssignedRole` associations). This group is:
- Created during `DefaultConfigurationCreatorService.SetupTenantAsync()` for new tenants
- Provisioned to child tenants via `EnsureGroupInChildTenantAsync()`
- Migrated to existing tenants via `IdentityAssociationMigration` (migration 9→10)

## Migration System

### Migration Pattern

Migrations are versioned and auto-discovered:

```csharp
[Migration(0, 1, IdentityServiceConstants.IdentityMigrationVersionKey)]
internal class InitialMigration : IMigration
{
    public async Task<MigrationResult> MigrateAsync(
        IOctoAdminSession adminSession,
        ITenantContext tenantContext)
    {
        // Create indexes, update schemas, etc.
        return MigrationResult.Success();
    }
}
```

### Migration Versions

| Version | Class | Purpose |
|---------|-------|---------|
| 0 → 1 | `InitialMigration` | Create RT association indexes |
| 1 → 2 | `CkTypeIndexMigration` | Update CK type indexes |
| 2 → 3 | `CkTypeIndexMigration2` | Additional index updates |
| 9 → 10 | `IdentityAssociationMigration` | Convert StringArray relationships to CK associations; create TenantOwners group |

Current schema version: `IdentitySchemaVersionValue = 11`

### Registration

Migrations are registered in `Program.cs`:

```csharp
builder.Services.AddMigrations(typeof(IdentityServiceConstants).Assembly);
```

Migrations run automatically on application startup.

## AutoMapper Configuration

Mapping between Duende models and CK runtime types:

```csharp
// Duende → CK Runtime
CreateMap<Client, RtClient>()
    .ForMember(dest => dest.ClientSecrets,
        opt => opt.MapFrom(src => src.ClientSecrets));

// CK Runtime → Duende
CreateMap<RtClient, Client>()
    .ForMember(dest => dest.ClientSecrets,
        opt => opt.MapFrom(src => src.ClientSecrets));
```

**Custom Converters:**
- `AttributeStringValueListConverter` - Maps `ICollection<string>` ↔ `IAttributeValueList<string>`

## Dependency Injection Setup

Store registration in `RuntimeEngineBuilderExtensions.AddOctoIdentityPersistence()`:

```csharp
builder.AddMongoDbRuntimeRepository();
builder.Services.AddCkModelSystemIdentityV1();  // Register generated CK models

builder.Services.AddScoped<IOctoClientStore, ClientStore>();
builder.Services.AddScoped<IOctoResourceStore, ResourceStore>();
builder.Services.AddScoped<IOctoPersistentGrantStore, PersistentGrantStore>();
builder.Services.AddScoped<IOctoIdentityProviderStore, IdentityProviderStore>();

builder.Services.AddScoped<IGroupStore, GroupStore>();
builder.Services.AddScoped<IGroupRoleResolver, GroupRoleResolver>();

builder.Services.AddIdentity<RtUser, RtRole>()
    .AddUserStore<OctoUserStore>()
    .AddRoleStore<OctoRoleStore>();
```
