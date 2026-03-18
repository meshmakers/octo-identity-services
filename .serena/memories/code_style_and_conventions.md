# Code Style and Conventions

## C# Language Settings
- **Language Version**: Latest major C# version (`latestmajor`)
- **Nullable Reference Types**: Enabled
- **Implicit Usings**: Enabled
- **Target Framework**: net9.0
- **Treat Warnings as Errors**: True (strict quality enforcement)

## Naming Conventions

### Type Prefixes
- **`Rt*` prefix**: Runtime entities from Construction Kit (e.g., `RtUser`, `RtClient`, `RtRole`)
  - These are auto-generated from YAML models
  - Found in `Generated/System.Identity.v1/` namespace
  - Never manually edit these files

- **`I*` prefix**: Interfaces (standard .NET convention)
  - Example: `IClientStore`, `IUserEmailInteractionService`, `ITenantContext`

- **`*Dto` suffix**: Data Transfer Objects
  - Used for API request/response models
  - Separate from domain entities

- **`*Service` suffix**: Service classes
  - Business logic layer
  - Example: `IUserEmailInteractionService`

- **`*Store` suffix**: Data store implementations
  - Persistence layer
  - Example: `ClientStore`, `ResourceStore`
  - Implement IdentityServer store interfaces

- **`*Consumer` suffix**: Event/message consumers
  - Handle distributed events
  - Registered in `Program.cs`

### Controller Naming
- Controllers end with `Controller` suffix
- Located in `src/IdentityServices/TenantApi/v{version}/Controllers/`
- Examples: `UsersController`, `ClientsController`, `RolesController`

## API Conventions

### Controller Structure
```csharp
[Route(IdentityServiceConstants.ApiPathPrefix)]
[Authorize(Policy = IdentityServiceConstants.IdentityApiReadWritePolicy)]
public class ExampleController : ControllerBase
{
    // Controller implementation
}
```

### Route Patterns
- Base path: `/{tenantId:tenantId}/v{version:apiVersion}/`
- API versioning via route constraint

### Authorization
- Use policy-based authorization
- Read-only policy: `IdentityApiReadOnlyPolicy`
- Read-write policy: `IdentityApiReadWritePolicy`

## Configuration Patterns

### Options Pattern
```csharp
// Registration
builder.Services.Configure<MyOptions>(configuration.GetSection("MySection"));

// Usage
public class MyService
{
    private readonly MyOptions _options;
    
    public MyService(IOptions<MyOptions> options)
    {
        _options = options.Value;
    }
}
```

### Dynamic Authentication Registration
```csharp
builder.Services.AddDynamicAuthentication()
    .AddGoogle()
    .AddMicrosoft()
    .AddAzureEntraId()
    .AddOpenLdapAuthentication();
```

## Construction Kit (CK) Guidelines

### Working with CK Models
1. **Never manually edit** `Rt*` classes - they are generated
2. **Edit YAML** in `src/Persistence.IdentityCkModel/ConstructionKit/types/`
3. **Rebuild** to trigger source generation
4. **Generated location**: `obj/` and `Generated/` folders

### Adding New Entities
```yaml
# In ConstructionKit/types/MyEntity.yaml
type:
  name: MyEntity
  properties:
    - name: Id
      type: string
    - name: Name
      type: string
```

After rebuild, use as `RtMyEntity` in code.

## Project Settings

### Directory.Build.props
Key settings enforced across all projects:
- `LangVersion`: latestmajor
- `Nullable`: enable
- `TreatWarningsAsErrors`: true
- `ImplicitUsings`: true
- `TargetFramework`: net9.0

### Version Management
- **DebugL**: 999.0.0 (local development)
- **Private NuGet**: 0.1.* (when `OctoNugetPrivateServer` set)
- **Public NuGet**: 3.2.* (default)

## Error Handling
- Enable nullable reference types
- Treat warnings as errors
- Use proper exception handling in services
- Return appropriate HTTP status codes in controllers

## Dependency Injection
- Register services in `Program.cs`
- Use interface-based dependencies
- Follow ASP.NET Core DI patterns
- Lifetime management:
  - Transient: Per request
  - Scoped: Per HTTP request
  - Singleton: Application lifetime

## Best Practices

### Store Implementations
```csharp
public class MyStore : IMyStore
{
    private readonly IMongoDatabase _database;
    
    public MyStore(IMongoDatabase database)
    {
        _database = database;
    }
    
    // Implementation
}

// Registration
builder.Services.AddTransient<IMyStore, MyStore>();
```

### Adding API Endpoints
1. Create controller in `TenantApi/v{version}/Controllers/`
2. Inherit from `ControllerBase`
3. Apply route attribute: `[Route(IdentityServiceConstants.ApiPathPrefix)]`
4. Apply authorization: `[Authorize(Policy = ...)]`
5. Implement actions with proper HTTP verbs

### Adding Authentication Providers
1. Extend `src/Authentication/` project
2. Create provider implementation
3. Add builder extension in `DynamicAuthBuilderExtensions`
4. Register in `Program.cs`

## File Organization
- Keep related files together (controllers, services, stores)
- Separate concerns by layer
- Use namespaces that match folder structure
- Place shared code in appropriate libraries
