# Octo Identity Services - Developer Documentation

This documentation provides a comprehensive architectural deep-dive into the Octo Identity Services codebase.

## Table of Contents

| Document | Description |
|----------|-------------|
| [Architecture Overview](architecture-overview.md) | High-level system architecture, project structure, and technology stack |
| [Authentication](authentication.md) | Dynamic authentication framework, identity providers, and authentication flows |
| [External Identity Provider Setup](external-identity-provider-setup.md) | Step-by-step setup guides for Google, Microsoft, Facebook, Azure Entra ID |
| [Persistence](persistence.md) | Data layer, Construction Kit model, and MongoDB integration |
| [System API](system-api.md) | REST API reference, endpoints, and authorization |
| [Configuration](configuration.md) | Environment variables, build configurations, and deployment |

## Quick Reference

### Build & Run

```bash
# Build the solution
dotnet build Octo.Identity.sln

# Run the identity service
dotnet run --project src/IdentityServices/IdentityServices.csproj

# Build for local development (uses local NuGet packages)
dotnet build Octo.Identity.sln -c DebugL
```

### Project Structure

```
src/
├── IdentityServices/           # Main web application (entry point)
├── Authentication/             # Dynamic authentication providers
├── IdentityServerPersistence/  # Data stores and MongoDB integration
├── Persistence.IdentityCkModel/# Construction Kit model definitions
└── IdentityServices.Resources/ # Localized string resources
```

### Key Technologies

- **.NET 10** - Target framework
- **Duende IdentityServer** - OAuth 2.0 / OpenID Connect implementation
- **MongoDB** - Data persistence via Octo Runtime Engine
- **ASP.NET Core Identity** - User and role management
