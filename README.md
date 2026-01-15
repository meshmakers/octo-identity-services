# Octo Identity Services

OAuth 2.0 / OpenID Connect identity provider for the Octo platform, built on [Duende IdentityServer](https://duendesoftware.com/products/identityserver).

## Features

- OAuth 2.0 and OpenID Connect authentication
- Multiple identity providers: Google, Facebook, Microsoft, Azure Entra ID, OpenLDAP, Microsoft AD
- Dynamic authentication scheme management (runtime configuration)
- Multi-tenant support
- REST API for identity management
- MongoDB persistence via Octo Runtime Engine

## Requirements

- .NET 10 SDK
- MongoDB 5.0+
- Octo framework packages

## Quick Start

```bash
# Clone the repository
git clone https://github.com/meshmakers/octo-identity-services.git
cd octo-identity-services

# Restore dependencies
dotnet restore

# Build the solution
dotnet build

# Run the identity service
dotnet run --project src/IdentityServices/IdentityServices.csproj
```

## Configuration

Configure via environment variables (prefix `OCTO_`) or `appsettings.json`:

```bash
export OCTO_System__MongoDbConnectionString="mongodb://localhost:27017"
export OCTO_System__MongoDbDatabaseName="octo-identity"
```

For local development, use .NET User Secrets:

```bash
dotnet user-secrets set "System:MongoDbConnectionString" "mongodb://localhost:27017"
```

## Project Structure

```
src/
├── IdentityServices/           # Main web application
├── Authentication/             # Dynamic authentication providers
├── IdentityServerPersistence/  # Data stores (MongoDB)
├── Persistence.IdentityCkModel/# Entity model definitions (YAML)
└── IdentityServices.Resources/ # Localized strings
```

## Documentation

Detailed documentation is available in the [docs](docs/) folder:

- [Architecture Overview](docs/architecture-overview.md) - System design and components
- [Authentication](docs/authentication.md) - Identity providers and auth flows
- [Persistence](docs/persistence.md) - Data layer and Construction Kit
- [System API](docs/system-api.md) - REST API reference
- [Configuration](docs/configuration.md) - Deployment and configuration

## Docker

```bash
docker build \
    --build-arg OCTO_VERSION=3.2.0 \
    -t octo-identity-services:latest \
    -f src/IdentityServices/Dockerfile .

docker run -d \
    -e OCTO_System__MongoDbConnectionString="mongodb://mongo:27017" \
    -p 80:80 \
    octo-identity-services:latest
```

## License

[MIT License](LICENSE)

Copyright (c) 2026 meshmakers.io
