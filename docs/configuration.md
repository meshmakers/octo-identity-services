# Configuration and Deployment

## Environment Variables

All Octo-specific environment variables use the `OCTO_` prefix.

```bash
# Example configuration
export OCTO_System__MongoDbConnectionString="mongodb://localhost:27017"
export OCTO_System__MongoDbDatabaseName="octo-identity"
export OCTO_Identity__SigningCertificatePath="/app/certs/signing.pfx"
export OCTO_Identity__SigningCertificatePassword="secret"
```

### Configuration Sections

#### System Configuration

```json
{
  "System": {
    "MongoDbConnectionString": "mongodb://localhost:27017",
    "MongoDbDatabaseName": "octo-identity",
    "TenantId": "System"
  }
}
```

#### Identity Configuration

```json
{
  "Identity": {
    "SigningCertificatePath": "/app/certs/signing.pfx",
    "SigningCertificatePassword": "password",
    "IssuerUri": "https://identity.example.com"
  }
}
```

Key options in `OctoIdentityServicesOptions`:

| Option | Env variable | Description |
|--------|-------------|-------------|
| `AuthorityUrl` | `OCTO_IDENTITY__AuthorityUrl` | Public URL of the Identity service (default: `https://localhost:5003`) |
| `RefineryStudioUrl` | `OCTO_IDENTITY__RefineryStudioUrl` | Public URL of the Data Refinery Studio SPA. When set, the `octo-data-refinery-studio` OIDC client is auto-provisioned in all tenants. |
| `DataProtectionKeysPath` | `OCTO_IDENTITY__DataProtectionKeysPath` | **Legacy / seed-only.** When set and the directory contains `key-*.xml` files, those keys are imported once into MongoDB at startup (zero-logout migration from the old PVC). Safe to leave unset in new deployments — DataProtection keys are always stored in MongoDB (`RtDataProtectionKey`, system tenant). |

### Configuration Sources

Configuration is loaded in this order (later sources override earlier):

1. `appsettings.json`
2. `appsettings.{Environment}.json`
3. Environment variables (with `OCTO_` prefix)
4. Command-line arguments
5. User secrets (development only)

```csharp
builder.Configuration
    .AddEnvironmentVariables("OCTO_")
    .AddCommandLine(args)
    .AddUserSecrets(typeof(Program).Assembly, true);
```

### User Secrets

For local development, use .NET User Secrets:

**User Secrets ID:** `173d8e91-b831-4e8a-a43f-672c57e6a4da`

```bash
# Set a secret
dotnet user-secrets set "System:MongoDbConnectionString" "mongodb://localhost:27017"

# List secrets
dotnet user-secrets list

# Clear all secrets
dotnet user-secrets clear
```

## Build Configurations

### Standard Configurations

| Configuration | Purpose |
|--------------|---------|
| Debug | Development with debug symbols |
| Release | Production builds |
| DebugL | Local development with local NuGet packages |

### DebugL Configuration

The `DebugL` configuration is for local development when working with local Octo packages:

- Sets version to `999.0.0`
- Uses NuGet sources from `../nuget` directory
- Useful when developing Octo framework packages alongside this service

```bash
# Build with local packages
dotnet build Octo.Identity.sln -c DebugL
```

### Version Management

Versions are controlled via `Directory.Build.props`:

```xml
<PropertyGroup>
    <!-- Version for DebugL (local development) -->
    <OctoVersion Condition="'$(Configuration)'=='DebugL'">999.0.0</OctoVersion>

    <!-- Version for private NuGet server -->
    <OctoVersion Condition="'$(OctoNugetPrivateServer)'!='' And '$(OctoVersion)'==''">0.1.*</OctoVersion>

    <!-- Default public version -->
    <OctoVersion Condition="'$(OctoNugetPrivateServer)'=='' And '$(OctoVersion)'==''">3.2.*</OctoVersion>
</PropertyGroup>
```

## Docker Deployment

### Dockerfile

Located at `src/IdentityServices/Dockerfile`:

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS build

ARG OCTO_PRIVATE_NUGET_SERVICE
ARG OCTO_PRIVATE_NUGET_CERTIFICATE
ARG OCTO_VERSION

# Install private NuGet CA certificate
COPY ${OCTO_PRIVATE_NUGET_CERTIFICATE} /usr/local/share/ca-certificates/nugetca.crt
RUN chmod 644 /usr/local/share/ca-certificates/nugetca.crt && update-ca-certificates

WORKDIR /src
COPY . .
ENV NUGET_XMLDOC_MODE=none
WORKDIR "/src/src/IdentityServices"
RUN dotnet build "IdentityServices.csproj" -c Release \
    -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE} \
    -p:OctoVersion=${OCTO_VERSION}

FROM build AS publish
RUN dotnet publish "IdentityServices.csproj" -c Release \
    -p:OctoNugetPrivateServer=${OCTO_PRIVATE_NUGET_SERVICE} \
    -p:OctoVersion=${OCTO_VERSION} \
    -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
COPY --from=build /src/src/IdentityServices/run.sh /app/run.sh

ENTRYPOINT ["/bin/sh", "-c", "chmod +x /app/run.sh && /app/run.sh"]
```

### Build Arguments

| Argument | Description |
|----------|-------------|
| `OCTO_PRIVATE_NUGET_SERVICE` | Private NuGet feed URL |
| `OCTO_PRIVATE_NUGET_CERTIFICATE` | Path to CA certificate for private NuGet |
| `OCTO_VERSION` | Package version to use |

### Build Example

```bash
docker build \
    --build-arg OCTO_PRIVATE_NUGET_SERVICE=https://nuget.internal.example.com \
    --build-arg OCTO_PRIVATE_NUGET_CERTIFICATE=./ca.crt \
    --build-arg OCTO_VERSION=3.2.0 \
    -t octo-identity-services:latest \
    -f src/IdentityServices/Dockerfile .
```

### Runtime Configuration

Pass configuration via environment variables:

```bash
docker run -d \
    -e OCTO_System__MongoDbConnectionString="mongodb://mongo:27017" \
    -e OCTO_System__MongoDbDatabaseName="octo-identity" \
    -e OCTO_Identity__IssuerUri="https://identity.example.com" \
    -p 80:80 \
    octo-identity-services:latest
```

## Kubernetes Deployment

### ConfigMap Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: identity-services-config
data:
  appsettings.Production.json: |
    {
      "System": {
        "MongoDbDatabaseName": "octo-identity"
      },
      "Logging": {
        "LogLevel": {
          "Default": "Information"
        }
      }
    }
```

### Secret Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: identity-services-secrets
type: Opaque
stringData:
  OCTO_System__MongoDbConnectionString: "mongodb://mongo:27017"
  OCTO_Identity__SigningCertificatePassword: "secret"
```

### Deployment Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: identity-services
spec:
  replicas: 2
  selector:
    matchLabels:
      app: identity-services
  template:
    metadata:
      labels:
        app: identity-services
    spec:
      containers:
      - name: identity-services
        image: meshmakers/octo-mesh-identity-services:latest
        ports:
        - containerPort: 80
        envFrom:
        - secretRef:
            name: identity-services-secrets
        volumeMounts:
        - name: config
          mountPath: /app/appsettings.Production.json
          subPath: appsettings.Production.json
        - name: signing-cert
          mountPath: /app/certs
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: identity-services-config
      - name: signing-cert
        secret:
          secretName: signing-certificate
```

## Logging

### NLog Configuration

Logging is configured via `nlog.config`:

```xml
<?xml version="1.0" encoding="utf-8" ?>
<nlog xmlns="http://www.nlog-project.org/schemas/NLog.xsd"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

    <targets>
        <target name="console" xsi:type="Console"
                layout="${longdate}|${level:uppercase=true}|${logger}|${message} ${exception:format=tostring}" />
    </targets>

    <rules>
        <logger name="*" minlevel="Info" writeTo="console" />
    </rules>
</nlog>
```

### Runtime Log Level Changes

Log levels can be changed at runtime via the API:

```http
POST /{tenantId}/v1/diagnostics/reconfigureLogLevel?minLogLevel=Debug&maxLogLevel=Error
# Example: POST /octosystem/v1/diagnostics/reconfigureLogLevel?minLogLevel=Debug&maxLogLevel=Error
```

## Health Checks

The service exposes health check endpoints via the Observability package:

```
GET /health        # Overall health
GET /health/ready  # Readiness probe
GET /health/live   # Liveness probe
```

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 80
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /health/ready
    port: 80
  initialDelaySeconds: 5
  periodSeconds: 10
```

## CI/CD Pipeline

### Azure Pipelines

The project includes Azure DevOps pipeline configuration in `devops-build/azure-pipelines.yml`:

**Triggers:**
- `dev/*` branches
- `test/*` branches
- `main` branch

**Build Steps:**
1. Restore NuGet packages
2. Build solution
3. Run tests
4. Build Docker image
5. Push to container registry
6. Publish Construction Kit artifacts

### Construction Kit Artifacts

The pipeline publishes CK model artifacts for use by other services:

```yaml
constructionKitLibraryPaths:
  - 'src/Persistence.IdentityCkModel/bin/$(buildConfiguration)/$(artifactsFrameworkVersion)/octo-ck-libraries/Persistence.IdentityCkModel'
```

## TLS Considerations

The service runs behind an ingress controller that terminates TLS. The application:

1. Runs HTTP internally
2. Forces HTTPS scheme in requests for correct discovery document URLs

```csharp
app.Use((context, next) =>
{
    context.Request.Scheme = "https";
    return next();
});
```

Ensure your ingress controller is configured for TLS termination and sets appropriate headers (`X-Forwarded-Proto`).
