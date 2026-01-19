# Suggested Commands for Development

## Build Commands

### Build Entire Solution
```bash
# Standard build
dotnet build Octo.Identity.sln

# Release build
dotnet build Octo.Identity.sln --configuration Release

# Debug build (default)
dotnet build Octo.Identity.sln --configuration Debug

# DebugL build (local development, version 999.0.0)
dotnet build Octo.Identity.sln --configuration DebugL
```

### Build with Private NuGet Feed
```bash
dotnet build Octo.Identity.sln -c Release /p:OctoNugetPrivateServer=<server-url>
```

### Build Specific Project
```bash
# Build main service
dotnet build src/IdentityServices/IdentityServices.csproj --configuration Release

# Build authentication library
dotnet build src/Authentication/Authentication.csproj

# Build persistence model (triggers CK code generation)
dotnet build src/Persistence.IdentityCkModel/Persistence.IdentityCkModel.csproj
```

### Clean and Rebuild
```bash
# Clean
dotnet clean Octo.Identity.sln

# Clean and rebuild
dotnet clean Octo.Identity.sln && dotnet build Octo.Identity.sln
```

## Restore Commands

### Standard Restore
```bash
dotnet restore Octo.Identity.sln
```

### Force Restore (Clear Cache)
```bash
dotnet restore Octo.Identity.sln --force
```

### Restore with Private NuGet Server
```bash
dotnet restore Octo.Identity.sln --force /p:OctoNugetPrivateServer=<server-url>
```

## Testing Commands

### Run All Tests (Exclude System Tests)
```bash
dotnet test --filter "FullyQualifiedName!~SystemTests"
```

### Run All Tests
```bash
dotnet test Octo.Identity.sln
```

### Run Specific Test Project
```bash
dotnet test src/IdentityServices.Tests/IdentityServices.Tests.csproj
dotnet test src/Authentication.Tests/Authentication.Tests.csproj
```

### Run Tests with Detailed Output
```bash
dotnet test --verbosity detailed
```

### Run Tests with Coverage
```bash
dotnet test --collect:"XPlat Code Coverage"
```

## Running the Application

### Run Main Service
```bash
# From solution root
dotnet run --project src/IdentityServices/IdentityServices.csproj

# From project directory
cd src/IdentityServices
dotnet run
```

### Run with Specific Environment
```bash
# Development
dotnet run --project src/IdentityServices/IdentityServices.csproj --environment Development

# Production
dotnet run --project src/IdentityServices/IdentityServices.csproj --environment Production
```

### Run with Configuration Override
```bash
dotnet run --project src/IdentityServices/IdentityServices.csproj \
  -- Identity:Authority=https://localhost:5001
```

## Docker Commands

### Build Docker Image
```bash
docker build -f src/IdentityServices/Dockerfile \
  --build-arg OCTO_PRIVATE_NUGET_SERVICE=<server> \
  --build-arg OCTO_PRIVATE_NUGET_CERTIFICATE=<path> \
  --build-arg OCTO_VERSION=<version> \
  -t octo-identity-services .
```

### Run Docker Container
```bash
docker run -p 5000:80 \
  -e OCTO_Identity__Authority=https://identity.example.com \
  -e OCTO_Runtime__MongoDb__ConnectionString="mongodb://localhost:27017" \
  octo-identity-services
```

## Git Commands (Darwin/macOS)

### Common Git Operations
```bash
# Status
git status

# Add changes
git add .
git add <file>

# Commit
git commit -m "AB#<ticket>: <type>: <message>"

# Push
git push origin <branch>

# Pull
git pull origin main

# Create branch
git checkout -b feature/<branch-name>

# View log
git log --oneline -10
```

### Commit Message Convention
Format: `AB#<ticket-number>: <type>: <message>`

Types:
- `New:` - New feature
- `Fix:` - Bug fix
- `Update:` - Enhancement to existing feature
- `Refactor:` - Code refactoring
- `Docs:` - Documentation changes
- `Test:` - Test additions/modifications

Examples:
```
AB#2811: New: Introducing DeleteOptions and reworking DataQueryOperation
AB#2767: New: Notification ck model is imported by identity service only
AB#2758: Fix: Ensure load sequence that octo system is created before migrations
```

## File System Commands (Darwin/macOS)

### Directory Navigation
```bash
# List files
ls -la

# Change directory
cd <directory>

# Print working directory
pwd

# Create directory
mkdir <directory-name>

# Remove directory
rm -rf <directory-name>
```

### File Operations
```bash
# View file
cat <file>
less <file>

# Find files
find . -name "*.cs"
find . -type f -name "*Controller.cs"

# Search in files (using grep)
grep -r "pattern" src/
grep -r "RtUser" src/ --include="*.cs"
```

### Process Management
```bash
# List processes
ps aux | grep dotnet

# Kill process
kill <pid>
kill -9 <pid>  # Force kill
```

## NuGet Commands

### List Packages
```bash
dotnet list package
dotnet list package --outdated
```

### Add Package
```bash
dotnet add package <package-name>
dotnet add package <package-name> --version <version>
```

### Remove Package
```bash
dotnet remove package <package-name>
```

## Construction Kit (CK) Workflow

### Regenerate CK Models
```bash
# Clean and rebuild the CK model project
dotnet clean src/Persistence.IdentityCkModel/Persistence.IdentityCkModel.csproj
dotnet build src/Persistence.IdentityCkModel/Persistence.IdentityCkModel.csproj
```

### View Generated Code
```bash
# Generated code location
ls -la src/Persistence.IdentityCkModel/obj/Generated/
ls -la src/Persistence.IdentityCkModel/Generated/
```

## Development Workflow Commands

### Quick Development Cycle
```bash
# 1. Build
dotnet build Octo.Identity.sln

# 2. Run tests
dotnet test --filter "FullyQualifiedName!~SystemTests"

# 3. Run application
dotnet run --project src/IdentityServices/IdentityServices.csproj
```

### Local Development Setup
```bash
# Use DebugL configuration for local development
dotnet build Octo.Identity.sln --configuration DebugL

# This uses version 999.0.0 and local NuGet folder
# Configured in Directory.Build.props
```

## Troubleshooting Commands

### Clear NuGet Cache
```bash
dotnet nuget locals all --clear
```

### View Detailed Build
```bash
dotnet build Octo.Identity.sln --verbosity detailed
```

### Check .NET Version
```bash
dotnet --version
dotnet --info
```

### View Solution Structure
```bash
dotnet sln Octo.Identity.sln list
```
