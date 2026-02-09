# Build/Runtime Issue Analysis: CK Migrations Refactoring

## Summary
There are TWO different issues depending on the environment:

### Azure DevOps (Private NuGet v0.1.x)
- **Type**: RUNTIME error during test execution
- **Status**: Tests fail after build succeeds
- **Error**: `Could not load type 'Meshmakers.Octo.Runtime.Contracts.Blueprints.IMigrationExecutor'`
- **Root Cause**: After CK migrations refactoring, `IMigrationExecutor` was removed from v0.1.x packages
- **Location**: `AddRuntimeEngine()` method tries to reference this missing type

### Local Development (Public NuGet v3.3.x)
- **Type**: BUILD error during CK model compilation  
- **Status**: Build fails before tests can run
- **Error**: `'System-(,3.0)' is not a known construction kit model`
- **Root Cause**: Version 3.3.x changed model discovery mechanism; System model not in accessible catalog

## Root Cause Analysis

### Environment Differences
The Azure DevOps build environment differs significantly from local development:

1. **Azure Pipeline Configuration** (`devops-build/azure-pipelines.yml`):
   - Uses private NuGet server: `$(nugetPrivateServer)` variable
   - Package version: `0.1.*` (from private feed)
   - Setting: `OctoLocalCatalogIsEnabled: 'false'`
   - Build: **SUCCEEDS** ✓
   - Tests: **FAIL** ✗ (Runtime error: `IMigrationExecutor` missing)

2. **Local Development** (without private NuGet access):
   - Uses public NuGet: `https://api.nuget.org/v3/index.json`
   - Package version: `3.3.*` (latest public)
   - Setting: `OctoLocalCatalogIsEnabled: 'true'` (default)
   - Build: **FAILS** ✗ (CK model not found)
   - Tests: Cannot run (build fails first)

### The Real Issue (Azure Environment)
After the "CK migrations refactoring", the type `Meshmakers.Octo.Runtime.Contracts.Blueprints.IMigrationExecutor` was removed from the runtime contracts package (v0.1.x).

However, `AddRuntimeEngine()` (in `Meshmakers.Octo.Runtime.Engine.MongoDb`) still tries to reference this type internally, causing:
```
System.TypeLoadException: Could not load type 'Meshmakers.Octo.Runtime.Contracts.Blueprints.IMigrationExecutor' 
from assembly 'Meshmakers.Octo.Runtime.Contracts, Version=0.1.0.0'
```

This affects:
- `tests/IdentityServices.IntegrationTests/Fixtures/ServiceCollectionFixture.cs` (line 26)
- `tests/IdentityServices.IntegrationTests/Infrastructure/CustomWebApplicationFactory.cs` (line 104)  
- `src/IdentityServices/Program.cs` (line 102)

### What Changed
After the "CK migrations refactoring" in Octo framework 3.3.x:
- **Before**: CK compiler automatically discovered models from referenced NuGet packages
- **After**: CK compiler requires models to be in a catalog (Local/PrivateGitHub/PublicGitHub)
- The System model package exists but is not discoverable by the compiler

## Attempted Solutions

### 1. Version Range Adjustments ❌
- Tried: `System-(,2.0)`, `System-[2.0,3.0)`, `System-(,3.0)`, `System-2.0.2`
- Result: Same error for all variants
- Conclusion: Syntax is correct; discovery mechanism is the issue

### 2. Explicit construction-kits.yaml File ❌
- Created `src/Persistence.IdentityCkModel/construction-kits.yaml` with various formats
- Added explicit `<ConstructionKitConfigFile>` item to project file  
- Result: File not processed or schema validation failures

### 3. Downgrade to 3.3.20 ❌
- Tested with Octo packages version 3.3.20 instead of 3.3.22
- Result: Identical error - issue exists across multiple 3.3.x versions

### 4. Manual Catalog Population ❌
- Investigated MSBuild tasks (`CkCompile`, `CkRestore`)
- No clear mechanism found to populate catalog from NuGet packages

## Required Information

To fix the ACTUAL issue (Azure DevOps runtime error), we need:

1. **Access to Private NuGet Server**
   - URL configured in Azure variable: `$(nugetPrivateServer)`
   - Contains Octo packages version `0.1.*`
   - Required to reproduce and test the fix locally

2. **Updated Package Information**
   - Which version of `Meshmakers.Octo.Runtime.Engine.MongoDb` is compatible post-refactoring?
   - Is there a migration guide for the CK migrations refactoring?
   - What replaced `IMigrationExecutor` in the new architecture?

3. **Alternative**: If using public NuGet v3.3.x
   - Need mechanism to register System model in catalog
   - OR working `construction-kits.yaml` format for v3.3.x
   - This would allow local development and testing

## Proposed Solutions

### Option A: Update to Compatible Package Version (Recommended)
Update `Directory.Build.props` to use a specific version of Octo packages that:
1. Has the refactored CK migrations (without `IMigrationExecutor`)
2. Works with the current codebase
3. Is available on public NuGet (or provide private feed access)

### Option B: Code Changes for v0.1.x Compatibility
If `IMigrationExecutor` was removed but migrations still work differently:
1. Update calls to `AddRuntimeEngine()` if parameters changed
2. Remove any explicit references to `IMigrationExecutor`  
3. Update migration registration/execution code if the API changed

### Option C: Revert to Pre-Refactoring Version
Use an older version of Octo packages (before CK migrations refactoring) if the new version isn't ready

## Cannot Proceed Without

- [ ] Access to private NuGet server with v0.1.x packages, OR
- [ ] Specific compatible package version numbers to use, OR
- [ ] Migration guide explaining the breaking changes

## Impact
- **Azure DevOps**: Build succeeds, but ALL integration tests fail at runtime
- **Local Development**: Cannot build or test without private NuGet access
- **Scope**: Affects entire integration test suite and main application startup

## Files Involved
- `tests/IdentityServices.IntegrationTests/Fixtures/ServiceCollectionFixture.cs:26`
- `tests/IdentityServices.IntegrationTests/Infrastructure/CustomWebApplicationFactory.cs:104`
- `src/IdentityServices/Program.cs:102`
- `devops-build/azure-pipelines.yml` (line 32-33, 60)
- `Directory.Build.props` (package version selection)
- `src/Persistence.IdentityCkModel/ConstructionKit/ckModel.yaml`

## Next Steps
1. **Immediate**: Get access to private NuGet server or compatible package versions
2. **Then**: Reproduce the actual runtime error locally
3. **Then**: Update code to work with refactored CK migrations API
4. **Finally**: Test and verify fix in both environments

## Environment
- .NET SDK: 10.0.102
- Octo Packages: 3.3.* (currently resolves to 3.3.22)
- Target Framework: net10.0
- OS: Linux (GitHub Actions runner)
