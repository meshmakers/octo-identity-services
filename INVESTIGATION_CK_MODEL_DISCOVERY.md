# Construction Kit Model Discovery Issue - Investigation Report

## Problem Statement
Build fails with error: `'System-(,2.0)' is not a known construction kit model`

## Environment
- **Octo Framework Version**: 3.3.22
- **System Model Package**: Meshmakers.Octo.ConstructionKit.Models.System 3.3.22
- **System Model ID (in DLL)**: System-2.0.2
- **Dependency Declaration**: `System-(,2.0)` (version < 2.0)

## Root Cause Analysis

### 1. Version Mismatch
The dependency declares `System-(,2.0)` which means "System with version < 2.0" (exclusive upper bound).
The actual System model in the package is version `2.0.2`, which does NOT satisfy this constraint (2.0.2 >= 2.0).

### 2. Model Discovery Mechanism Changed in 3.3.22
After investigating the "refactoring ck migrations" mentioned for version 3.3.22:

- **Before 3.3.22**: The CK compiler likely discovered models from referenced NuGet package assemblies automatically
- **After 3.3.22**: The CK compiler requires models to be in a catalog:
  - Local Filesystem Catalog: `~/.octo/ck-catalog/`
  - Private GitHub Catalog (requires `OctoPrivateGitHubApiKey`)
  - Public GitHub Catalog (requires `OctoPublicGitHubApiKey`)

### 3. Catalog is Empty
The local catalog at `~/.octo/ck-catalog/cache/` shows:
```json
{"version":"1.0","updatedAt":"2026-02-09T17:52:40Z","models":{}}
```

The `models` object is empty, meaning the System model is not registered in any accessible catalog.

## Investigation Steps Taken

### Attempted Solutions
1. ✅ **Updated dependency version range** to `System-(,3.0)` - Still failed (model not found)
2. ✅ **Used exact version** `System-2.0.2` - Still failed (model not found)
3. ✅ **Created construction-kits.yaml** with various formats:
   ```yaml
   # Attempt 1: libraries with assemblyPath
   libraries:
     - assemblyPath: /path/to/System.dll
   
   # Attempt 2: models with modelId
   models:
     - modelId: System-2.0.2
       assemblyPath: /path/to/System.dll
   
   # Attempt 3: packageId reference
   libraries:
     - packageId: Meshmakers.Octo.ConstructionKit.Models.System
       version: 3.3.22
   ```
   **Result**: All formats rejected with schema validation error:
   ```
   Schema validation failed at '/libraries'->'All values fail against the false schema'
   ```

4. ✅ **Manually triggered CkRestore target** - Successfully runs but rejects construction-kits.yaml schema
5. ✅ **Disabled local catalog** (`OctoLocalCatalogIsEnabled=false`) - No change
6. ✅ **Provided GitHub API key** - No change (model likely not published to public catalog yet)

### Key Findings

1. **CkRestore task exists** but requires valid `construction-kits.yaml` format
2. **Schema validation is very strict** - rejects all property combinations tried
3. **Compiler always refreshes cache** but finds no models
4. **System model DLL exists** at `~/.nuget/packages/meshmakers.octo.constructionkit.models.system/3.3.22/lib/net10.0/`
5. **Model metadata is embedded** in the DLL (confirmed via `strings` command shows `modelId: System-2.0.2`)

## MSBuild Integration Analysis

### CkCompile Task
- Runs `AfterTargets="ResolveProjectReferences"`
- Parameter: `IsLocalCatalogEnabled=True`
- Parameter: `PublishCatalogName=LocalFileSystemCatalog`
- Refreshes catalog cache but finds no models

### CkRestore Task
- Should run `AfterTargets="ResolveProjectReferences"`  
- Processes `construction-kits.yaml` file
- Schema validation fails on all attempted formats

## Unknowns / Questions for Meshmakers Team

1. **What is the correct `construction-kits.yaml` schema for version 3.3.22?**
   - The schema rejects all properties including `libraries`, `models`, `assemblyPath`, `packageId`
   - Error indicates "false schema" suggesting no properties are currently allowed

2. **Is System model 2.0.2 published to a catalog?**
   - Private GitHub Catalog?
   - Public GitHub Catalog?
   - Should it be consumed differently?

3. **What changed in the "refactoring ck migrations"?**
   - Was automatic NuGet package discovery intentionally removed?
   - Is there migration documentation?

4. **How should NuGet package models be registered?**
   - Should packages include build targets that auto-register?
   - Should there be a CLI tool to import models?

## Recommendations

### Short Term
1. **Contact Meshmakers** for:
   - Correct `construction-kits.yaml` format documentation
   - Confirmation of System model 2.0.2 catalog availability
   - Migration guide from pre-3.3.22 to 3.3.22

2. **Possible Workarounds** (if available):
   - Pin to pre-3.3.22 Octo packages temporarily
   - Build System model locally with `OctoPublishCkModel=true` to populate local catalog
   - Access private catalog if System model is published there

### Long Term
1. Document the new model discovery mechanism
2. Consider adding build targets to model packages for auto-registration
3. Provide CLI tool for model catalog management
4. Add clear error messages indicating which catalog was searched

## Files Changed
- `src/Persistence.IdentityCkModel/ConstructionKit/ckModel.yaml` - Updated dependency from `System-(,2.0)` to `System-2.0.2`

## Next Steps
- [ ] Get response from Meshmakers team on correct approach
- [ ] Apply recommended solution
- [ ] Test build with corrected configuration
- [ ] Document solution for future reference
