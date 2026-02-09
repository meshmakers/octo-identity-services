# Build Issue: Construction Kit Model Dependency Resolution Failure

## Summary
The build fails because the Construction Kit (CK) compiler cannot resolve the `System` model dependency, preventing compilation of the `Persistence.IdentityCkModel` project.

## Error Message
```
/src/Persistence.IdentityCkModel/ConstructionKit : error 1: 'System-(,3.0)' is not a known construction kit model. Please check if you have set dependency to the correct construction kit model.
```

## Root Cause Analysis

### What We Know
1. **System Model Package**: `Meshmakers.Octo.ConstructionKit.Models.System` version 3.3.22
   - Contains model ID: `System-2.0.2`
   - Referenced correctly in `Persistence.IdentityCkModel.csproj`
   - Package is restored successfully to `~/.nuget/packages/`

2. **Dependency Declaration**: In `src/Persistence.IdentityCkModel/ConstructionKit/ckModel.yaml`:
   ```yaml
   dependencies:
     - System-(,3.0)
   ```
   - Version range `(,3.0)` means "less than 3.0", which should match `System-2.0.2`

3. **CK Catalog is Empty**: All catalog cache files at `~/.octo/ck-catalog/cache/` contain:
   ```json
   {"version":"1.0","updatedAt":"...","models":{}}
   ```

4. **Issue Title Context**: "Build error after refactoring ck migrations"
   - Suggests a breaking change in Octo framework 3.3.x related to CK model discovery

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

## Questions for Meshmakers Team

1. **Model Discovery**: How should CK models from NuGet packages be discovered in version 3.3.x?
   - Is there a required configuration file?
   - Is there a CLI command to register models?
   - Should models be published to a GitHub-based catalog?

2. **Migration Path**: What's the upgrade path from pre-3.3 to 3.3.x?
   - Is there migration documentation for the CK refactoring?
   - Are there breaking changes that need code updates?

3. **System Model 2.0.2**: Is this model available in any public catalog?
   - Can we reference it from GitHub instead of NuGet?
   - Is there a v1.x model we should use instead?

4. **construction-kits.yaml**: What's the correct format for this file in 3.3.x?
   - Schema validation failures suggest format changes
   - No working examples found in documentation

## Impact
- **Blocking**: Complete build failure - no projects can compile
- **Scope**: Affects all projects that depend on `Persistence.IdentityCkModel`
- **Tests**: Integration tests also fail (they depend on the Identity model)

## Next Steps
1. Contact Meshmakers support/development team
2. Check for recent framework updates that might address this issue
3. Review Octo framework changelog for 3.3.x breaking changes
4. Consider temporary workaround if one exists (e.g., catalog pre-population)

## Files Investigated
- `src/Persistence.IdentityCkModel/ConstructionKit/ckModel.yaml`
- `src/Persistence.IdentityCkModel/Persistence.IdentityCkModel.csproj`
- `Directory.Build.props`
- `~/.nuget/packages/meshmakers.octo.constructionkit.msbuildtasks/3.3.*/build/`
- `~/.octo/ck-catalog/cache/`

## Environment
- .NET SDK: 10.0.102
- Octo Packages: 3.3.* (currently resolves to 3.3.22)
- Target Framework: net10.0
- OS: Linux (GitHub Actions runner)
