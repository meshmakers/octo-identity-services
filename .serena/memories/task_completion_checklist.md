# Task Completion Checklist

This checklist should be followed when completing development tasks in the Octo Identity Services project.

## Before Starting Any Task

- [ ] Ensure you understand the requirements
- [ ] Check if Construction Kit models need to be modified
- [ ] Identify which projects will be affected
- [ ] Review related code and existing patterns

## During Development

### Code Quality
- [ ] Follow naming conventions (Rt*, I*, *Dto, *Service, *Store, *Consumer)
- [ ] Respect the nullable reference types (enabled)
- [ ] Use implicit usings (enabled)
- [ ] No warnings (TreatWarningsAsErrors is true)
- [ ] Follow existing architectural patterns

### Construction Kit Changes
If modifying CK models:
- [ ] Edit YAML files in `src/Persistence.IdentityCkModel/ConstructionKit/types/`
- [ ] Never manually edit generated `Rt*` classes
- [ ] Rebuild CK project to regenerate code
- [ ] Verify generated classes in `Generated/` folder

### API Changes
If adding/modifying API endpoints:
- [ ] Use correct route: `[Route(IdentityServiceConstants.ApiPathPrefix)]`
- [ ] Apply appropriate authorization policy
- [ ] Inherit from `ControllerBase`
- [ ] Use proper HTTP verbs
- [ ] Return appropriate status codes
- [ ] Document any breaking changes

### Authentication Provider Changes
If adding/modifying auth providers:
- [ ] Implement in `src/Authentication/Providers/`
- [ ] Add builder extension in `DynamicAuthBuilderExtensions`
- [ ] Register in `Program.cs`
- [ ] Test with multiple tenants

### Store Implementation Changes
If adding/modifying stores:
- [ ] Implement IdentityServer store interface
- [ ] Use MongoDB correctly
- [ ] Register in DI container
- [ ] Handle multi-tenancy correctly

## After Code Changes

### Build
- [ ] Clean build succeeds: `dotnet clean && dotnet build Octo.Identity.sln`
- [ ] Release build succeeds: `dotnet build Octo.Identity.sln --configuration Release`
- [ ] No build warnings or errors

### Testing
- [ ] All existing tests pass: `dotnet test --filter "FullyQualifiedName!~SystemTests"`
- [ ] Add new tests for new functionality
- [ ] Test multi-tenant scenarios if applicable
- [ ] Test authentication flows if applicable

### Code Review Checklist
- [ ] Code follows project conventions
- [ ] No hardcoded values (use configuration)
- [ ] Proper error handling
- [ ] Logging added where appropriate
- [ ] Security considerations addressed
- [ ] No sensitive data in logs
- [ ] HTTPS required in production configurations

## Before Committing

### Local Verification
- [ ] Build succeeds on your machine
- [ ] Tests pass locally
- [ ] Application runs without errors
- [ ] MongoDB connection works
- [ ] Configuration is correct

### Git Workflow
- [ ] Review all changed files
- [ ] Remove any debug code or console logs
- [ ] Commit message follows convention: `AB#<ticket>: <type>: <message>`
- [ ] Changes are on the correct branch

### Commit Message Format
```
AB#<ticket-number>: <type>: <description>

Types:
- New: New feature
- Fix: Bug fix
- Update: Enhancement to existing feature
- Refactor: Code refactoring
- Docs: Documentation changes
- Test: Test additions/modifications
```

## After Committing

- [ ] Push to remote branch
- [ ] Verify CI/CD pipeline passes (if applicable)
- [ ] Create pull request with detailed description
- [ ] Link related tickets/issues
- [ ] Request code review

## Documentation Updates

If applicable:
- [ ] Update CLAUDE.md if architecture changes
- [ ] Update API documentation
- [ ] Update README if deployment changes
- [ ] Document breaking changes
- [ ] Update configuration examples

## Deployment Considerations

### Configuration Check
- [ ] Environment variables documented
- [ ] Default values are sensible
- [ ] Secrets are not committed
- [ ] Connection strings use configuration
- [ ] Authority URL is configurable

### Docker
If Docker changes:
- [ ] Dockerfile builds successfully
- [ ] Build args are documented
- [ ] Image runs correctly
- [ ] Environment variables are passed correctly

### Database
If database changes:
- [ ] Migration added if schema changes
- [ ] Schema version updated
- [ ] Migration tested locally
- [ ] Backward compatibility considered

## Special Considerations

### Multi-Tenancy
If changes affect multi-tenancy:
- [ ] Tenant context flows correctly
- [ ] Tenant isolation is maintained
- [ ] Route constraints work correctly
- [ ] Configuration is tenant-aware

### Authentication
If changes affect authentication:
- [ ] OAuth2/OIDC flows work correctly
- [ ] JWT tokens are validated
- [ ] Authorization policies are correct
- [ ] Provider registration works
- [ ] Multi-provider scenarios tested

### Performance
- [ ] No N+1 query issues
- [ ] Proper indexes on MongoDB collections
- [ ] Caching used where appropriate
- [ ] No memory leaks

### Security
- [ ] Input validation implemented
- [ ] SQL injection prevented (N/A for MongoDB but check for NoSQL injection)
- [ ] XSS prevented
- [ ] CSRF protection in place
- [ ] Authentication required for protected endpoints
- [ ] Authorization enforced correctly
- [ ] Secrets not in source code
- [ ] HTTPS enforced in production

## Final Checklist

- [ ] All items above completed
- [ ] Code reviewed by team member
- [ ] Tests pass in CI/CD
- [ ] Documentation updated
- [ ] Ready for deployment

## Quick Command Reference

```bash
# Build
dotnet build Octo.Identity.sln --configuration Release

# Test
dotnet test --filter "FullyQualifiedName!~SystemTests"

# Run
dotnet run --project src/IdentityServices/IdentityServices.csproj

# Git commit
git add .
git commit -m "AB#<ticket>: <type>: <message>"
git push origin <branch>
```
