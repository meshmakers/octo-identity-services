# AGENTS.md

Instructions for coding agents in this repository. Detail lives in `docs/`; read the matching file before changing the
code it covers.

## What this repo is

Octo Identity Services is a .NET 10 identity and authentication service built on **OpenIddict 7.6** (migrated from
Duende IdentityServer 8.0.6; see `docs/CONCEPT-OPENIDDICT-MIGRATION.md`). It provides OAuth2/OpenID Connect
authentication with support for multiple identity providers (Google, Facebook, Microsoft, Azure Entra ID, OpenLDAP,
Microsoft AD). The wire protocol (endpoint paths, discovery, JWKS, token shape, claims) is kept Duende-compatible so all
consumers work unchanged; the remaining discovery-document differences are documented in
`docs/openiddict-discovery-diff.md`.

## Read before you change

<!-- >>> generated: routing -->
| When you change | Read first |
|---|---|
| `src/IdentityServices/ClientApp/**` | `docs/angular-clientapp.md` |
| `{Program,IdentityApi*,*KeyStore}.cs`, `*.csproj`, `Dockerfile`, `appsettings*.json`, `azure-pipelines.yml`, `**/{Configuration,Mapping,Consumers,DataProtection}/**` | `docs/architecture.md` |
| `src/Persistence.IdentityCkModel/**`, `src/IdentityServerPersistence/Services/Migrations/**`, `CkModelCompatibility.cs` | `docs/ck-model.md` |
| `**/SystemStores/*Client*.cs`, `**/Services/{ClientGrants,PipelineServiceAccounts,DynamicClientRegistration}/**`, `*ClientMirror*.cs`, `ClientsController.cs` | `docs/client-credentials.md` |
| `*ClientMirror*.cs`, `{ClientCredentialsTenantProcessor,MirrorSecretUsageTelemetry,OctoApplicationManager}.cs` | `docs/client-mirroring.md` |
| `src/IdentityServices/{Logging,TenantApi,Controllers/Api}/**`, `{OctoUser*,*Revocation*,SecondFactorEvidence,*UserCredentialChangeService}.cs` | `docs/credential-security.md` |
| `*CrossTenant*.cs`, `**/{CrossTenantAudit,SourceTenantGrants,ShadowUserCleanup}/**`, `{TenantProbeGuard*,AllowedTenants*,*IdentityResolver,*Processor}.cs` | `docs/cross-tenant-authentication.md` |
| `src/IdentityServices/Methods/**`, `**/Services/{SelfService,SecretManagement}/**`, `*DataPermission*.cs` | `docs/identity-methods.md` |
| `{IdentityMethodFacade,IdentityRestDeprecation,UsersController,ManageApiController,RoleChangeProblems,ResetUserPasswordRequestDto}.cs` | `docs/identity-rest-facades.md` |
| `src/Authentication/**`, `**/Services/Login/**`, `{TenantDiscovery*,TenantTopology*,*IdentityProvider*,*EmailDomainGroupRule*,*Channel*}.cs` | `docs/login-and-providers.md` |
| `src/IdentityServices/{OpenIddict,Cookies,Middleware,Controllers/Protocol}/**`, `**/{SystemStores/OpenIddict,DynamicAuth}/**`, `OpenIddictConfiguration.cs` | `docs/openiddict-protocol.md` |
| `**/{Authorization/RoleChange,AdminRoleMigration}/**`, `{GroupRoleResolver,GuardedEntityMutation,OctoRoleStore,*GroupStore,RolesController,GroupsController}.cs` | `docs/role-guards.md` |
| `**/Services/{Admin,FileRoles,ScratchTenants,RoleGrants}/**`, `{DefaultConfiguration*,AdminProvisioning*,PipelineServiceAccountFileRoles*}.cs` | `docs/tenant-provisioning.md` |
| `tests/**` | `docs/testing.md` |
| `User{CreateUser,Merge,DisableTwoFactor}Handler.cs`, `User{Creation,Merge,TwoFactorAdministration,Management}Service.cs`, `UserEmailUniqueness.cs` | `docs/user-create-merge-methods.md` |
<!-- <<< end generated: routing -->

Background, not path-triggered (open when the task names the topic):

- `docs/authentication.md` (large reference): sign-in attempt counting and rate limits, external provider and LDAP
  login flows, device flow, impersonation, dynamic client registration, resource indicators, authorize error page.
- `docs/system-api.md` (REST reference), `docs/persistence.md` (CK entities, stores, indexes),
  `docs/configuration.md` (environment variables), `docs/architecture-overview.md`, `docs/README.md` (index).
- `docs/external-identity-provider-setup.md` and `docs/external-identity-provider-concept.md` (provider setup),
  `docs/SINGLE-LOGOUT-IMPLEMENTATION.md`, `docs/openiddict-discovery-diff.md`.
- Decisions and history: the concepts `docs/CONCEPT-*.md` and `docs/TODO-TENANT-DISCOVERY-IMPROVEMENTS.md`; rollouts:
  `docs/rollout-*.md` and `docs/runbook-*.md`.

## Build & test

### Build commands

Locally only `-c DebugL` builds. `Directory.Build.props` has no version fallback: the commands without a
configuration and with `-c Release` stop with `OCTO0001` unless the pipeline sets the version (or you pass
`-p:OctoVersion=X.Y.Z`, or `-p:OctoNugetPrivateServer=<feed>` for the main line `0.1.*`). DebugL restores the upstream
`999.0.0` packages from `../nuget`; on a fresh workspace build the dependency chain first
(`Invoke-BuildAll -configuration DebugL`, octo-tools).

```bash
# Restore and build
dotnet restore Octo.Identity.sln
dotnet build Octo.Identity.sln

# Build with specific configuration
dotnet build Octo.Identity.sln -c Release
dotnet build Octo.Identity.sln -c DebugL  # Local development with version 999.0.0

# Run the identity service
dotnet run --project src/IdentityServices/IdentityServices.csproj

# Run tests
dotnet test Octo.Identity.sln -c Release
```

### Solution test run

`dotnet test` on the solution starts the four test hosts in parallel. After a transaction abort or a Testcontainers
timeout, run the projects one after the other (`-m:1`) before you treat it as a test failure; all four projects must
be green either way. Detail: `docs/testing.md`.

## Before you commit

1. `dotnet test Octo.Identity.sln -c DebugL`: all four test projects green, unit and integration (the integration
   tests need Docker for the MongoDB Testcontainer). Without Docker say so and wait for the developer's go; never run
   only the unit tests silently, never `--no-verify`. The rule in full follows below.
2. Touched `src/IdentityServices/ClientApp/`: `npm run lint` in that folder (`docs/angular-clientapp.md`).
3. Update the doc in `docs/` that covers the code you changed, in the same commit.
4. Touched `AGENTS.md` or a file in `docs/`: `Test-OctoAgentDocs -Fix` (octo-tools) reports 0 errors. It rewrites the
   generated routing table, so run it before you stage.

### Pre-Commit & Pre-Push Rule (CRITICAL — NO EXCEPTIONS)

**IMMER vor JEDEM `git commit` UND vor JEDEM `git push` lokal die volle Test-Suite ausführen:**

```bash
dotnet test Octo.Identity.sln -c DebugL
```

🔴 **`-c Release` funktioniert lokal auf `test/0.2-dev` nicht — das ist kein kaputter Branch.**
Die Paket-Lane kommt aus der Pipeline: `azure-pipelines.yml` reicht `octoCoreLibVersion` als
`octoCoreLibVersionOverride` ans CI-Template, und nur dort steht die 0.2-Lane. Lokal greift der
Fallback in `Directory.Build.props` — `0.1.*` mit privatem Feed, sonst gar keiner (seit der Umstellung
gibt es keinen Release-Fallback mehr; ohne Version bricht der Build mit `OCTO0001` ab) —, also nie
die 0.2-Lane, und ohne konfigurierten `OctoNugetPrivateServer` sind `0.2.*`-Pakete
ohnehin nicht erreichbar. Der Build bricht dann mit einer Wand aus `CS0246` auf Typen ab, die es nur
in der 0.2-Lane gibt (z.B. `DataPermissionDto` aus `Communication.Contracts` im
`DataPermissionsController`). Das sieht nach einem kaputten Merge aus, ist aber die Lane.

`DebugL` löst gegen `999.0.0` aus `../nuget` auf und ist deshalb die einzige lokal funktionierende
Konfiguration auf diesem Branch — so wie in allen anderen Repos auch. Die Release-Absicherung leistet
die CI, die die Lane injiziert.

- Gilt für **jeden** Commit und **jeden** Push — auch für vermeintlich triviale Änderungen, Doc-Updates, Renames oder
  "nur einen Index hinzufügen".
- Gilt für Unit- **und** Integration-Tests. Wenn Testcontainers/Docker lokal nicht verfügbar sind, das **explizit** dem
  User melden und auf Freigabe warten — **nicht** stillschweigend nur Unit-Tests laufen lassen.
- **Niemals** `--no-verify`, `git commit -n` oder Hook-Skips verwenden, um diese Regel zu umgehen.
- **Niemals** auf "die CI fängt es schon ab" verlassen — die CI ist die letzte, nicht die erste Verteidigungslinie.
- Bei rotem Test: erst fixen, dann committen. Niemals "fix in einem nachfolgenden Commit" versprechen.

Build #35223 (PR #95) ist genau wegen Verstoß gegen diese Regel fehlgeschlagen. Wenn lokale Validierung übersprungen
wird, sind alle anderen Pre-Commit-Regeln (Lint etc.) ebenfalls hinfällig.

## Rules

- **This repository is public.** No work item ids, internal hostnames, customer or tenant names, or secrets in code
  comments, docs or test names.
- **Credentials never reach a log property, a request URL or a DTO `ToString()`.** Read
  `docs/credential-security.md` before you touch logging, secrets or password endpoints.
- **Every administration endpoint carries a policy of `IdentityApiAuthorizationPolicies`** (scope and tenant role;
  secret writes need `SecretManagement`). `IdentityApiAuthorizationPolicyTests` fails for a controller action without
  one: `docs/architecture.md`, "API Versioning and Route Prefix".
- **Every change of roles, groups or role definitions goes through the role change guard** (no escalation, the last
  administrator stays): `docs/role-guards.md`.
- **Tokens are bound to one tenant.** Grants are stored per tenant, every access token carries `tenant_id` and
  `tenant_gen`, and a grant or subject token of an earlier tenant with the same id is refused:
  `docs/openiddict-protocol.md`.
- **Ancestry is not authority.** A cross-tenant token exchange issues exactly the roles the shadow user resolves in
  the target tenant, and every cross-tenant entry point checks the second factor:
  `docs/cross-tenant-authentication.md`.
- **A client-credentials token names its tenant, and an ambiguous tenant binding is refused**, never guessed:
  `docs/client-mirroring.md`.
- **A user is created only through `User.CreateUser` and merged only through `User.Merge`**:
  `docs/user-create-merge-methods.md`. The password and role methods: `docs/identity-methods.md`.
- **The wire protocol stays Duende-compatible** (endpoint paths, discovery, token shape, claims); the golden-file
  tests pin it: `docs/openiddict-protocol.md`.
- **Every CK attribute declares its `ownership`** (`OCTO-CK001` fails the build), and a change of System.Identity
  follows the version and migration rules: `docs/ck-model.md`.
- **Integration tests share no process-wide or machine-wide state**: `docs/testing.md`.

### Documentation Guidelines

**CRITICAL REQUIREMENT:** Documentation MUST be updated after EVERY change. This is mandatory, not optional.

#### Language Requirement

All documentation MUST be written in **English**. This includes:
- README.md files
- Concept documents in `docs/`
- Code comments
- API documentation
- Architecture documents
- AGENTS.md files

#### Mandatory Documentation Updates

After making ANY code changes, you MUST update the relevant documentation:

1. **For Bug Fixes**:
   - Document the fix in relevant architecture docs if it clarifies behavior
   - Update troubleshooting sections if applicable

2. **For New Features**:
   - Update `docs/` with new feature documentation
   - Add API endpoint documentation for new endpoints
   - Update architecture documents if new patterns are introduced
   - Update this `AGENTS.md` (or the routed `docs/` file) if project structure changes

3. **For Refactoring**:
   - Update architecture documents to reflect new structure
   - Update code flow diagrams if applicable

4. **For Configuration Changes**:
   - Update `docs/configuration.md` with new options
   - Update environment variable documentation

#### Documentation Files

| File | When to Update |
|------|----------------|
| `docs/README.md` | Project overview changes |
| `docs/architecture-overview.md` | Structural changes |
| `docs/authentication.md` | Auth flow changes |
| `docs/persistence.md` | Data layer changes |
| `docs/system-api.md` | API endpoint changes |
| `docs/configuration.md` | Config option changes |
| `AGENTS.md` | Project structure changes |
