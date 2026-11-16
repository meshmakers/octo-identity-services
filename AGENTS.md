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
| `Program.cs`, `*.csproj`, `Dockerfile`, `azure-pipelines.yml`, `appsettings*.json`, `**/{Configuration,Mapping,Consumers}/**`, `src/IdentityServices.Resources/**` | `docs/architecture.md` |
| `src/Persistence.IdentityCkModel/**`, `src/IdentityServerPersistence/Services/Migrations/**`, `CkModelCompatibility.cs` | `docs/ck-model.md` |
| `**/SystemStores/Client*.cs`, `**/Services/{ClientGrants,PipelineServiceAccounts,DynamicClientRegistration}/**` | `docs/client-credentials.md` |
| `ClientMirror*.cs`, `src/IdentityServices/Services/**` | `docs/client-mirroring.md` |
| `src/IdentityServices/Logging/**`, `OctoUser*.cs`, `UserTokenRevocation.cs`, `SecondFactorEvidence.cs`, `src/IdentityServices/Controllers/Api/**` | `docs/credential-security.md` |
| `CrossTenant*.cs`, `**/{CrossTenantAudit,SourceTenantGrants,ShadowUserCleanup}/**`, `TenantProbeGuard*.cs`, `AllowedTenants*.cs`, `*IdentityResolver.cs` | `docs/cross-tenant-authentication.md` |
| `src/IdentityServices/Methods/**`, `**/Services/{SelfService,SecretManagement}/**` | `docs/identity-methods.md` |
| `src/IdentityServices/{OpenIddict,Cookies}/**`, `src/IdentityServices/Controllers/Protocol/**`, `OpenIddictConfiguration.cs`, `**/SystemStores/OpenIddict/**` | `docs/openiddict-protocol.md` |
| `src/IdentityServices/Authorization/**`, `GroupRoleResolver.cs`, `GuardedEntityMutation.cs`, `**/AdminRoleMigration/**`, `OctoRoleStore.cs`, `GroupStore.cs` | `docs/role-guards.md` |
| `DefaultConfiguration*.cs`, `**/Services/{Admin,FileRoles,ScratchTenants,RoleGrants}/**`, `ITenantSetupCompletedHandler.cs` | `docs/tenant-provisioning.md` |
| `tests/**` | `docs/testing.md` |
<!-- <<< end generated: routing -->

Background, not routed (open when the task names the topic): the concept documents `docs/CONCEPT-*.md`, the rollout
runbooks `docs/rollout-*.md` and `docs/runbook-*.md`, the reference documents `docs/authentication.md`,
`docs/persistence.md`, `docs/system-api.md`, `docs/configuration.md`, `docs/architecture-overview.md` and
`docs/README.md` (index), and the feature references `docs/login-and-providers.md`,
`docs/user-create-merge-methods.md` and `docs/identity-rest-facades.md`.

## Build & test

### Build commands

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

### Build configurations

- **Debug/Release**: Standard configurations
- **DebugL**: Local development mode that sets version to 999.0.0 and uses local NuGet sources from `../nuget`

### 🔴 `dotnet test` auf der Solution startet alle vier Testhosts gleichzeitig

`dotnet test <sln>` baut und startet die vier Testprojekte **parallel** (ein Testhost-Prozess pro Projekt).
`IdentityServices.IntegrationTests` fährt dabei seine MongoDB-Testcontainer hoch, während die drei Unit-Test-Hosts
dieselbe Maschine belegen — Container-Kontention, die es beim Einzelaufruf nicht gibt. Vor der Umstellung auf
Collection-Fixtures, als jede Testklasse ihren eigenen Container bekam (32 Container pro Lauf), war das massiv: dasselbe
Integrationsprojekt **einzeln** 4:48 mit 188/188 grün — **in der Solution** 27 min, mit sporadischem `commitTransaction
... has been aborted`, weil der Tenant-Setup in einer Mongo-Transaktion läuft und unter Last das 60-s-Default-Limit
riss.

Die Umstellung hat beide Ursachen entschärft (5 statt 32 Container, `transactionLifetimeLimitSeconds = 300`);
gemessen danach: Solution-Lauf 1:37, alle 681 Tests grün. **Der Mechanismus ist aber nicht weg** — auf
einer belasteten Maschine bleibt der parallele Solution-Lauf die anfälligste Variante. Bei einem
Abbruch aus dieser Ecke (Transaktions-Abort, Testcontainer-Timeout) also erst seriell gegenprüfen,
bevor man ihn für einen echten Testfehler hält:

```bash
dotnet test Octo.Identity.sln -c DebugL -m:1      # Projekte nacheinander
# oder Projekte einzeln:
dotnet test tests/IdentityServices.IntegrationTests/IdentityServices.IntegrationTests.csproj -c DebugL
dotnet test tests/IdentityServices.UnitTests/IdentityServices.UnitTests.csproj -c DebugL
dotnet test tests/IdentityServerPersistence.UnitTests/IdentityServerPersistence.UnitTests.csproj -c DebugL
dotnet test tests/Authentication.UnitTests/Authentication.UnitTests.csproj -c DebugL
```

Das ist eine Empfehlung zur **Ausführungsart**, keine Erlaubnis, Projekte wegzulassen: grün müssen
weiterhin alle vier sein.

## Before you commit

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

- Credentials never reach a log property, a request URL or a DTO `ToString()`; read `docs/credential-security.md`
  before you touch logging, secrets or password endpoints.
- Every change of roles, groups or role definitions goes through the role change guard: `docs/role-guards.md`.
- Integration tests share no process-wide or machine-wide state: `docs/testing.md`.

### Every attribute declares its ownership; the build enforces it

`Persistence.IdentityCkModel.csproj` sets `OctoEnforceRuntimeStateMarkers=true`: the `CkLintRuntimeStateMarkers` task of
`Meshmakers.Octo.ConstructionKit.MsBuildTasks` fails the build with `OCTO-CK001` when an attribute in
`ConstructionKit/attributes/*.yaml` declares neither `ownership` nor the deprecated `isRuntimeState` (`OCTO-CK003` for
both, `OCTO-CK004` for an unknown value). The ownership rule made the existing behaviour explicit: 151 attributes got
`ownership: SeedOwned` (a restatement - the same resolved ownership, so `octo-ckc ValidateVersion` reports "no bump
required" and System.Identity stays 2.24.0); the `TenantOwned` / `Secret` decisions of the table in `docs/ck-model.md`
and the four `isRuntimeState: true` URI lists are unchanged. Assignment overrides on types (`Client`, `Resource`,
`ApiResource`) are not linted; they still win over the definition. **Review question for every new attribute:** could an
operator or user type this value in the product? Yes → `TenantOwned` (or `Secret` for a credential); a service writes it
→ `RuntimeState`; the product ships and corrects it → `SeedOwned`.

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
