# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Octo Identity Services is a .NET 10 identity and authentication service built on **OpenIddict 7.6** (migrated from Duende IdentityServer 8.0.6 — Epic AB#4989, work items AB#4990–AB#4996; see `docs/CONCEPT-OPENIDDICT-MIGRATION.md`). It provides OAuth2/OpenID Connect authentication with support for multiple identity providers (Google, Facebook, Microsoft, Azure Entra ID, OpenLDAP, Microsoft AD). The wire protocol (endpoint paths, discovery, JWKS, token shape, claims) is kept Duende-compatible so all consumers work unchanged; the remaining discovery-document differences are documented in `docs/openiddict-discovery-diff.md`.

## Build Commands

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

## Pre-Commit & Pre-Push Rule (CRITICAL — NO EXCEPTIONS)

**IMMER vor JEDEM `git commit` UND vor JEDEM `git push` lokal die volle Test-Suite ausführen:**

```bash
dotnet test Octo.Identity.sln -c DebugL
```

🔴 **`-c Release` funktioniert lokal auf `test/0.2-dev` nicht — das ist kein kaputter Branch.**
Die Paket-Lane kommt aus der Pipeline: `azure-pipelines.yml` reicht `octoCoreLibVersion` als
`octoCoreLibVersionOverride` ans CI-Template, und nur dort steht die 0.2-Lane. Lokal greift der
Fallback in `Directory.Build.props` — `0.1.*` mit privatem Feed, sonst gar keiner (seit AB#6297
gibt es keinen Release-Fallback mehr; ohne Version bricht der Build mit `OCTO0001` ab) —, also nie
die 0.2-Lane, und ohne konfigurierten `OctoNugetPrivateServer` sind `0.2.*`-Pakete
ohnehin nicht erreichbar. Der Build bricht dann mit einer Wand aus `CS0246` auf Typen ab, die es nur
in der 0.2-Lane gibt (z.B. `DataPermissionDto` aus `Communication.Contracts` im
`DataPermissionsController`). Das sieht nach einem kaputten Merge aus, ist aber die Lane.

`DebugL` löst gegen `999.0.0` aus `../nuget` auf und ist deshalb die einzige lokal funktionierende
Konfiguration auf diesem Branch — so wie in allen anderen Repos auch. Die Release-Absicherung leistet
die CI, die die Lane injiziert.

- Gilt für **jeden** Commit und **jeden** Push — auch für vermeintlich triviale Änderungen, Doc-Updates, Renames oder "nur einen Index hinzufügen".
- Gilt für Unit- **und** Integration-Tests. Wenn Testcontainers/Docker lokal nicht verfügbar sind, das **explizit** dem User melden und auf Freigabe warten — **nicht** stillschweigend nur Unit-Tests laufen lassen.
- **Niemals** `--no-verify`, `git commit -n` oder Hook-Skips verwenden, um diese Regel zu umgehen.
- **Niemals** auf "die CI fängt es schon ab" verlassen — die CI ist die letzte, nicht die erste Verteidigungslinie.
- Bei rotem Test: erst fixen, dann committen. Niemals "fix in einem nachfolgenden Commit" versprechen.

Build #35223 (PR #95) ist genau wegen Verstoß gegen diese Regel fehlgeschlagen. Wenn lokale Validierung übersprungen wird, sind alle anderen Pre-Commit-Regeln (Lint etc.) ebenfalls hinfällig.

### 🔴 `dotnet test` auf der Solution startet alle vier Testhosts gleichzeitig

`dotnet test <sln>` baut und startet die vier Testprojekte **parallel** (ein Testhost-Prozess pro
Projekt). `IdentityServices.IntegrationTests` fährt dabei seine MongoDB-Testcontainer hoch, während die
drei Unit-Test-Hosts dieselbe Maschine belegen — Container-Kontention, die es beim Einzelaufruf nicht
gibt. Vor AB#5160, als jede Testklasse ihren eigenen Container bekam (32 Container pro Lauf), war das
massiv: dasselbe Integrationsprojekt **einzeln** 4:48 mit 188/188 grün — **in der Solution** 27 min, mit
sporadischem `commitTransaction ... has been aborted`, weil der Tenant-Setup in einer Mongo-Transaktion
läuft und unter Last das 60-s-Default-Limit riss.

AB#5160 hat beide Ursachen entschärft (5 statt 32 Container, `transactionLifetimeLimitSeconds = 300`);
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

## Integration-Test-Fixtures: fünf Collections, fünf Container (AB#5160)

`IdentityServices.IntegrationTests` teilt seine MongoDB-Testcontainer über **Collection**-Fixtures, nicht
mehr über `IClassFixture` (das erzeugt eine Fixture-Instanz **pro Testklasse** — vorher 32 Container pro
Lauf, davon ~50 % der CI-Testzeit reines Setup). Die Definitionen liegen in `tests/…/Collections/`:

| Collection | Fixture | Wer |
| --- | --- | --- |
| `IdentityPersistence` | `IdentityServicesFixture` | 14 Persistence-Klassen |
| `DataProtectionKeySeed` | `IdentityServicesFixture` | nur `DataProtectionKeySeedIntegrationTests` |
| `DataProtectionKeyEncryption` | `IdentityServicesFixture` | nur `DataProtectionKeyEncryptionIntegrationTests` (AB#5530, leert den Key-Store je Fact) |
| `VirginBootstrap` | `VirginBootstrapFixture` | nur `VirginSystemDatabaseBootstrapIntegrationTests` |
| `ZWebFactory` | `CustomWebApplicationFactory` | 15 HTTP-Klassen (Basis `IntegrationTestBase`) |
| `ZSetupApi` | `CustomWebApplicationFactory` | nur `SetupApiTests` |

**Regel für neue Testklassen:** `[Collection(IdentityPersistenceCollection.Name)]` bzw.
`[Collection(WebFactoryCollection.Name)]` setzen und alle Entitäten mit GUID-Suffix anlegen
(`$"foo-{Guid.NewGuid():N}"`) — dann ist der akkumulierte Zustand der Geschwisterklassen unsichtbar.
Wer auf den Zustand der **ganzen** Datenbank angewiesen ist (leere Collection erwartet, alles löscht,
System-Tenant droppt), bekommt eine **eigene** Collection — so wie die drei Einzelgänger oben. Ein
Container mehr ist billiger als ein flakiger oder vakuum-grüner Test; niemals stattdessen die Assertion
aufweichen. Vorbild: `octo-asset-repo-services` (7 Collections) / `octo-communication-controller-services`
(AB#4963).

### 🔴 Collections laufen PARALLEL — prozessweiter Zustand ist die Fehlerklasse (AB#5117, AB#5440)

`xunit.runner.json` hält `parallelizeTestCollections: true` mit `maxParallelThreads: 4`. (Diese Doku
behauptete bis AB#5440 `false`; das war seit AB#5117 falsch.) Nur **ein** MongoDB-Container lebt
gleichzeitig — die Isolationsgrenze ist seit AB#5117 die **Datenbank**, nicht der Server —, aber bis zu
vier Collections bauen gleichzeitig Hosts hoch und ab.

Damit ist **jeder prozessweite Zustand ein Race**, und das ist die einzige Fehlerklasse, die diese
Suite wirklich flakig macht. Bisher dreimal getreten:

| Geteilter Zustand | Symptom | Behandlung |
| --- | --- | --- |
| Test-Tenant-ID `test-tenant` (⇒ DB-Name, serverweiter Namensraum) | Fixtures überschreiben sich | GUID-Suffix (AB#5117) |
| System-Tenant-ID `octosystem` ⇒ statisches `DefaultConfigurationCreatorServiceBase.TenantsInHandling` | Fixtures überspringen still den CK-Import, dann `CkCacheException` | GUID-Suffix, Präfix gekürzt (AB#5117) |
| **statisches `NLog.LogManager.Configuration`** | `ConfigurationException: LogManager configuration not found` aus `HostedInitializer.StartAsync`, wandernde Testmenge | Aufrufer tolerant (AB#5440) |

**Machine-wide state counts too (AB#5880).** In the Development environment `OpenIddictConfiguration`
calls `AddDevelopmentSigningCertificate()`, which publishes **every** certificate with subject
`CN=OpenIddict Server Signing Certificate` from the current user's X509 store — expired ones and
duplicates created by concurrently starting hosts included. On a long-lived CI agent that store
persists across builds, so the JWKS depended on the agent (`TokenShapeGoldenTests.JwksDocument_*` saw
two keys on `azure-devops-agents-ci-1` only). `CustomWebApplicationFactory` therefore replaces the
signing and encryption credentials with one in-memory certificate (`Infrastructure/TestSigningCertificate.cs`),
and the JWKS test asserts that this is the only published key. Never let a test host read key material
from the user/machine store.

**Linux agents: inotify instance limit (AB#8019).** Every in-process host (each `CustomWebApplicationFactory` and each
`WithWebHostBuilder` derivative) used to load `appsettings*.json` with reload-on-change, i.e. one file watcher per file and host.
On the Linux CI agents the inotify instance limit (128) was reached across the suite and unrelated tests failed at host start
(`The configured user limit (128) on the number of inotify instances has been reached`). The static constructor of
`CustomWebApplicationFactory` therefore sets `DOTNET_hostBuilder__reloadConfigOnChange=false` for the test process (tests never
change configuration files at run time); `TestHostConfigurationTests` pins it. Dispose derived factories a test creates
(`WithWebHostBuilder`) at the end of the test (`GroupMethodTestBase`, `ClientMirrorReconciliationTests`, `UserRoleMethodTests`,
`UserChangePasswordMethodTests`); otherwise they live until the class fixture ends.

**Test host memory: every in-process host must be collectable (AB#8337).** ASP.NET Core's `RateLimitingMiddleware`
(`app.UseRateLimiter()`, policies `tenant-discovery` and `dcr`) never disposes its `DefaultPartitionedRateLimiter`, whose 100 ms
heartbeat timer is a GC root for the whole request pipeline and the host's services, and whose captured `ExecutionContext` holds
xUnit's `TestContext` and with it the class fixtures. In production that is one pipeline per process; the suite builds ~300 hosts
and none was ever collected: the live heap after a full GC grew monotonically to **8.6 GB** (dump: 295 live meter providers,
3.6 GB OpenTelemetry `MetricPoint[]` alone), which hit the 9 GiB GC heap hard limit of a 12 Gi CI agent (OutOfMemoryException in
random tests, builds 65745, 65817). `CustomWebApplicationFactory` therefore registers `Infrastructure/RateLimiterReleaser` (hosted
service, last registration, inherited by every `WithWebHostBuilder` derivative): when the host stops it finds the middleware's
limiters by reflection over the built pipeline and disposes them. Measured locally (Mac mini, `GC.GetTotalMemory(true)` every 15 s,
engine-mongodb main incl. AB#8281): live heap peak **8.6 GB → 3.3-3.5 GB**, suite duration unchanged (~9:40-10:00 min).
`RateLimiterReleaserTests` fails when a framework update changes the internal shape the walk relies on — fix the walk then, never
delete the test. Rules: a `StopAsync` of a test-only hosted service must never throw (it aborts the factory's dispose and leaks the
host); a new background timer or long-running loop in startup code needs a dispose path, or every test host keeps it.
The shared MongoDB container still grows to ~10 GiB per run (outside the test process; a `--wiredTigerCacheSizeGB 1` cap did not
change that and a 4 GiB container limit got mongod OOM-killed), which is tracked with the CI agent memory work (AB#8336).

**A stale DebugL feed starves the suite on driver threads (AB#8424).** Every repository client of the runtime engine is a
MongoDB driver cluster of its own (heartbeat, RTT monitor and pool maintenance thread each). Since AB#8281
(engine-mongodb #229, 2026-11-05) a disposed host closes all of them; a `Meshmakers.Octo.Runtime.Engine.MongoDb` 999.0.0
in `../nuget` built **before** that keeps every cluster of every host the suite ever built. Measured on a Mac (16 cores,
2026-11-07, same identity commit): with the stale feed the test host passed 3,100 threads after 9.5 min with ~500 of ~1,000
tests done and throughput collapsing (thread stacks: ~390 × `ServerMonitor`, ~390 × `RoundTripTimeMonitor`, ~390 ×
`MaintenanceHelper`; dump: 497 clusters in `ClusterRegistry`, rooted only by the registry); with the library chain rebuilt
from main the same suite stays bounded (numbers in AB#8424). CI is not affected (its feed is built from main). Symptoms of a
stale feed: thousands of threads at ~50 % CPU, transaction aborts, server-selection timeouts and canceled operations in
unrelated classes, a run that never ends. `Infrastructure/TestHostMongoClientReleaseTests` pins the release on the server
(`$currentOp` by the host's system database name) and turns red within seconds against such a feed — then rebuild the chain
(`Invoke-BuildRange` from `octo-construction-kit-engine-mongodb`, or the whole DebugL chain) before you hunt for test defects.

Der NLog-Fall ist der einzige, den man **nicht** per-Fixture eindeutig machen kann: `Program.cs` lädt
die globale Konfiguration am Entry-Point und räumt sie im `finally` mit `LogManager.Shutdown()` wieder
ab (dort gegen den Segfault beim Prozessende auf Linux). Unter `WebApplicationFactory<Program>` läuft
der Entry-Point pro Factory-Instanz und `app.Run()` wird kurzgeschlossen — das `finally` feuert also
direkt nach dem Host-Build, während eine andere Factory die Konfiguration gerade liest. Deshalb fängt
`DefaultConfigurationCreatorService.InitializeAsync` die `ConfigurationException` und warnt nur;
`DiagnosticsService` selbst **wirft weiter**, weil sein anderer Aufrufer der operator-sichtbare
`DiagnosticsController` ist, wo ein stiller No-op der schlimmere Fehler wäre.

**Regel für neue Tests und neuen Startup-Code:** bevor du etwas in einen `static` legst oder aus einem
`static` liest, das ein Host beim Start oder beim Dispose anfasst — annehmen, dass vier Hosts es
gleichzeitig tun. Ein wandernder Satz fehlgeschlagener Tests über mehrere Retry-Versuche ist die
Signatur dieser Klasse, nie ein Testdefekt.

## Build Configurations

- **Debug/Release**: Standard configurations
- **DebugL**: Local development mode that sets version to 999.0.0 and uses local NuGet sources from `../nuget`

## Architecture

### Project Structure

- **IdentityServices** (`src/IdentityServices/`): Main ASP.NET web application and entry point. Contains the OpenIddict protocol configuration (`Configuration/OpenIddictConfiguration.cs`), the passthrough protocol controllers (`Controllers/Protocol/`), the OpenIddict integration layer (`OpenIddict/`), plus controllers for account management, consent flows, device authorization, and the System API (v1). Entity ↔ DTO mapping is explicit code in `Mapping/` (no mapping library since AB#6506; see `docs/persistence.md` § DTO Mapping).

- **Authentication** (`src/Authentication/`): Razor class library with authentication schemes and handlers. Implements dynamic authentication for multiple providers:
  - OAuth providers: Google, Facebook, Microsoft, Azure Entra ID
  - LDAP providers: OpenLDAP, Microsoft AD

- **IdentityServerPersistence** (`src/IdentityServerPersistence/`): Data persistence layer. Contains the Octo-native stores (ClientStore, ResourceStore, IdentityProviderStore, GroupStore, …) and the custom OpenIddict stores in `SystemStores/OpenIddict/` (application/scope/authorization/token stores over the existing CK entities). Uses Octo Runtime Engine with MongoDB.

- **Persistence.IdentityCkModel** (`src/Persistence.IdentityCkModel/`): Construction Kit model definitions (YAML files in `ConstructionKit/`) for identity entities. Uses Octo source generation to create runtime types.

- **IdentityServices.Resources** (`src/IdentityServices.Resources/`): Localized string resources (resx files).

### Key Dependencies

This service depends on Octo framework packages (versioned via `$(OctoVersion)` in Directory.Build.props):
- `Meshmakers.Octo.Runtime.Engine.MongoDb`: MongoDB persistence
- `Meshmakers.Octo.Services.Infrastructure`: Base service infrastructure
- `Meshmakers.Octo.ConstructionKit.SourceGeneration`: Code generation from CK models

### Construction Kit (CK) Model

The `Persistence.IdentityCkModel` project uses YAML-based model definitions that are transformed into C# code at build time. Model files are in `src/Persistence.IdentityCkModel/ConstructionKit/`. The model ID is `System.Identity-3.0.0` (ckLanguage 2, first major of the 3.x line, AB#8053) with dependency on `System-[2.5,3.0)`. Generated types live in namespace `Persistence.IdentityCkModel.Generated.System.Identity.v3` (the suffix is the **major** of the model: 2.x was `.v2`, the registration is `AddCkModelSystemIdentityV3()`).

### OpenIddict Protocol Stack (Epic AB#4989)

The OAuth2/OIDC server is **OpenIddict 7.6.0**, configured in
`src/IdentityServices/Configuration/OpenIddictConfiguration.cs`:

- **Endpoint URIs are pinned to the previous Duende paths** (`/connect/authorize`, `/connect/token`,
  `/connect/endsession`, `/connect/deviceauthorization`, `/connect/deviceverification`,
  `/connect/par`, userinfo, introspection, revocation) and JWKS stays at
  `/.well-known/openid-configuration/jwks` — no consumer needs reconfiguration. Remaining discovery
  differences: `docs/openiddict-discovery-diff.md`.
- **Flows:** authorization code + PKCE, `client_credentials`, refresh token, device flow (RFC 8628),
  and RFC 8693 token exchange (now a first-class OpenIddict flow).
- **`DisableAccessTokenEncryption`** keeps access tokens as plain signed JWTs (Duende-compatible).
- **`DisableEntityCaching` is CRITICAL:** the stores are per-tenant; OpenIddict's process-wide entity
  cache would leak entities across tenants. Never re-enable it.
- **Signing:** the same static PKCS#12 certificate as before (`KeyFilePath`/`KeyFilePassword`) →
  the JWKS is unchanged and outstanding access tokens stayed valid across the cutover. The signing
  cert doubles as the encryption credential for OpenIddict-internal token payloads.

**Custom OpenIddict stores** (`src/IdentityServerPersistence/SystemStores/OpenIddict/`) project the
existing CK entities — no data migration:

- `OpenIddictApplicationStore`: read-only projection of `RtClient` (application id = `client_id`;
  honors the enabled flag and the DCR TTL gate).
- `ClientPermissionsMapper`: pure function mapping `AllowedGrantTypes`/scopes/flags to OpenIddict
  permissions; unit-tested against all seed client shapes.
- `OpenIddictScopeStore`: projects `RtApiScope` + `RtIdentityResource` as requestable scopes;
  scope→audience resolution via `RtApiResource`.
- `OpenIddictAuthorizationStore` / `OpenIddictTokenStore`: over the new **per-tenant** CK types
  `RtOAuthAuthorization` / `RtOAuthToken` (System.Identity-2.12.0, migration 21→22).

**Client secrets:** `OctoApplicationManager` + `OctoSecretHasher` (`src/IdentityServices/OpenIddict/`)
validate client secrets against the stored Duende hash format (Base64 SHA-256/512) — no secret
rotation was needed at cutover.

**Principals are built by passthrough controllers** in `src/IdentityServices/Controllers/Protocol/`:

- `TokenEndpointController`: `client_credentials` (stamps effective client roles via
  `IClientRoleStore`), RFC 8693 token exchange (delegates to `TenantExchangeProcessor`), and
  code/refresh/device redemption (re-validates the user and re-resolves roles on every redemption).
- `AuthorizeController`: cookie authentication and tenant-scoped login/consent redirects (replaces
  Duende's UserInteraction plus the deleted `TenantLoginRedirectMiddleware`).
- `EndSessionController`: logout; `logoutId` is a self-contained data-protected payload;
  `/connect/endsession/callback` renders front-channel logout iframes for all registered
  front-channel clients.
- `DeviceVerificationController` at `/connect/deviceverification`: OpenIddict end-user verification
  endpoint; the Angular device page posts form-encoded to it (`DeviceApiController` now only holds
  the DTOs).

**Resource indicators (RFC 8707, AB#5193):** the `resource` parameter is validated against the
requesting tenant's API resources, not against OpenIddict's static `RegisterResources(...)`
allow-list — that list has no per-tenant form and was never filled, so **every** indicator was
rejected with `invalid_target` and no interactive MCP client could log in (Duende validated against
the API resource store). `OctoResourceValidationHandlers` (`IdentityServices/OpenIddict/`) replaces
all three built-in `ValidateResources` handlers (authorize, PAR, token/refresh) and resolves through
`IOpenIddictResourceStore<RtApiResource>` → `OpenIddictResourceStore`
(`IdentityServerPersistence/SystemStores/OpenIddict/`) — the same store shape OpenIddict 8.x
introduces upstream, so the upgrade is a `ReplaceResourceStore<...>()` plus deleting the handlers.
Accepted: statically registered, or an **enabled** `RtApiResource` of that tenant carrying at least
one **requested** scope (a request without `scope` — the refresh renewal — is judged on registration
alone). A trailing slash is insignificant (`ResourceIdentifiers`); nothing else is normalized.
🔴 The companion `ValidateResourcePermissions` handlers (ID2192) are removed too — they look for a
per-client `rsrc:{resource}` permission that `RtClient` cannot express, so they could only ever
reject; removed one by one rather than via `IgnoreResourcePermissions()`. The indicator does **not**
shape the token (audiences stay scope-derived); if that ever changes, the per-client allow-list
becomes load-bearing again. No cache, no invalidation event — entity caching is off anyway. See
`docs/CONCEPT-RESOURCE-INDICATORS.md`.

**Claims parity layer** (`src/IdentityServices/OpenIddict/`):

- `OctoTokenClaimsService`: stamps `tenant_id`, `allowed_tenants`, `home_tenant_id`, roles, and
  `aud` (replaces `UserProfileService`).
- `OctoClaimsDestinations`: claim→token mapping; profile claims are NOT embedded in tokens —
  userinfo serves them.
- `OctoAccessTokenShapeHandler`: enforces the Duende-compatible wire format — `scope` as one claim
  per value (platform-wide `RequireClaim(scope, …)` policies compare full values), **no `sub` on
  `client_credentials` tokens** (`TenantAuthorizationMiddleware` identifies service tokens by its
  absence), no `oi_*` claims, `nbf` present, no `azp` on id tokens; access tokens get no DB entry.

**Interaction facade** `IOctoInteractionService` (`src/IdentityServices/OpenIddict/Interaction/`):
consumed by `AuthApiController`/`ConsentApiController`/`GrantsApiController`. Error/logout/one-time
consent round-trip state travels as self-contained data-protected payloads (`errorId`, `logoutId`,
`octo_consent` query parameter) — no server-side message store, multi-pod safe. Remembered consent
is a permanent `RtOAuthAuthorization`; the grants page lists permanent authorizations plus clients
with live refresh tokens.

**Audit:** `IIdentityAuditService` persists failure events to the runtime event log (replaces
Duende's `IEventService`/`OctoEventSink`; success events are log-only — behavior unchanged).

**Regression gate:** golden baseline tests in
`tests/IdentityServices.IntegrationTests/Api/Protocol/TokenShapeGoldenTests.cs` + `GoldenFiles/` —
token shapes were recorded from Duende and are verified **byte-identical** against OpenIddict
(all 5 green). Any change to token shape must keep these tests green or consciously re-record.

**Behavioral differences vs. Duende** (accepted): `client_credentials` WITHOUT a `scope` parameter
now yields no scopes (Duende granted all allowed scopes); token responses may report `expires_in`
as remaining seconds; introspection now authenticates clients (Duende's ApiSecrets-based resource
introspection is not wired — it was unused).

### Cross-Tenant Authentication

The service supports hierarchical cross-tenant authentication where parent-tenant users can log in to child tenants:

- **`RtOctoTenantIdentityProvider`**: CK type linking a child tenant to a parent tenant for auth delegation
- **`RtExternalTenantUserMapping`**: CK type mapping a parent-tenant user to roles in the child tenant
- **`CrossTenantAuthenticationService`**: Walks the tenant hierarchy to validate credentials against parent tenant databases
- **`ExternalTenantUserMappingStore`**: Persistence for cross-tenant user role mappings. A mapping is unique per (`SourceTenantId`, `SourceUserId`) in a tenant, but the database does not enforce it (no unique index on runtime entities). `FindBySourceUserAsync` (login, `IsExplicitlyProvisionedAsync`, token exchange) therefore never throws on duplicates: it returns the oldest mapping (smallest `RtId`) and logs a WARN naming all ids (`ExternalTenantUserMappingLookup`, AB#6975). The store is scoped and holds a `DuplicateWarningGate`: the several lookups of one login or exchange log the WARN once per duplicate set (repeats at Debug). The effective roles (`GroupRoleResolver`, via `FindBySourceUserNamesAsync`) are the union over all matching mappings, not only the oldest. Both create paths (`POST adminProvisioning/{targetTenantId}`, `POST ExternalTenantUserMappings`) answer `409 application/problem+json` with `code: ExternalTenantUserMappingAlreadyExists` and `existingMappingId` when the pair exists; to change roles, update the existing mapping (`PUT ExternalTenantUserMappings/{id}`). `provisionCurrentUser` stays idempotent. Existing duplicates are not migrated; delete the extra rows (`DeleteAdminProvisioningMapping`).
- **`ExternalTenantUserMappingsController`**: System API CRUD for managing mappings (per-tenant, requires `allowed_tenants`)
- **Source user lookup (AB#8341)**: `POST ExternalTenantUserMappings/sourceUserLookup` finds one user of another tenant by
  exact user name / e-mail for a grant (`docs/CONCEPT-SIBLING-TENANT-GRANTS.md`). Code in
  `IdentityServerPersistence/Services/SourceTenantGrants/`: `SourceUserLookupService` (registry ancestry via
  `ICrossTenantAncestryGuard`, never `SearchUsersInTenantAsync`), `ISourceTenantGrantPolicy` (default
  `DenyNonAncestorsSourceTenantGrantPolicy` until AB#8345), `ISourceUserLookupAuditSink` (no-op until AB#8342),
  `SourceUserLookupRateLimiter` (`Identity:SourceUserLookupRateLimit`). 🔴 Every negative case returns the one constant
  `404 SourceUserNotFound` and runs the same queries (no early return, decoy query in T when S is unknown); never add a
  reason to the answer and never log the identifier. The HTTP test host replaces the policy with
  `Helpers/TestSourceTenantGrantPolicy` (permits only the pairs a test arranges, default otherwise); tests
  `SourceUserLookupTests`, `SourceUserLookupServiceIntegrationTests`. The sign-in block rule of AB#7855 lives in
  `SourceUserSignInBlock` and is shared with `CrossTenantAuthenticationService`.
- **`AdminProvisioningController`**: Cross-tenant provisioning via system tenant (see below)

**Cross-tenant auto-login** (token-based, no credential re-entry):
- `POST /{parentTenantId}/api/auth/cross-tenant-token` — Generates a DataProtection-encrypted token (60s expiry) for the authenticated parent-tenant user
- `POST /{childTenantId}/api/auth/cross-tenant-login` — Exchanges the token for a session in the child tenant
- The Angular login component automatically attempts token-based auto-login when clicking "LOGIN VIA {parent}". If no parent session exists, it redirects to the parent tenant's login page (where all auth methods are available); after authentication there, it redirects back with a `crossTenantAutoLogin` query param to auto-complete the token exchange

**Cross-tenant role sync**: When a cross-tenant user logs in (via `FindOrCreateCrossTenantUserAsync`), `SyncMappedRolesAsync` resolves mapped role IDs to role names by querying the tenant repository directly (via `IMultiTenancyResolverService.GetTenantRepository()`), then calls `UserManager.AddToRoleAsync` with the role **name** (not ID). This runs on every login, ensuring existing users get role updates. Important: `RoleManager<RtRole>` must NOT be used for this — it may resolve to the wrong tenant context during cross-tenant login. The tenant repository approach reads from `HttpContext.Items["tenantRepository"]` which is correctly set by the inline middleware.

**Second factor across tenant boundaries (AB#7804, AB#7815):** every cross-tenant entry point (password login
fallback, cross-tenant-token/-login, tenant-switch, token exchange; the device approval no longer crosses tenants, AB#7884) refuses a source user
with 2FA (own or anywhere in its `xt_` chain: `CrossTenantAuthResult.SourceUserRequiresSecondFactor`) unless the proof
carries `amr=mfa` (`SecondFactorEvidence`). The password login answers `requiresTwoFactor` and completes through the
normal `login-2fa`/`login-2fa-email`/`login-recovery` endpoints against the SOURCE user (`ICrossTenantSecondFactorVerifier`,
source lockout counts). Sessions/tokens issued on evidence carry `amr=mfa` on (exchange: `["token_exchange","mfa"]`);
device tokens now keep the session's `amr` instead of a forced `pwd`. `tenant-switch` derives the source identity from
the caller's own chain (never the request body, AB#7815). Details: `docs/authentication.md` § Second Factor Across
Tenant Boundaries; tests `CrossTenantSecondFactorTests` (HTTP, real child tenant). The repository has no CHANGELOG file;
this paragraph and that section are the change record (Security). AB#7859: the security-stamp revalidation (every 30 min) used to drop
`amr=mfa` from the session; `SessionClaimPreservation` (`OnRefreshingPrincipal`) keeps `amr`/`idp`/`sid`. The refresh
grant already kept `amr`. 🔴 Tests that need the revalidation advance `CustomWebApplicationFactory.SecurityStampClock`
(reset it in `finally`); tests: `SecondFactorEvidenceRefreshTests`.

**Sign-in attempts are counted atomically and rate-limited (AB#7854):** `OctoUserManager` (the registered
`UserManager<RtUser>`) counts failures and resets the counter in one MongoDB transaction on the stored user
(`IAtomicUserLockoutStore`, `OctoUserStore.Atomic.cs`, retried on write conflicts); recovery codes are redeemed in one
transaction; cross-tenant password failures count against the parent-tenant user and a locked parent user is not verified.
`ISignInRateLimiter` (per pod, in memory) answers 429 on `login`/`ldap-login`/`login-2fa*`/`send-2fa-email`/`login-recovery`
above 10 attempts per account per minute, 1 concurrent attempt per account, 60 per client address (right-most
`X-Forwarded-For`) — `Identity:SignInRateLimit`. 🔴 A record inside `RtUser.UserTokens` must be written back through the list
indexer (`UserTokens[i] = token`); an in-place change of the record object is not persisted. 🔴 The integration-test factory
raises the limits (the suite signs in from one address); a test of the limit itself uses `Factory.WithWebHostBuilder` +
`ConfigureTestServices`. Details: `docs/authentication.md` § Sign-In Attempts; tests `SignInAttemptConcurrencyTests`,
`SignInRateLimiterTests`.

**Cross-tenant hardening (AB#7861):** the challenge cookie is single-use (nonce + `ICrossTenantChallengeReplayGuard`,
voided on completion, logout and local sign-in), gaps in the `xt_` chain require the second factor, and stored `amr` user
claims are never returned by `OctoUserStore.GetClaimsAsync`. AB#7884: the unreachable cross-tenant provisioning branch of
`DeviceVerificationController` is gone — a session whose subject is not a user of the device code's tenant gets
`access_denied`; the session's `amr` is still passed on to the device token.

**Locked-out or disabled source users (AB#7855):** `ValidateCrossTenantAccessAsync` (every crossing) also refuses a
locked-out source user and one the `IdentityOptions.SignIn` rules refuse ("disabled"; no separate flag on `RtUser`),
including every tier of its `xt_` chain.

**Cross-tenant token exchange (RFC 8693, AB#4338)** — the non-interactive
counterpart of the browser tenant-switch, for the MCP server:

- **`TenantExchangeProcessor`** (`IdentityServices/OpenIddict/`, invoked by
  `TokenEndpointController` for
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` — RFC 8693 is a
  first-class OpenIddict flow; this replaces the former Duende
  `TenantExchangeGrantValidator`): validates the caller's home-tenant (A) access
  token (`subject_token`), reads the target tenant B from `acr_values=tenant:B`,
  asserts the request was wired to B (fail closed → `invalid_target`), gates on
  `ValidateCrossTenantAccessAsync(B, A, subA)` (→ `unauthorized_client`), then
  `FindOrCreateCrossTenantUserAsync` for the B-shadow user and builds the
  principal with **`sub` = the B-shadow user's `RtId`**. This is the same
  security linchpin as before (AB#4966 dual-candidate source selection is
  preserved): the token runs on the B-shadow sub, so
  `OctoTokenClaimsService`/`OctoUserStore` stamp `tenant_id=B` + B-resolved roles
  automatically — A's roles never leak into B. Reuses `CrossTenant*` services and
  `AllowedTenantsResolver` unchanged.
- **`OidcTenantResolutionMiddleware.ResolveTenantFromTokenRequestAsync`** has a
  `token-exchange` branch that resolves B from `acr_values` exactly like the
  `client_credentials` branch, wiring B's repo into `HttpContext.Items` before the
  token is minted.
- **Audit**: `TokenExchangeSuccessEvent` / `TokenExchangeFailureEvent`. Failure
  events persist to the runtime event log via `IIdentityAuditService`; success
  events are log-only.
- **Clients**: the token-exchange grant is on `AllowedGrantTypes` of the
  `octo-mcpServices-device` client (660…034) in the `System.Identity.Bootstrap`
  blueprint — additive client config, no CK schema change. The MCP server performs
  ALL exchanges with the device client regardless of how the user logged in
  (device flow or DCR-registered interactive client). The interim
  `octo-mcpServices-interactive` client (660…035) was removed again in blueprint
  **1.1.5** — interactive MCP clients self-register via DCR (`octo-dcr-*`)
  and nothing ever consumed the static client.
- **octo-cli exchanges too (AB#6839, blueprint 1.8.0):** `octo-cli` (660…31, public, secretless)
  carries the token-exchange grant next to device_code, so an operator's root-tenant token can be
  exchanged for a child-tenant token (`acr_values=tenant:X`) instead of being sent to a foreign
  tenant route. The client reaches the child tenant twice: the blueprint seeds `octo-cli` in every
  tenant, and the `AutoProvisionInChildTenants` mirror copies the parent's `AllowedGrantTypes`
  (`CreateMirrorClient`), converging on every identity start (for tenants that already had the client see
  *Rollout* below: the seed cannot change a tenant-owned value). Pinned by
  `OctoCliClientTokenExchangeSeedTests`.
- **Ancestry is not authority (decision Gerald 2026-10-17, AB#6839).** The exchange only checks that
  the caller's tenant is an ancestor of B; the issued token carries exactly the roles the B-shadow
  user resolves in B (explicit `ExternalTenantUserMapping` roles/groups, group membership, direct
  role) — **no implicit admin role for ancestor users**. Provisioning in each child tenant is a
  **required operator step, also for new tenants**: `octo-cli ProvisionCurrentUser -ttid <child>`.
  A caller with an ancestor relationship but no role in B is refused **at the exchange**
  (`TenantExchangeProcessor.ExchangeAsync`, step e): HTTP 403, `error=access_denied`,
  `error_description` starting with the stable marker `tenant_not_provisioned`
  (`TenantExchangeProcessor.NotProvisionedMarker`; clients match the marker, not the text) — plus a
  `Token Exchange Failure` audit event. A role-less token could not pass role enforcement anyway,
  so the only change for existing callers (octo-mcp-service `TenantTokenExchanger` treats any
  non-success as "denied"; Studio `switchTenantByExchange` is unused) is an early, clear refusal
  instead of a token that fails on the first call. A non-ancestor caller is still
  `unauthorized_client`. A refused exchange leaves nothing in B: no mapping since AB#7088, no shadow
  user since AB#8304; an empty mapping that already exists grants nothing (`Exchange_RepeatedAfterEmptyMapping…`).
  Exchanged tokens never carry a refresh token. Tests: `TenantExchangeIntegrationTests`
  (`Exchange_AncestorUserWithoutProvisioning…`, `…ProvisionedOperator…`, `…DirectRoleGrant…`,
  `…NonAncestor…`).
- **Rollout (AB#6839, existing tenants):** the blueprint bump alone does NOT reach a tenant that already
  has the client. `Client.AllowedGrantTypes` is `TenantOwned` (AB#6324), so the seed import (Upsert) keeps the
  stored value; the apply logs `mode=Initial added=N updated=0` regardless (Upsert is counted as "added").
  Verified on test-2 (octo-cli r3.5.27: exchange refused with `unauthorized_client`). Hence
  `OctoCliTokenExchangeGrant` (`Services/ClientGrants`): a one-time, additive step in
  `DefaultConfigurationCreatorService.SetupTenantAsync` (every identity start, tenant create/update) that
  appends the token-exchange URN to `AllowedGrantTypes` of every client with `ClientId == "octo-cli"` and
  touches nothing else. It runs AFTER the blueprint apply and AFTER the child-tenant mirror provisioning,
  because that mirror copies the parent's grants over a mirrored `octo-cli` — in a child whose parent is not
  fixed yet this step must have the last word. One log line per tenant: `AB#6839 octo-cli token-exchange
  grant: tenant=… result=Added|AlreadyPresent|ClientMissing|AlreadyDone clientsUpdated=n` (no secrets).
  Run-once marker (tenant configuration key `OctoCliTokenExchangeGrant`, written only when an `octo-cli`
  client was found): a grant an administrator removes later is not re-added by this step (a mirror copy from
  the parent still can). Tenants without the client are retried on each setup. No blueprint bump and no
  manual database edit needed; after deploying the identity image, check the start-up log lines per tenant
  (counts show which tenants were touched) and verify with `octo-cli -c GetClient -id octo-cli`.
  Before the CLI relies on the exchange (AB#6836), operators must be provisioned in each child tenant they
  operate (`ProvisionCurrentUser -ttid`). Tests: `OctoCliTokenExchangeGrantIntegrationTests` (real MongoDB),
  `OctoCliClientTokenExchangeSeedTests`.
- **Only access tokens are subject tokens (AB#7860):** `TenantExchangeProcessor` and `OnBehalfOfProcessor` validate the
  `subject_token` with `SubjectTokenValidation.ForAccessToken` (`typ` must be `at+jwt`), so an id_token with user claims
  is refused. OpenIddict already refuses it for the RFC 8693 grant; on-behalf-of (custom flow) relies on this check alone.
  Test tokens minted with `JsonWebTokenHandler` need `TokenType = "at+jwt"`.
- **v1 issues no exchanged refresh token** (short-lived B tokens, re-exchanged from
  the still-valid A token). See `docs/CONCEPT-CROSS-TENANT-TOKEN-EXCHANGE.md` and
  `docs/authentication.md` § Cross-Tenant Token Exchange. Coverage:
  `tests/IdentityServices.IntegrationTests/Persistence/TenantExchangeIntegrationTests.cs`
  (privilege-escalation regression: resolved roles == B subset, not A's full set).

### Delegation / On-Behalf-Of Grant (AB#5026)

A service-account `Client` authenticates with its own client credentials **and** presents a user's
access token as `subject_token`; the issued token runs on the **user's** `sub` but carries only the
**intersection** of both parties' effective roles, plus `act` = the service account's `client_id`.

- **Grant type:** `urn:meshmakers:params:oauth:grant-type:on-behalf-of` — an **own URN**, deliberately
  not the RFC 8693 token-exchange one: the grant type IS the per-client opt-in surface
  (`AllowedGrantTypes` → grant permission via `ClientPermissionsMapper`), a shared URN would also share
  the opt-in, and the only client carrying the token-exchange grant today
  (`octo-mcpServices-device`) is a **public client with no secret**. Registered as an OpenIddict
  custom flow (`AllowCustomFlow` in `OpenIddictConfiguration`).
- **`IDelegatedIdentityResolver` / `DelegatedIdentityResolver`** (`IdentityServerPersistence/Services/`):
  the policy, free of every protocol type (which is what made it survive the OpenIddict migration
  unchanged, and keeps the rule unit-testable without protocol mocks). Service-account roles via
  `IClientRoleStore.GetEffectiveRoleNamesAsync`, user roles via `IUserRoleStore<RtUser>`
  (= `OctoUserStore`); both therefore include **group-inherited** roles. Intersection compares role
  names case-insensitively (role lookups key off the upper-invariant `NormalizedName` everywhere).
  Unknown client / user return a `DelegationDenialReason`, never an exception.
- **`OnBehalfOfProcessor`** (`IdentityServices/OpenIddict/`): a thin protocol adapter — raw
  parameters → out-of-context `subject_token` validation (`JsonWebTokenHandler`, same rationale as
  `TenantExchangeProcessor`) → same-tenant gate → resolver → `DelegationOutcome`.
  `TokenEndpointController.HandleOnBehalfOfAsync` turns the outcome into the issued principal.
- 🔴 **`OnBehalfOfProcessor.ApplyDelegationClaims` is load-bearing.** Because the token runs on the
  user's `sub`, `PopulateUserClaimsAsync` resolves that user's **full** role set onto the issued
  identity. Left alone, the intersection never reaches the token and the grant is a placebo. The
  helper replaces every `role` claim with the intersection and stamps `act`; the access-token
  destination for `act` comes from `OctoClaimsDestinations` — **no blueprint bump or `octoAPI`
  ResourceClaims change was needed**.
- 🔴 **`OidcTenantResolutionMiddleware.ResolveTenantFromTokenRequestAsync` needed a new branch.** Its
  if/else chain is a closed list of grant types; an unlisted URN falls through to `null`, no tenant is
  wired into `HttpContext.Items`, and every per-tenant store reads the **system** tenant instead.
- **Same-tenant only (v1):** `acr_values` tenant == request tenant == `subject_token.tenant_id`, else
  `invalid_target`. Cross-tenant delegation is v2; the token-exchange grant covers cross-tenant today.
- **Empty intersection is a success**, not an error — the token carries no `role` claim so role-gated
  consumers fail closed.
- 🔴 **`offline_access` is rejected with `invalid_scope`** (persisted as a delegation-failure audit
  entry), not just discouraged. The intersection is computed **at issuance**; a
  `grant_type=refresh_token` request rebuilds the access token from the stored principal and never
  re-enters the processor, so the intersection would freeze and a role revoked on **either** side
  would keep working for the refresh token's whole lifetime. Two layers enforce it: the processor
  refuses an explicit request with an explained error, and `HandleOnBehalfOfAsync` removes the
  `offline_access` scope from the issued principal so OpenIddict never mints a refresh token.
  `AllowOfflineAccess=false` on the client is a seeding convention, not an invariant, so it is not
  relied on.
- **Audit:** success is log-only; failures are persisted via `IIdentityAuditService` as
  "Delegation Failure" entries carrying client, subject, tenant and reason.
- **No seeded service account here** — the client must carry the URN in `AllowedGrantTypes` or
  OpenIddict rejects the request before the token controller runs. The real pipeline service account
  is created by the Communication Controller over the bus; see "Service-Account Clients over the
  Distribution Event Hub" below (AB#5027).

### Command consumers run on every replica (AB#6910)

`CreateIdentityData` (`CreateIdentityDataCommandRequestConsumer`, queue `octo::identity::create-identity-data`) is
registered **shared** (competing consumers) in `Consumers/IdentityCommandConsumers.cs`, called from `Program.cs`:
with two or more replicas every replica consumes it and each command is processed **exactly once** by one of them.
Before AB#6910 it was the classic exclusive consumer: only one replica consumed, the others waited, and a hung owner
(prod-1 2026-10-18/19, NotReady node) blocked identity provisioning.

- `CommandConsumerOptions { MigratesLegacyCommand = true }` is **required**: all senders (asset repository, bot,
  communication controller, AI, MCP, report service; `AddCommandClient`) still send to the classic address. The
  consumer uses the queue `…::shared` and serves the classic address only while no old exclusive replica is alive, so a
  rolling update (old and new build side by side) starts without errors and loses or duplicates nothing. Plain shared
  options without the flag would receive nothing from these senders. Rollback: stop the new replicas first, then start
  the old build (event hub `docs/DEVELOPER.md`, "Migrating exclusive command queues").
- Safe under competing consumers: no state between messages, one MongoDB transaction per message, existing clients
  replaced with the version read in the transaction (AB#8054, a conflict is retried). The exclusive endpoint had no
  concurrency limit, so one replica already ran these commands concurrently.
- The AB#6909 deprecation warning ("classic EXCLUSIVE topology") is no longer logged at start; a new command consumer is
  added to `IdentityCommandConsumers` with the shared options and a comment why it is safe.
- The CK method handlers (`IdentityMethodHost`) are unaffected: they already use the shared per-method queues of
  octo-common-services.
- Tests: `IdentityServices.IntegrationTests/Consumers/IdentityCommandConsumerReplicaTests` (Docker: MongoDB + RabbitMQ
  Testcontainers): two replicas with the production registration, 16 commands from a classic sender, each processed
  once, both replicas consume, each client exists once; no deprecation warning at start; rolling update old exclusive
  + new shared replica (old keeps the traffic, after it stops the new replicas take over, nothing lost or duplicated).
- Operations: queues `*::shared` and exchanges `*::send` are new names; broker policies or monitoring matching command
  queue names must include them.

### Service-Account Clients over the Distribution Event Hub (AB#5027)

The Communication Controller provisions one `client_credentials` service account per mesh adapter, so
pipeline execution runs under a real identity. It can only reach this service **over the bus**: the
REST `ClientsController` needs an `octo_api` bearer token, i.e. the very identity being created, and
no client-credentials client with a secret is seeded anywhere. `CreateIdentityDataCommandRequestConsumer`
therefore had to learn three things it could not do before — it hard-coded `RequireClientSecret=false`,
never wrote a `ClientSecrets` entry and never touched an association:

| `DistClientDto` field (octo-common-services `Meshmakers.Octo.Services.Contracts`) | Consumer behaviour |
|---|---|
| `ClientSecret` (**plaintext**, optional) | Hashed with `OctoSecretHasher.HashSecret` (the same legacy SHA-256 convention `ClientsController` uses) and written as the single `ClientSecrets` entry. **Never** persisted or logged in the clear. |
| `RequireClientSecret` (default `false`) | Written verbatim. The default reproduces the previous hard-coded behaviour, so every pre-AB#5027 producer keeps creating public clients unchanged. |
| `AssignedRoleNames` (optional) | Additive, idempotent `AssignedRole` edges — matched on `RtRole.NormalizedName` (upper-invariant). Roles not listed are never removed; an **unknown role name is logged and skipped**, not fatal, because the tenant's role seed runs on an independent trigger (the `SuccessIdentityDataSeedPending` case) and losing the whole identity-data setup over it would be far worse. |

Two traps worth knowing:

- 🔴 **The upsert branch preserves the existing secret when the DTO carries none.** The consumer
  replaces an existing client wholesale (`ReplaceOneRtEntityByIdAsync`); without the preserve branch
  the next identity-data pass would silently drop a live secret. Harmless while no bus client had
  one — fatal now that a service account does. Sending the *same* plaintext again is therefore the
  no-rotation path, and that is exactly what the controller does on every convergence pass.
- 🔴 **`IClientRoleStore` cannot be used from the consumer.** It resolves its repository through
  `IMultiTenancyResolverService.GetTenantRepository()`, i.e. the HTTP-scoped tenant; a bus consumer
  has no HTTP context and would silently write into the **system** tenant. The `AssignedRole` edge is
  written directly against the tenant repository the consumer resolved from the message.

🔴 **An under-privileged service account fails silently.** The controller seeds the account with the
`octo_api` scope plus `CommunicationManagement`. For the delegation grant above, the issued token
carries the **intersection** of service-account and user roles — and an **empty intersection is a
success**, not an error: a token is issued, it simply has no `role` claim, and role-gated consumers
fail closed. A service account lacking the tenant's fachliche roles (e.g. Accounting) therefore makes
the feature go quiet with no error anywhere. When setting up delegation for a tenant, grant
`octo-pipeline-sa-{adapterRtId}` those roles as well —
`PUT {tenantId}/v1/clients/{clientId}/roles/{roleName}` or `octo-cli AddClientToRole`. Since AB#7928 the caller must hold
a built-in role itself to grant it to a client (403 `role-not-held` otherwise); custom roles are free, and since AB#8564 a caller holding
`UserManagement` may also grant app roles (roles a blueprint other than `System.Identity.Bootstrap` seeds) it does not hold.

**Deployment order:** identity first, then the Communication Controller. An identity that predates
this change ignores the new fields and would create a secretless client.

Tests: `tests/IdentityServices.IntegrationTests/Persistence/ServiceAccountClientProvisioningIntegrationTests.cs`
(hashed secret + both grant types + scope + role on create; a second run with the same secret rotates
nothing and creates no duplicate client or role edge; a re-run without a secret preserves the existing
one; a pre-AB#5027-shaped client stays public and secretless; an unknown role name is skipped instead
of failing the setup).
- **Tests:** `DelegatedIdentityResolverTests` (intersection arithmetic), `DelegationClaimCompositionTests`
  (the anti-placebo proof: real `GrantValidationResult` → real `ApplyDelegationClaims`),
  `OnBehalfOfGrantValidatorTests` (protocol adapter over a real `ExtensionGrantValidationContext` and a
  genuinely signed `subject_token`: the `offline_access` refusal and the unchanged happy path — note it
  must call `ValidatedTokenRequest.SetClient(...)`, since a plain `Client = …` initializer leaves
  `ClientId` empty),
  `OidcTenantResolutionMiddlewareTests` (new grant branch),
  `Persistence/DelegatedIdentityIntegrationTests.cs` (real MongoDB, group-inherited roles on both sides).

See `docs/authentication.md` § Delegation / On-Behalf-Of.

### Multi-Tenant Client Credentials (Auto-Provisioning) — Phase 1 in flight

Schema groundwork for the cross-tenant ClientCredentials feature lives in CK
model `System.Identity-2.5.0` (schema version 15):

- `RtClient.AutoProvisionInChildTenants` (bool, default `false`): when set on
  a parent-tenant client, every new sub-tenant gets a mirror of this client
  auto-provisioned. Enables a single ClientCredentials identity (typically a
  CI/CD agent) to reach every tenant on the instance with the same
  `ClientId` / secret pair, without per-tenant manual setup. Default `false`
  preserves the existing single-tenant behaviour for every client that
  pre-dates this feature.
- `RtClientMirror` (new CK type): one row per (parentClientId × childTenantId)
  pair. Lives in the **parent tenant's** identity DB and tracks
  `ParentClientId`, `ParentTenantId`, `ChildTenantId`, `ProvisionedAt`,
  `SecretHashVersion`. Unique index on `(ParentClientId, ChildTenantId)`.
  `SecretHashVersion` is a monotonic counter that the parent's secret-rotation
  consumer bumps on every rotation, so mirrors that fell behind can be
  detected and re-synced.

**Provisioning service (#4043 — done):**
`IClientMirrorProvisioningService.ProvisionForChildTenantAsync(parentTenantId, childTenantId)`
in `IdentityServerPersistence/Services/` walks the parent's flagged clients
and (idempotently) materialises each as an `RtClient` in the child tenant's
identity DB, then writes a tracking `RtClientMirror` row in the parent. Uses
`ISystemContext.TryFindTenantRepositoryAsync` for both repos. The mirror's
`AutoProvisionInChildTenants` is forced to `false` so a mirror can never
itself become a source of further mirroring.

**Setup-time hook:** `DefaultConfigurationCreatorService.SetupTenantAsync`
invokes `ProvisionForChildTenantAsync(systemContext.TenantId, tenantId)` for
every child tenant. Runs on every startup → mirrors are also backfilled
automatically for tenants that pre-date the flag being set on the parent.
Provisioning failures are logged but never break tenant setup. **Open
question (intentional):** parent is hard-wired to `systemContext.TenantId` —
nested customer sub-tenants are out of scope for v1, see
`octo-communication-controller-services/docs/concepts/cicd-workload-deployment.md`.

**Upkeep hooks (#4044 — done):**

- `ClientStore.MutateAsync` (the only way to change a stored client since AB#8015) fires `SyncMirrorsForClientAsync`
  after commit when the post-update client carries `AutoProvisionInChildTenants=true`.
  Propagates secret rotation / scope / lifetime changes onto every mirror
  and bumps each mirror's `SecretHashVersion`.
- `ClientStore.DeleteAsync` fires `RemoveMirrorsForClientAsync` after commit
  when the deleted client was flagged. Removes the child-tenant
  `RtClient` records and the parent's tracking rows together.
- `IdentityTenantManagementConsumer` (in `IdentityServices/Consumers/`)
  subscribes to `PreDeleteTenant` and calls
  `RemoveMirrorsForChildTenantAsync(systemContext.TenantId, deletedTenantId)`.
  The mirror's child-side `RtClient` is gone with the tenant DB, so this
  only drops the parent's tracking rows.

All three paths are best-effort: failures are logged and **do not** bubble
back to the primary operation (client update, client delete, tenant delete).
The same holds for the secret writes of `Client.AddSecret` / `Client.RemoveSecret`
and the REST secret endpoints (sync after commit, error logged).

**Periodic mirror reconciliation (AB#8019, Security).** Before it, only the next identity start
re-converged a mirror that a failed sync left behind, so a secret removed in the parent stayed valid
in the child tenants until a restart. A compensation job (decision OD-6: no outbox) closes the window:

- `ClientMirrorReconciliationHostService` (`IdentityServices/Services/`) runs
  `IClientMirrorReconciliationJob.RunOnceAsync` every `Identity:ClientMirrorReconciliationInterval`
  seconds (default `300`, `0` or less = off; first pass one interval after start, plus a random offset
  of at most 10 % / 30 s). The job (`IdentityServerPersistence/Services/ClientMirrorReconciliationJob.cs`)
  calls `IClientMirrorProvisioningService.ReconcileMirrorsAsync(tenantId)` for the system tenant and every
  registered tenant (tracking rows live in the parent).
- `ReconcileMirrorsAsync` walks the `RtClientMirror` rows of the parent (child repositories cached per pass). Per row: read
  the child mirror, **then** the parent client; derive the desired mirror with the same `CreateMirrorClient` +
  `ReconcileOwnSecret` the provisioning uses; compare (`MirrorDiffers`: **every** attribute `RtClient` declares - secrets incl.
  expiry and own secret, claims, PKCE/DPoP flags, lifetimes, all URIs, ... -, lists as multisets, records by attribute, the mirror
  marker case-insensitively; not the entity id/version/timestamps); write only on a difference, then bump `SecretHashVersion`
  (version-checked; a concurrent bump wins) and publish `CorsClientsUpdate`. The tracking row is the authority: a tracked mirror
  follows its parent even after the flag was switched off. An unreachable child tenant is skipped (row kept).
- **Missing mirror:** the row is re-read right before the insert (gone = skip), the client is inserted, then the row is written
  **with its version**; when that fails (row removed by `RemoveMirrorAsync` / the client-delete cleanup, or another replica
  re-created the mirror first) the inserted client is deleted again. No untracked orphan, no duplicate.
- **Deleted parent client** (delete cleanup failed): the mirror is removed on the **second consecutive** pass that misses the
  parent (`MissingParentPassesBeforeRemoval`, per process), and only a child client carrying this parent's marker.
- 🔴 **Every mirror writer is version-checked (replica safety, review finding on #230).** A replace *without* an expected version
  writes the entity as given and does **not** advance `rtVersion` (engine AB#7769), so the check only holds when every writer
  takes part. All child-mirror writes go through `ConvergeChildMirrorAsync` (immediate sync, start-up provisioning, backfill,
  reconciliation: read child, read parent, derive, replace with the read `rtVersion`, re-read and re-derive on
  `RtVersionConflictException`, at most `MaxMirrorWriteAttempts` = 5) or the versioned `RotateMirrorSecretAsync`. The sync re-reads
  the parent after the child (the passed snapshot is only the fallback), so a delayed sync cannot write an older parent state over
  a newer one. Result: a write after our child read makes our replace fail, a write before it is visible to the comparison while
  the parent was read after it; neither a removed secret nor a superseded own secret can come back.
- 🔴 **All other writers of a client record are versioned too (AB#8054).** Every writer that can touch a mirror writes with the
  `rtVersion` it read, so its write advances `rtVersion` and a reconciliation pass that read the mirror before it fails its check
  and re-reads (before, such a write left `rtVersion` unchanged and the stale pass overwrote it unnoticed):

  | Writer | How |
  |---|---|
  | REST client `PUT`, overlay URIs, overlay clean-up, `PATCH autoProvisionInChildTenants` (any tenant, mirrors included) | `IOctoClientStore.MutateAsync` (AB#8015; `UpdateAsync` is gone), retry on conflict, `409` after 20 attempts |
  | `octo-cli` token-exchange grant step (`OctoCliTokenExchangeGrant`) | replace with the version read in the same transaction |
  | Post-blueprint URI restore / URI family pass (`DefaultConfigurationCreatorService`) | replace with the version read in the same transaction |
  | Bus consumer `CreateIdentityDataCommandRequestConsumer` (existing client) | replace with the version read in the same transaction; a conflict fails the message, which is retried |
  | Tracking row: immediate sync, start-up provisioning, mirror secret rotation | the row is re-read right before the write (sync) and written with its version; a concurrent bump wins (the counter is informational). When the sync or the provisioning had to **insert** the mirror, the versioned row write claims the insert, exactly as the reconciliation does: a row that changed or vanished meanwhile (another writer re-created the mirror, `RemoveMirrorAsync`, the delete cleanup) withdraws the inserted client, so no duplicate and no untracked mirror (a removed mirror the sync would otherwise have re-created) stays behind |
  | **Blueprint seed upsert** (engine `ImportRt`, `ImportStrategy.Upsert`) | **not changed** (decision AB#8054, see below) |

  **Blueprint seed upsert - why no engine change.** The import reads the stored entity (to keep its `Secret` / `TenantOwned`
  attributes) and replaces it in **one MongoDB transaction**. A write that commits after that read makes the replace fail with a
  write conflict (MongoDB snapshot isolation; the engine reports the same case as a version mismatch for versioned writes), so the
  seed can never write back a secret the reconciliation or a secret delete removed in between - it is not a stale writer. What it
  does not do is advance `rtVersion`, so a reconciliation pass that read the mirror before the seed write overwrites the seed's
  values with the values derived from the parent: the intended direction (a mirror is derived data), and the start-up provisioning
  that runs right after the apply in `SetupTenantAsync` converges every system-parent mirror again anyway. Making the bulk upsert
  version-checked would change every `ImportRt` caller (blueprints, migrations, user imports) for no security gain.
  `TransactionalReadModifyWrite_ThatReadTheMirrorBeforeTheJobsWrite_CannotWriteTheRemovedSecretBack` pins the guarantee.
- Logs: a failing mirror or tenant is a Warning (not an Error every pass); test seams `BeforeMirrorWriteForTests` (client id,
  child tenant id) / `BeforeMirrorInsertForTests` / `BeforeMissingMirrorWriteForTests` (AB#8054: between the child read of a missing
  mirror and its insert) (internal) let the integration tests interleave writers.
- **Expiry is copied now.** `CopySecrets` dropped `ExpirationDateTime`, so a parent secret that expired kept
  authenticating in every child tenant; mirrors now carry the expiry (also the carried-over own secret).
- **Metrics/logs:** meter `Meshmakers.Octo.Identity` (registered in `Program.cs` via
  `ConfigureOpenTelemetryMeterProvider`): `identity.client_mirror.reconciled` (`outcome` = repaired / removed /
  skipped / failed) and `identity.client_mirror.reconcile.runs` (`outcome` = ok / tenant_failed); labels never
  carry tenant, client, secret or hash. One Information line per repaired mirror (client id, tenants, version)
  and one summary per pass with counts when something changed; never a secret value or hash.
- Bound: a removed / added / rotated / expired parent secret reaches every reachable mirror within about one
  interval after the failed sync. The integration-test factory sets the interval to `0`; tests call the job.
- **Tests:** `tests/IdentityServices.IntegrationTests/Api/Methods/ClientMirrorReconciliationTests.cs` (real MongoDB,
  real child tenant and token endpoint; the immediate sync is fault-injected by a decorator: removed secret still
  valid in the child after the failed sync, gone after the job, child token refused; added secret; expired parent
  secret; in-sync mirror (rich client) not written; orphaned mirror removed after the grace pass; two parallel passes
  without a duplicate; a mirror secret rotation and an immediate sync interleaved between the job's parent read and its
  write (red with unversioned writers); AB#8054: a client `PUT` in the child tenant, the `octo-cli` grant step and an immediate sync
  that re-creates a missing mirror, each between the job's reads and its write (red with unversioned writers), and a transactional
  stale write that cannot bring a removed secret back; a missing mirror whose row is removed before the insert; two parallel passes
  re-creating a missing mirror; metric and log canary),
  `tests/IdentityServerPersistence.UnitTests/Services/ClientMirrorReconciliationTests.cs` (comparison incl. token fields,
  marker case, read order + version, conflict, orphan with grace pass and foreign client, unreachable child, withdrawn
  insert, row gone on the re-read),
  `tests/IdentityServices.UnitTests/Services/ClientMirrorReconciliationHostServiceTests.cs` (interval).

**Management REST endpoints (#4045 — done):** all under
`{tenantId}/v1/clients/{clientId}/...`:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `mirrors` | List the sub-tenants this client has been auto-provisioned into. |
| `POST` | `mirrors/provisionInExistingTenants` | Backfill — provision into every existing sub-tenant of the caller. Requires the client to be flagged (400 otherwise). |
| `POST` | `mirrors/provisionInTenant?childTenantId=…` | One-shot provision into a specific sub-tenant. |
| `DELETE` | `mirrors/{childTenantId}` | Remove a single mirror (drops both the child-side `RtClient` and the parent's tracking row). |
| `PATCH` | `autoProvisionInChildTenants` | Flip the `AutoProvisionInChildTenants` flag on the client without rewriting the full client object. Body: `{ "enabled": true|false }`. |

Backed by `ClientMirrorController` + `ClientAutoProvisionFlagController` in
`TenantApi/v1/Controllers/`. The `PATCH` flow piggybacks on
`ClientStore.MutateAsync` (version-checked, AB#8015) so the post-commit upkeep hook (#4044) fires
automatically — flipping the flag from `false` → `true` does **not**
backfill existing sub-tenants; the operator must explicitly trigger
`provisionInExistingTenants` for that (or wait for the next service
startup, which runs the same provisioning loop).

**End-to-end coverage (#4046 — done):**
`tests/IdentityServices.IntegrationTests/Persistence/ClientMirrorProvisioningIntegrationTests.cs`
exercises the full stack against a Testcontainers-backed MongoDB:
fresh-child provision, idempotency on repeat, backfill into three
pre-existing children, secret rotation propagating + version bump,
client-delete cleanup, tenant-delete tracking-row cleanup. Tests reuse
the existing `IdentityServicesFixture` and call
`IDefaultConfigurationCreatorService.SetupAsync(...)` to seed CK models
into both the system tenant and the new child tenants — this is also the
real production path, so the integration coverage includes the
`DefaultConfigurationCreatorService` ↔ `IClientMirrorProvisioningService`
hookup added in #4043. `ServiceCollectionFixture` now registers
`AddMigrations(typeof(IdentityServiceConstants).Assembly)` so the same
constructor parameter that production resolves to `MigrationService` is
satisfied in tests too.

The CLI commands and the Studio UI are tracked under **ADO #4047–#4051**
(Epic 3054).

### Server-Side Sessions (cookie-bloat fix)

Full per-tenant ASP.NET auth tickets (~3 KB each, sent with every request and on OAuth loopback-callback redirects) were overflowing small loopback servers and bloating all browser traffic. Sessions are stored server-side via **`OctoTicketStore : ITicketStore`** (`src/IdentityServices/OpenIddict/`), standard ASP.NET Core machinery (the former Duende `ServerSideSessionStore` was deleted in the OpenIddict migration).

**How it works:**
- The per-tenant `.AspNetCore.Identity.Application.{tenantId}` cookie carries **only a short session key** (hundreds of bytes) instead of the full encrypted ticket. The ticket itself lives in MongoDB per-tenant via the CK runtime.
- `OctoTicketStore` persists data-protected tickets in the per-tenant `RtServerSideSession` entities (same CK type as before, new serialization — old Duende-serialized tickets were invalidated at cutover, one re-login).
- The `sid` claim is stamped at session creation.
- `TenantCookieManager` naming convention (`{name}.{tenantId}`) is **unchanged**.
- `ConfigureApplicationCookie` sets `ExpireTimeSpan = 7 days` sliding; this bounds both the cookie lifetime and the session record lifetime.

**CK types:**
- `RtServerSideSession`: stores the encrypted ticket with a **Unique** `SessionKey` index and ascending indexes on `SubjectId`, `SessionId`, and `ExpirationDateTime`.
- `RtDataProtectionKey`: stores the DataProtection key ring (see Data Protection Key Persistence section).

**Cleanup:** expired-but-not-yet-cleaned records are treated as missing on lookup. `TokenCleanupHostService` sweeps expired sessions, expired `RtOAuthToken`/`RtOAuthAuthorization` entries, and legacy grants for the system tenant plus all child tenants.

**Write-conflict retry:** Concurrent session renewals (two browser tabs refreshing simultaneously) can trigger a transient MongoDB write conflict (`MongoCommandException` with a 'Write conflict' message). The store shares the `MongoWriteRetry` helper to retry transient write conflicts transparently.

### Default-Configuration Provisioning

The Identity CK model, default roles, identity resources, API scopes, API resources, and OIDC clients are provisioned to **all tenants** (not just the system tenant) during startup. This ensures OAuth/OIDC flows work when targeting any tenant. For child tenants, roles are written directly to the child tenant database via `EnsureRoleInChildTenantAsync()` using the same `childRepo` pattern as clients and resources. The identity service writes its data directly to child tenant databases (including the `octo-data-refinery-studio` SPA client when `RefineryStudioUrl` is configured), while other services (asset-repo, bot, etc.) send their data via the Distribution Event Hub. Cross-tenant users receive a `home_tenant_id` claim in their tokens.

**The system tenant is only bootstrapped when its database is genuinely absent — or an
infrastructure-only shell (AB#4762, AB#4854).** `SetupTenantAsync` used to call
`CreateSystemTenantAsync()` whenever `IsSystemTenantExistingAsync()` returned false. That is false not
only for a missing database but also for a **present, fully populated** one whose System CK model is
absent or not at the exact expected version — the state `EnsureSystemCkModelAsync()` leaves behind when
it swallows a `ModelValidationException`, e.g. while a dependency still lags during a version-bump
rollout. The engine's create path then hit its database-exists guard inside the `try` whose `catch`
dropped the database, **wiping the entire platform database at service startup**, with no user action
involved.

The caller now checks `systemContext.IsSystemDatabaseBootstrappableAsync()` first. Bootstrappable means
the database is absent or contains nothing but the engine's own infrastructure collections
(lifecycle / setup-retry / lock bookkeeping) — the "shell" the engine's plumbing can materialize on a
virgin server before the bootstrap runs. Refusing over such a shell wedged every 3.4.93 fresh install,
because the bootstrap is the only path that creates the datasource user (AB#4854). For any other
existing database it throws with the real cause instead: the System CK model needs repairing, and
system-tenant setup is deliberately fatal (`DefaultConfigurationInitializationService`), so failing
loudly and diagnosably is correct — repairing itself by dropping the platform database is not. The
engine refuses the same case independently (`TenantException.SystemTenantDatabaseNotBootstrappable`),
so this is defence in depth, not the only guard.

The shell classification is a **closed allowlist** (`InfrastructureCollections` in the engine): any
write into the system database from outside that list, before the bootstrap has run, re-arms the
fresh-install wedge. Identity has exactly one such pre-bootstrap writer — the Data Protection key
store, whose hosted key-ring preload (`AddDataProtection()`) is registered before the setup
initializer. Whether its typed insert succeeds pre-bootstrap depends on whether the process CK cache
happens to be warm, so `DataProtectionKeyStore` refuses to persist (and to run the legacy file seed)
while `IsSystemTenantExistingAsync()` is false — the preload treats that as best-effort and the key
is re-created on the first real Data Protection use after the bootstrap.
`VirginSystemDatabaseBootstrapIntegrationTests.DataProtectionKeyWrite_OnVirginServer_DoesNotArmTheBootstrapWedge`
pins this.

**Deferred tenant startup is parallelized.** `DefaultConfigurationCreatorServiceStandardized.StartDeferredTenantsAsync` (in `octo-common-services`) processes the deferred identity-data setup and the per-tenant `StartTenantAsync` loop with `Parallel.ForEachAsync` and a bounded degree of `min(ProcessorCount, 8)`. This keeps the Identity-service cold start roughly linear in `tenants / parallelism` instead of `O(tenants)` — sequential per-tenant `CkModelUpgradeService` + `MigrationService` runs (~2-3s each) were the dominant cold-start cost (~44s for 13 tenants on test-2). MongoDB databases are tenant-isolated, so the work parallelizes safely; `_pendingIdentityDataTenantIds` is guarded with a `lock` and `failedTenants` is collected into a `ConcurrentBag`. `RetryFailedTenantsAsync` deliberately stays sequential to avoid bursting MongoDB on repeated failures.

**A failed tenant setup is retried durably (AB#4690).** `SetupTenantAsync` applies the
`System.Identity.Bootstrap` blueprint with `throwOnFailure: true`, and Identity derives from
`DefaultConfigurationCreatorServiceBase`, whose `RetryFailedTenantsAsync` used to be a no-op — so a setup
that threw once was lost. That happened in production when a tenant was deleted and recreated under the
same database name: Identity's first access to the new database failed with MongoDB `errorCode 13`
("requires authentication"), the setup aborted, and the tenant was left with **zero roles**, so
`ProvisionCurrentUser` could only ever answer 503. Recovery required a pod restart. The creator now
passes an `ITenantSetupRetryStore` to its base constructor: failures are recorded durably and
`FailedTenantRetryBackgroundService` re-runs the setup until it succeeds (10 attempts, ≥60 s apart).

**`CreateIdentityDataCommandRequestConsumer` reports whether the tenant is actually seeded.** It creates
only the *caller's* API scopes, resources and clients; the tenant's own roles/groups come from
`SetupTenantAsync`. Answering `Success` regardless made the asset repository record the tenant as fully
provisioned while it had no roles. The consumer now checks for roles and answers
`CreateIdentityDataResult.SuccessIdentityDataSeedPending` when there are none, which the caller treats as
a retriable not-ready condition (AB#4690).

**Manual recovery** for a tenant that is already stuck without roles, without restarting the service:
`PUT {systemTenant}/v1/tenants/clearCache?childTenantId=<tenant>` on the asset repository publishes
`PreUpdateTenant` + `PosUpdateTenant`, which makes every service — including this one — re-run
`SetupAsync` for that tenant.

### CK Model Data Migrations Run Once per Tenant Setup (CK v2 D8/N2, AB#5902)

`DefaultConfigurationCreatorService.SetupTenantAsync` captures the tenant's schema versions **before** the
CK model imports, imports System.Identity / System.Notification, and then runs its own data-migration pass
(`RunCkModelMigrationsAsync` → `ICkModelUpgradeService.UpgradeModelsAsync`). The engine already migrates
every model it imports or updates (`TenantContext.RunCkModelMigrationsForImportAsync`) and records
`MigrationHistory` at the new version. Handing the stale pre-import versions to the second pass made the
upgrade service read "schema older than MigrationHistory", assume a manual downgrade and run the same
migration again (D8: every upgraded model was migrated twice per tenant, with a WARN each time). This was
not concurrent setup: both runs are sequential inside one `SetupTenantAsync`.

`MergeSchemaVersionsAfterImport(preImport, postImport, migrationHistory)` decides what the second pass sees:

| Situation | Version handed over | Effect |
|---|---|---|
| Import changed the model **and** the latest successful `MigrationHistory` entry equals the post-import version | post-import | upgrade service finds the target → skip (no double run, no WARN) |
| Import changed the model, but history is missing or behind (the engine's import-time migration failed; it only logs) | pre-import | migration is retried (N2: with the post-import version and no history row, the upgrade service would record "already at target" and silently skip it) |
| Import did not change the model (already current, or skipped by the engine's downgrade guard because the tenant has a newer version) | pre-import | unchanged behaviour |

History comes from `ICkModelUpgradeService.GetInstalledVersionsAsync` (latest successful row per model),
the same source the upgrade service uses. Tests:
`tests/IdentityServerPersistence.UnitTests/Services/DefaultConfigurationCreatorServiceSchemaVersionMergeTests.cs`.

### Embedded CK Models: "Embedded or Newer" (CK v2 Phase 1 G-H2 / R-L4, AB#5902)

Since the engine's downgrade guard (engine-mongodb, AB#5900) a tenant may keep a **newer** System /
System.Identity / System.Notification than this service embeds (rollback, an old replica during a
rolling update). Never decide with `ITenantContext.IsCkModelExistingAsync(SystemIdentityCkIds.CkModelId)`:
it matches the **exact** version `[x.y.z]`. Use `CkModelCompatibility`
(`src/IdentityServerPersistence/Services/CkModelCompatibility.cs`), which looks the model up **by name**
(highest `Available` version) and classifies it. `IsSatisfied` = embedded version or newer, **any
major** — the same rule as the engine's `IsCkModelSatisfiedAsync`.

**Platform rule R-L4 (one rule everywhere):** if a tenant has a **higher major** than this service
embeds, the service is too old for the tenant: skip the import (never downgrade), log **WARN** "service is
too old for the tenant", and keep running. No tenant-setup failure, and no host-startup failure for the
system tenant. Identity has no meter of its own for this; the WARN is the signal.

| Installed vs. embedded | State | Identity behaviour |
|---|---|---|
| none / only `ResolveFailed` / `Importing` | `NotInstalled` | tenant setup imports the embedded model; `CreateIdentityData` answers `FailedTenantHasNoIdentityCk` |
| older | `Older` | tenant setup imports (upgrade) |
| same | `Same` | nothing to import |
| newer, same major | `NewerSameMajor` | no import (INFO); identity data creation works |
| newer major | `NewerMajor` | no import, WARN "service is too old for the tenant"; setup continues; identity data creation proceeds with the same WARN |

The post-import migration run (`RunCkModelMigrationsAsync`) passes `[embedded, nextMajor)` ranges
(`EmbeddedOrNewerSameMajor`) instead of exact `[x.y.z]` ranges, so a newer same-major model is kept with
an INFO instead of a "newer than the declared compatibility range" WARN on every setup. A higher major
stays outside that range: the upgrade service keeps it (never downgrades) and WARNs, which is the R-L4
rule. `SystemContext.IsSystemTenantExistingAsync` (System model in the system DB) is an engine-mongodb
check (`IsCkModelSatisfiedAsync`, any major). Tests: `CkModelCompatibilityTests` (unit) and
`tests/IdentityServices.IntegrationTests/Persistence/CkModelCompatibilityIntegrationTests.cs`, which
re-key the tenant's System.Identity `CkModel` row to a newer version.

### Admin Provisioning (Cross-Tenant Pre-Provisioning)

The `AdminProvisioningController` allows users with the TenantManagement or UserManagement role to pre-provision cross-tenant user mappings in a **target tenant** without needing `allowed_tenants` for that tenant. Since AB#5859 the target must be the caller's own tenant or one of its registry descendants (system-tenant callers: any tenant) — `AdminProvisioningTargetScopeFilter`; before, the role was documented but not checked and any target was reachable. It is routed via the system tenant: `{tenantId}/v1/adminProvisioning/{targetTenantId}`.

**Regression tests and the route rule (AB#4824):** every route whose path contains `{targetTenantId}` must carry
`[TypeFilter(typeof(AdminProvisioningTargetScopeFilter))]` (class or action). `AdminProvisioningRouteCoverageTests`
derives the route set by reflection over all controllers, so a new route without the filter fails the unit tests.
`AdminProvisioningPipelineTests` runs the real routing, `AdminProvisioningController`,
`IdentityTenantAdministrationWritePolicy` and filter against a fake tenant registry: own/descendant 201;
sibling, sibling descendant, unrelated, system and unknown target 403 with an identical response; system caller
any registered tenant (unknown tenant: 404 from the action); create-then-provision; policy and filter together
(roleless caller stopped by the policy, role holder by the filter); `RoleEnforcement=Warn` (the filter only
logs, the call passes — the fix depends on `Enforce`). Since AB#6758 the rule covers every action that names a target tenant — `{targetTenantId}`/`{childTenantId}` in
the route **or** a `targetTenantId`/`childTenantId` parameter (e.g. the query of
`clients/{id}/mirrors/provisionInTenant?childTenantId=`): `ClientMirrorController.ProvisionInTenant`, `RotateSecret` and
`Delete` carry the filter (it reads route and query values; every named tenant must be in scope), and
`ClientMirrorProvisioningService` checks the subtree again (`ClientMirrorScopeException` → 403) for
`ProvisionForChildTenantAsync`/`ProvisionInTenantAsync`/`RotateMirrorSecretAsync`/`RemoveMirrorAsync`; the system tenant as
parent reaches every tenant (tenant creation, dynamic client registration). Tests: `ClientMirrorScopePipelineTests`,
`ClientMirrorScopeGuardTests`, the extended `AdminProvisioningRouteCoverageTests`.

This solves the chicken-and-egg problem: after creating a child tenant, the user doesn't have `allowed_tenants` for it yet, so the per-tenant `ExternalTenantUserMappingsController` is inaccessible. The admin provisioning controller uses `ISystemContext.TryFindTenantRepositoryAsync()` to access the target tenant's database directly.

**Endpoints:**

| Method | Route | Purpose |
|--------|-------|---------|
| `GET` | `/{targetTenantId}` | List all ExternalTenantUserMappings in target tenant |
| `GET` | `/{targetTenantId}/sourceUsers?search=&take=` | Search provisionable users from the target's ancestor (parent) tenants — powers the Studio's cross-tenant user picker |
| `GET` | `/{targetTenantId}/roles` | List the roles defined in the target tenant (assignable options for a mapping) |
| `GET` | `/{targetTenantId}/groups` | List the groups defined in the target tenant (assignable options for a mapping) |
| `POST` | `/{targetTenantId}` | Create a new mapping in target tenant (direct role ids) |
| `POST` | `/{targetTenantId}/withGroups` | Create a mapping and make it a member of the given target-tenant groups (group-based role inheritance) |
| `POST` | `/{targetTenantId}/provisionCurrentUser` | Auto-provision current user with all roles |
| `DELETE` | `/{targetTenantId}/{mappingRtId}` | Delete a mapping in target tenant |

**`provisionCurrentUser` from a shadow user (AB#8017):** when the calling token's subject is a cross-tenant
shadow user (`xt_…`, e.g. a session or octo-cli context scoped to an intermediate tenant A that provisions into
grandchild B), the mapping is written for the caller's **home identity** — the root of its `xt_` chain
(`ICrossTenantShadowUserChainResolver.GetSourceChainAsync`, last tier), looked up by name in the home tenant — not
for the shadow user. Before, the mapping was keyed on (A, shadow); the exchange from the home token (what MCP and
octo-cli do for every later call) never finds such a mapping (`ResolveExchangeSourceAsync` only tries the subject
and its home, `GroupRoleResolver` only the B shadow's chain), so the call answered success and the user stayed
`tenant_not_provisioned`. One home mapping serves both paths: from the home token directly, and from the A shadow
(dual-candidate rule AB#4966). The exchange was deliberately **not** widened to ancestor shadow mappings. The
caller's name is taken from the user stored in its tenant (the token claim only when the user cannot be read). A
shadow whose chain is ambiguous or broken, whose home tenant is unregistered, whose home user does not exist or
whose home tenant is the target itself is refused with **409** (`ProblemDetails`, names the caller and says to
provision from the home tenant) and nothing is written — fail closed. The `OctoTenantIdentityProvider` is ensured
for the mapping's source tenant (the home tenant), as for a call from the home tenant. Old shadow-keyed mappings
stay (no migration); `provisionCurrentUser` from the home tenant adds the home mapping and repairs the exchange.
The response body (`SourceTenantId`/`SourceUserId`/`SourceUserName`) names the identity the mapping was written
for. Tests: `TenantExchangeIntegrationTests` (`ProvisionCurrentUser_AsShadowUserOfIntermediateTenant_…`,
`…_FromHomeTenant_RepairsTheStateOfAShadowKeyedMapping`, `…_ShadowUserWithoutResolvableHome_…`,
`…_ShadowUserOfAnUnregisteredTenant_IsRefused`), over the real `TenantExchangeProcessor.ExchangeAsync` for R → A → B.

The `sourceUsers` endpoint resolves the target's ancestor chain by walking
`RtOctoTenantIdentityProvider.ParentTenantId` (breadth-first, cycle-safe) and searches each ancestor's
`RtUser` by username OR email (case-insensitive substring), excluding `xt_` shadow users. It exists
because no other endpoint enumerates a parent tenant's directory — without it a picker had nothing to
bind to, so an admin literally could not select a parent-tenant user. `roles` reads the target tenant's
`RtRole` set directly via the system context (caller needs no `allowed_tenants` for the target).

The Studio's **Add User** dialog grants access **group-based** (the idiomatic Octo path — roles are
inherited through groups): it uses `groups` + `withGroups`, which makes the new mapping a `GroupMember`
of the selected groups — the same mechanism `provisionCurrentUser` uses with `TenantOwners`. The direct
`roles`/`POST` path (`MappedRoleIds`) remains for the CLI and role-level grants.

> **Note:** the *per-tenant* `ExternalTenantUserMappingsController.Create` (used by `octo-cli
> CreateExternalTenantUserMapping`) previously returned `CreatedAtAction(nameof(GetById), …)`, which
> threw "No route matches the supplied values" while formatting the 201 Location header (the entity was
> already stored) and surfaced as a 500. It now returns `Created(relativeSelfLink, dto)`. The
> `AdminProvisioningController.Create` was never affected — it already used `Created(string.Empty, …)`.
> `EmailDomainGroupRulesController.Create` had the same bug (`CreatedAtAction(nameof(GetByIdAsync), …)`: MVC
> strips the `Async` suffix from action names, so no route matched). AB#6648 fixed it with a **named route**:
> `[HttpGet("{rtId}", Name = …)]` plus `CreatedAtRoute(name, new { tenantId, version, rtId }, dto)`, pinned by
> `EmailDomainGroupRulesCreateTests` (also with a trailing slash on the POST URL). **Rule for new create
> actions:** use a named route, not `CreatedAtAction` (breaks on the `Async` suffix) and not a hand-built
> `$"{Request.Path}/{id}"` (ignores `PathBase`, doubles a trailing slash). Pass `tenantId` and `version`
> from `RouteData.Values` explicitly: with `Asp.Versioning` and the `{tenantId:tenantId}/v{version:apiVersion}`
> prefix, link generation does not fill them in and answers "No route matches". The hand-built link in
> `ExternalTenantUserMappingsController.Create` predates this rule and still has those two weaknesses.

The `provisionCurrentUser` endpoint extracts `sub`, `preferred_username`, and `tenant_id` from the JWT, fetches all roles from the target tenant, and creates an `RtExternalTenantUserMapping` with all role IDs. It also adds the mapping as a member of the **TenantOwners** group (via `GroupMember` association), so the user inherits all roles through group membership. If a mapping already exists it is judged, not just returned (AB#7088): one that grants no effective role (no existing role in `MappedRoleIds`, none via a group) or carries a wrong `SourceUserName` (role lookup keys on the NAME, this lookup on the user id) is repaired in place; one that already grants a role is left alone. The `X-Provisioning-Outcome` response header reports `created` / `repaired` / `already-provisioned`. No login path stores a mapping any more (`FindOrCreateCrossTenantUserAsync(..., storeMappingIfMissing: false)`): the token exchange since AB#7088, the interactive cross-tenant login (`SignInCrossTenantUserAsync`) and the tenant switch since AB#8439 — a bare mapping counted as explicit provisioning and bypassed `AllowSelfRegistration=false`. Only an admin action creates a mapping.

The `GET` endpoint returns `ExternalTenantUserMappingDto` with a `GroupNames` field populated by querying inbound `GroupMember` associations for each mapping entity.

The **per-tenant** `ExternalTenantUserMappingsController` (`{tenantId}/v1/externalTenantUserMappings`, used by `octo-cli GetExternalTenantUserMappings` and `IdentityServicesClient`) also resolves `GroupNames` on `GetAll`/`GetById` via `IGroupStore.GetGroupNamesForExternalUserMappingAsync` (inbound `GroupMember` walk, mirrors the AdminProvisioning resolution). Before AB#4660 this controller left `GroupNames` empty, so a group-based grant looked like "no roles/groups" even though roles were inherited via the group. `IGroupStore` also exposes symmetric `AddMemberExternalUserAsync` / `RemoveMemberExternalUserAsync` (previously only user/client member add/remove existed).

### Group-Based Role Inheritance

Groups are organizational units that can be assigned roles. Users become group members and inherit all roles from their groups. Groups can be nested (groups within groups) for hierarchical role inheritance.

All group relationships (role assignments, user members, external user members, nested groups) are stored as **CK associations**, not as denormalized StringArray attributes. This is the idiomatic Octo CK approach for entity relationships.

**Association Roles** (defined in `ConstructionKit/associations/identity-associations.yaml`):
- `AssignedRole`: Links User or Group → Role (N:N)
- `GroupMember`: Links Group → User or ExternalTenantUserMapping (N:N)
- `ChildGroup`: Links parent Group → child Group (N:N)

Key components:
- **`RtGroup`**: CK type (`ck-group.yaml`) with attributes: `GroupName`, `NormalizedGroupName`, `GroupDescription`. Relationships via associations: `AssignedRole` → Role, `GroupMember` → User/ExternalTenantUserMapping, `ChildGroup` → Group
- **`IdentityAssociationConstants`**: Central constants for association role IDs (`AssignedRoleId`, `GroupMemberId`, `ChildGroupId`)
- **`IGroupStore`** / **`GroupStore`**: CRUD operations for groups plus association-based relationship management (role assignments, member users, member external users, child groups)
- **`IGroupRoleResolver`** / **`GroupRoleResolver`**: Resolves effective roles for a user by traversing group memberships recursively (max depth 10, cycle-safe)
- **`OctoUserStore`**: `GetRolesAsync` and `IsInRoleAsync` merge direct roles (via `AssignedRole` associations) with group-inherited roles — this is the critical path for JWT token role claims
- **`GroupsController`**: REST API at `{tenantId}/v1/groups` with full CRUD, role assignment, member management, and circular group prevention
- **`TenantOwners`** group: Default group provisioned in every tenant with all 10 default roles. Created by `DefaultConfigurationCreatorService` and `IdentityAssociationMigration` (migration 9→10)

Current identity schema (migration) version: `23` (migration 21→22 added the `RtOAuthAuthorization`/`RtOAuthToken` OpenIddict store types; 22→23 re-runs the full index update so abstract collection roots get their indexes, AB#5261). Current CK model version: `System.Identity-2.30.0` (2.30.0 = `User.DisableTwoFactor-1`, AB#7879, see below; 2.29.0 = the identity method declarations, AB#7773, see below; 2.28.0 = first ckLanguage 2 release with access modifiers, AB#7772, see below; 2.19.0–2.23.0 were ownership/runtime-state classifications, 2.24.0 added `DataPolicy.ProtectBlueprintLocked`, 2.25.0 the `Secret` identity-provider `ClientSecret`, 2.27.0 the `Secret` credential material of a user, see the sections below) — the 2.12.0→2.17.0 changes (verified-identifier directory AB#5122+) are additive schema needing no numeric migration; 2.17.0→2.18.0 REPLACED `RtUser.PreferredChannel` with `RtUser.PreferredChannelBindingId` (AB#5149 revision, binding-specific preference). The feature shipped the day before the replacement with no external consumers, so the old attribute was dropped without a migration — any stored kind-level values are simply ignored (users re-select).

### Tenant-owned attributes: a blueprint update never reverts an administrator's decision (AB#6324, AB#6329; System.Identity 2.23.0)

A blueprint update imports its seed with `ImportStrategy.Upsert` (a full ReplaceOne); the engine keeps an attribute only when its
ownership is not seed-owned. Audit AB#6317 (incident class AB#6310) found decisions an administrator takes in the product that were
seed-owned, so an update silently undid them. System.Identity 2.23.0 (minor, `ownership` change per `ck-semver-rules`; attribute ids,
types and defaults unchanged, no migration entry) marks them:

| Entity | Attribute | Ownership | Why |
|--------|-----------|-----------|-----|
| `DataPolicy` | `PolicyEnforcementMode`, `PolicyScope` | `TenantOwned` | Seeds ship AuditOnly / All; the administrator flips to Enforce / narrows to OwnedOnly. Reverting would silently switch authorization enforcement off. Not a credential, part of the tenant's definition, so an `ExportRt` carries it |
| `Client` (assignment overrides) | `System/Enabled`, `AllowedGrantTypes`, `AllowedScopes`, `AutoProvisionInChildTenants` | `TenantOwned` | An update must not re-enable a disabled client or widen narrowed access. `System/Enabled` is shared, hence an override, not a definition change |
| `Client` (assignment override) | `Secrets` | `Secret` | Credential hashes: kept on a re-apply, left out of an `ExportRt` |
| `ApiResource` (assignment override) | `Secrets` (`ApiSecrets`) | `Secret` | Introspection secret hashes, same decision as `Client.Secrets`. The Identity.Bootstrap seed writes the attribute (empty) on both seeded API resources, so it was seed-owned in effect (AB#6443, System.Identity 2.24.0) |
| `Resource` (inherited by `ApiResource`, `ApiScope`, `IdentityResource`) | `System/Enabled` | `TenantOwned` | Same as the client switch |

A fresh tenant still gets the seed values. **Consequence for blueprint authors:** a seed initialises these values on a new entity but can
no longer change them on an existing one (not even tighten a policy or a client) — ship a CK migration step or a documented manual step.
`ClientMirrorProvisioningService` writes mirrors with insert/replace, not `ImportRt`, so mirroring is unaffected. Regression tests:
`BlueprintOwnershipIntegrationTests` (real MongoDB; compiled ownership, shipped policy seed, Enforce over an AuditOnly seed, client,
secrets, resources).

### Credential material of a user is `Secret`: never exported, kept on a re-apply (AB#7766; System.Identity 2.27.0)

Audit finding H3: `User.PasswordHash`, `User.SecurityStamp` and `User.UserTokens` (the `UserToken` record holds the TOTP key and the
recovery codes in `Value`) were `SeedOwned`, so an `ExportRt` (export as template, tenant clone) carried them. They are now
`ownership: Secret` (definition level, `User` is their only assignment) and so is the `UserToken.Value` record member
(assignment override). The engine skips `Secret` in `RtEntityToTcDtoConverter` (shared by `ExportRtModelByQueryCommand` and
`ExportRtModelByDeepGraphCommand`) and keeps it on an Upsert. SeedOwned -> Secret is an ownership change: `octo-ckc ValidateVersion`
rates it **Minor**, ids, types and defaults are unchanged, no migration entry, still ckLanguage 1 (the access modifiers followed with 2.28.0, below).
**Consequence (only up to 2.27.0):** a tenant cloned with ExportRt/ImportRt under 2.27.0 carried its users without password and 2FA
material; they reset the password in the target tenant. **Since 2.28.0 `ImportRt` refuses users altogether** — there is no user
export/import any more; the supported ways are listed in octo-documentation `technologyGuide/identityService/users-and-roles.md`
§ *Moving Users to Another Tenant* (`#moving-users-to-another-tenant`): repository dump/restore, creating the users again, a
cross-tenant user mapping, external sign-in with self-registration. No blueprint seeds `System.Identity/User` (`BootstrapBlueprintSeed_DoesNotSeedUsers` guards it). A repository
dump is unaffected. Tests: `CredentialMaterialExportIntegrationTests` (real MongoDB; compiled ownership, converter output of a user
with hash/stamp/tokens, Upsert of a seed-shaped user keeps all three).

### Access modifiers on `RtUser`, first ckLanguage 2 release (AB#7772; System.Identity 2.28.0)

Closes accepted risk R13 (password hashes and security fields readable through generic GraphQL). `ckModel.yaml` is `ckLanguage: 2`; the
`User` assignments carry `access`:

| Access | Attributes |
|--------|------------|
| `Hidden` | `PasswordHash`, `SecurityStamp`, `UserTokens` (never in GraphQL output or input, never in an ExportRt; an import refuses them) |
| `MethodOnly` | `UserName`, `Email` (readable, changed only by a type method) |
| `ReadOnly` | `AccessFailedCount`, `LockoutEnd` (readable; importable; written by the identity service) |

`ConcurrencyStamp` does not exist in this model. All seven attribute definitions are `securitySensitive: true`, so the tightening is **Minor +
acknowledge** (row T7a of `docs/ck-semver-rules.md` in `octo-construction-kit-engine`: the one release that moves a classic model to
ckLanguage 2, once per model; entries in `compatibility.acknowledge`). The next release follows the normal rule (T7) again: loosening is Minor,
tightening another attribute is Major. Every existing type and record declares `derivable: Any` (the ckLanguage 2 default is `Model`; the flip
would be a Major of its own) - **declare it on every new type/record that should stay derivable elsewhere**.

**Identity's own writes are unaffected**: the access modifiers guard the generic GraphQL path and the *import-like* paths (ImportRt, blueprint
seed/update, migration Add/Update/Transform: `OCTO-CK139` for Hidden/MethodOnly). `OctoUserStore`, the cross-tenant provisioning and the
password/2FA flows write through `ITenantRepository` (`InsertOneRtEntityAsync`, `ReplaceOneRtEntityByIdAsync`), which is not guarded. No
identity seed, blueprint or migration writes these attributes (`BootstrapBlueprintSeed_DoesNotSeedUsers`). Code that must set one of them from
an import (a test seed, a tool) creates the user through the repository instead. Tests: `CredentialMaterialExportIntegrationTests` (compiled
access values, `OCTO-CK139` refusal per attribute, ReadOnly import still possible, repository writes of all seven attributes still work).

### Identity method declarations (AB#7773; System.Identity 2.29.0)

`User`, `Group`, `Client` and `DataPermission` declare their identity operations as CK methods (declarations only; the handlers and the
method host follow with AB#5672, AB#7774, AB#7776-AB#7780, the typed GraphQL mutations with F3.7). Until a handler is registered the gateway
answers `METHOD_HANDLER_NOT_AVAILABLE`; the REST API is unchanged. **Release the identity service with this model only when the handler
stories are merged.**

| Type | Methods (`-1`) | Roles |
|------|----------------|-------|
| `User` | `ChangePassword` (instance, `allowSelf`, no role), `ResetPassword`, `SetRoles`, `AddRole`, `RemoveRole`, `Merge` (handler AB#7778), static `CreateUser` (handler AB#7777); `DisableTwoFactor` since 2.30.0 (AB#7879) | `UserManagement` |
| `Group` | `AddMember`, `RemoveMember` (`memberKind` enum `GroupMemberKind` = `User`/`Client`, `memberId`), `SetRoles` | `UserManagement` |
| `Client` | `AddSecret` (result `sensitive`: the generated secret, shown once), `RemoveSecret` (by `secretValue`, REST parity) | `TenantManagement`, `UserManagement` |
| `DataPermission` | `GrantToRole`, `RevokeFromRole` | `UserManagement` |

Rules behind the shape (do not change them without reading this):
- **Roles = REST parity** (`IdentityApiAuthorizationPolicies`: `UserAdministrationRoles`, `TenantAdministrationRoles`). Every method declares
  `authorization.dataAccess: Write` explicitly (AB#7036; the effective default, so no SemVer change; it raises the model's `minEngineVersion`).
- **`sensitive` on every password or secret parameter** (`currentPassword`, `newPassword`, `password`, `secretValue`) and on the `AddSecret`
  result; such a method can never have a pipeline handler (compiler messages 132/134). Pinned by `IdentityMethodDeclarationsIntegrationTests`.
- **`Create` is a reserved method name** (compiler error 102: `Create`, `Update`, `Delete` belong to the generic mutations) - the static user
  method is `CreateUser-1`.
- **`replacesGenericCreate` only on `User.CreateUser-1` (3.0.0, AB#8053).** Group, Client and DataPermission are seeded by
  `System.Identity.Bootstrap` (the flag would make AB#7121 refuse every new tenant), so they do not carry it. On `User` the flag is a
  **MAJOR** change of the model (row M16 of `docs/ck-semver-rules.md` in octo-construction-kit-engine: a new method with the flag on an
  existing type, decision 2026-10-19) and shipped with System.Identity 3.0.0; until 2.30.0 the engine stood in for it with a runtime rule
  (AB#7777), which was removed. No blueprint seeds a User.
- **No `LAST_ADMIN_PROTECTED`**: the REST API has no last-admin rule (AB#7914 refuses it with `METHOD_FORBIDDEN` / `last-administrator`). `User.DisableTwoFactor-1` followed in 2.30.0 (AB#7879, section below).
- `compatibility.acknowledge` of 2.28.0 is gone (an acknowledgement is valid for one release, OCTO-CK204). `octo-ckc ValidateVersion`
  against the published 2.28.0: **MINOR** (15 additions, no Major row).
- Tests: `IdentityMethodDeclarationsIntegrationTests` (compiled model from the CK cache of a real tenant: method set, roles, sensitive
  parameters and result, write access, no replacesGenericCreate). Docs: octo-documentation `identityService/methods.md` (en + de).

### CK method host of the identity service and `User.ChangePassword` (AB#5672)

The identity service hosts CK methods as a remote handler (bus transport, SDK `Meshmakers.Octo.Services.Methods`). All of it lives in
`src/IdentityServices/Methods/`; a later handler story (AB#7776-AB#7780; `User.ResetPassword` AB#7774 is the second one, section below) adds a handler class and **one row** to
`IdentityMethodHost.Handlers` (method id constant of `SystemIdentityCkIds`, handler type, `CarriesSecret`, `b => b.Handle<T>(id)`) - nothing else.

- **Host setup** (`IdentityMethodHost`, called once from `Program.cs` after `AddOctoIdentityPersistence`): `AddCkMethodHandlers("IdentityService", ...)`,
  `AddCkMethodHandlerDiscovery()` in the event hub configuration, and `AddCkMethodCallerTokenValidation()` with the authority of this service
  (`Identity:AuthorityUrl`, issuer with trailing slash; `Methods:Token` can override; Development accepts the self-signed local authority). The host
  validates the forwarded access token before the handler runs (a call without a valid token is `METHOD_FORBIDDEN`) and hands the validated caller
  as `context.CallerPrincipal`. Without any selected handler nothing is hosted (no queue, no announcement, no token validation requirement); since AB#7776 the role methods
  carry no secret and are always selected, so the host runs in every configuration and only the password methods wait for the switch.
- **Production gate `Methods:Identity:EnablePasswordMethods`** (default **false**, env `OCTO_Methods__Identity__EnablePasswordMethods`, Helm value
  `services.identity.methods.enablePasswordMethods` in the octo-helm-core `octo-mesh` chart, set per cluster in octo-mesh-deployment
  `clusters/<c>/values-octo-mesh.yaml` (AB#8603: test-2 on; staging-1, prod-1, prod-2 off until Gerald's go per cluster)): decided by Gerald 2026-10-23, no method carrying a password or secret on staging-1, prod-1,
  prod-2 before B0 (restricted broker user, Heimdall). **The switch controls the bus only** (AB#8413). Off: handlers whose registration has
  `CarriesSecret = true` are not offered on the bus, the service announces no password method and the gateway (GraphQL) answers
  `METHOD_HANDLER_NOT_AVAILABLE`; the rows with `ServesRestFacade = true` (`User.CreateUser`, `User.ResetPassword`, since AB#8414 also
  `User.ChangePassword`, `User.SetPassword`) are registered **local only** (`HandleLocalOnly`, `IdentityMethodHost.SelectLocalOnlyHandlers`: no
  announcement, no queue) so their REST facades `POST users`, `POST users/ResetPassword`, `api/manage/change-password` and `set-password` keep
  working in-process; the client secret methods stay unregistered. On (local, test-2 with
  test accounts): all offered on the bus (and called in-process by the facades).
  `IdentityMethodDeclarationsIntegrationTests.EveryHandlerRegistration_FlagsASecretCarryingMethod_AsTheModelDeclaresIt` compares every
  `CarriesSecret` with the compiled model (a sensitive parameter or result), so a new handler cannot pass the gate by a forgotten flag.
  The switch is read while the service collection is built: restart the service after changing it.
- **Startup validation tenant.** The SDK (octo-common-services, AB#7912) normalizes the tenant id of the start-up validation to the lower case CK
  cache key, so a default installation (`SystemTenantId` = `OctoSystem`) validates its methods without configuration; `IdentityMethodHost` sets no
  `Methods:ValidationTenantIds` any more (the AB#5672 workaround was removed). Needs the common-services package of AB#7912 or newer.
  `TheStartupValidation_NeedsNoIdentityWorkaround_WithTheDefaultConfiguration` pins that the host adds nothing. On a rolling upgrade the System.Identity model of
  the system tenant must already be the embedded version when the validation runs; the identity setup imports it first.
- **Tenant on the bus.** A handler has no HTTP request, but every store resolves its tenant through `IMultiTenancyResolverService`. The handler calls
  `IMethodTenantAccessor.BindAsync(context.TenantId)` **before** it resolves `UserManager`, the stores or `IUserCredentialChangeService` from its scope
  (it takes `IServiceProvider` for exactly that reason); `MethodTenantResolverService` answers with the bound tenant and falls back to the HTTP
  resolution when none is bound (HTTP requests are unchanged). Never resolve a store in a handler constructor.
- **`User.ChangePassword`** (`UserChangePasswordHandler`): self only. The declared authorization (`allowSelf`, no role) also admits an administrator for any
  target (default-deny rule of the SDK), so the handler requires `CallerPrincipal.SubjectId == TargetRtId` itself and answers `METHOD_FORBIDDEN`
  (`reason=not-self`) **before** any lookup: identical for an existing and a missing target, for another user, for an administrator and for a service
  token (administrators use `ResetPassword`). Order: tenant, user, shadow user (`SHADOW_USER_PASSWORD_NOT_ALLOWED`), lockout (`USER_LOCKED_OUT`),
  `UserManager.ChangePasswordAsync` (wrong current password = `CURRENT_PASSWORD_INVALID`, counted with the atomic lockout counter of AB#7854;
  policy failure = `PASSWORD_POLICY_VIOLATION` with one detail per failed rule, code only e.g. `PasswordTooShort`, never a value), counter reset, then
  `IUserCredentialChangeService.OnPasswordChangedAsync(..., PasswordChangePath.MethodChangePassword, ...)` (security stamp, revocation of all refresh
  tokens and authorizations of the user in this tenant, log line; AB#7765). A failing revocation throws, the caller gets `METHOD_HANDLER_FAILED`.
  REST: `ManageApiController.ChangePassword` is its facade since AB#8414 (section "Account pages run the password methods").
- **Audit.** `IdentityMethodAuditWriter` writes one event per call (success and failure) into the event log of the tenant (category `Identity.Method`,
  details `methodId`, `invocationId`, `outcome` (`SUCCESS` or the error code), `targetRtId`, `callerSubject`; no parameter, no hash, no token). It is
  not `IIdentityAuditService` (that one reads the tenant from the HTTP request and persists failures only). The gateway-side one-per-invocation record
  `Method.Invocation` of AB#6919 (`ICkMethodAuditRecorder`) is written where a call is dispatched (the SDK's remote host does not run the pipeline); it is a different category.
- **Secrets.** `currentPassword` / `newPassword` are only passed to `UserManager`; the generated parameter record prints `***`. Never log or audit the
  parameters or `context.Parameters`.
- **Tests:** `Api/Methods/UserChangePasswordMethodTests` (real MongoDB and identity host with the switch on; the bus side (endpoints, announcement) is removed in the test host
  because it has no broker): success with new/old sign-in and revocation, wrong current password, lockout, policy, other user / missing target / service token
  / administrator, shadow user, forged caller without a valid token, method without handler; `Methods/IdentityMethodHostTests` (switch default and
  selection, audit). A valid-token call through the real bus is verified on the local stack (see the PR of AB#5672).

### User role methods `SetRoles`, `AddRole`, `RemoveRole` (AB#7776)

`UserSetRolesHandler`, `UserAddRoleHandler`, `UserRemoveRoleHandler` (`src/IdentityServices/Methods/`, shared flow in `UserRoleMethodHandlerBase<T>`) replace
or change the **direct** roles of a user (the `AssignedRole` association; roles inherited from groups are never read or written, as in REST). The rule is
**REST parity, never more**; the guards of `UsersController` (`PUT users/{u}/roles`, `PUT/DELETE users/{u}/roles/{r}`) are, and the handlers implement exactly this list:

| Guard of REST | In the method |
|---------------|---------------|
| write policy: scope `octo_api` (not `octo_api.read_only`) and tenant role `UserManagement` (`IdentityUserAdministrationWritePolicy`, `RoleEnforcement=Enforce`) | gateway checks the declared role; the handler checks scope + role again on the validated `CallerPrincipal` (forged bus message) -> `METHOD_FORBIDDEN`, `reason=role-required`. Warn mode of REST is not copied |
| user must exist (404) | `METHOD_TARGET_NOT_FOUND` (also for a target that is no object id and for an unknown tenant) |
| role must exist, by name, case-insensitive (404) | `ROLE_NOT_FOUND` with parameter `roleName` |
| AddRole of an assigned role (400) | `ROLE_ALREADY_ASSIGNED` |
| RemoveRole of a role that is not assigned (400) | `ROLE_NOT_ASSIGNED` |
| client-credentials tokens are judged by their client roles | a service token with `UserManagement` is allowed |

Since AB#7914 REST and the methods share the escalation rules of `IRoleChangeGuard` (next section); before it REST had no other rule and the methods copied that.
`SetRoles` takes role **names**, REST takes ids; both resolve every role first (one unknown role changes nothing) and write only the difference (AB#7914; REST used to remove all direct roles first).

Audit: the `Identity.Method` event of every call (success and every refusal, `IdentityMethodAuditWriter`) additionally carries `rolesBefore` and `rolesAfter`
(direct role names, sorted, comma separated; absent when the caller was refused before the target was read). Role methods are not behind
`Methods:Identity:EnablePasswordMethods` (`CarriesSecret = false`; the model-vs-registration test guards the flag). Tests: `Api/Methods/UserRoleMethodTests`
(every guard, case/duplicates, empty list, audit, forged caller, hosting), `UserRoleMethodParityTests` (REST and method side by side per guard, the
documented difference, self grant), `IdentityMethodHostTests`. The integration test factory removes the bus side of the method host
(`CkMethodHandlerStartupService`, heartbeat) because the test host has no broker.

### Role change guard: no escalation, last administrator stays (AB#7914)

`IRoleChangeGuard` (`src/IdentityServices/Authorization/RoleChange/RoleChangeGuard.cs`, scoped) is the one rule set for changes of the **direct** roles of a
user. Callers: `UsersController` (`DELETE users/{u}`; since AB#8412 the role endpoints and `POST users/{u}/merge` run the methods, section
"REST facades of the role and merge endpoints"), the three role method handlers (`UserRoleMethodHandlerBase.GuardAsync`) and `IUserMergeService` (source user). It is **never** called from `OctoUserStore`/`UserManager`: first admin of a new tenant
(`UserManagementService`), the Bootstrap blueprint seed, the one-time grants (`SecretManagementAdminGrant`, file role grants), the scratch-tenant creator grant, cross-tenant
provisioning and the login group rules assign roles through the store and stay unrestricted (`TheGuard_IsNotCalledFromTheUserStoreOrTheUserManager…` pins the constructors).
AB#7927 (groups, mappings, role definitions, next section) and AB#7928 (client roles, section below) reuse it: `EvaluateGrantAsync(caller, addedRoleNames)` is the "grant only what you hold" part alone.

| Rule (checked in this order, on the **difference** before/after, never on the full list) | REST | Method (`METHOD_FORBIDDEN`, parameter `reason`) |
|---|---|---|
| `self-grant`: caller `sub` == target rtId and a direct role is **added** (removing own roles and an unchanged list are fine) | 403 problem+json, `code` | `self-grant` |
| `role-not-held`: an added **built-in** role (stored `RtWellKnownName`) is not in the caller's role claims; custom roles are free; removing is never judged. Since AB#8564 a caller holding `UserManagement` is refused only for **platform** roles; **app** roles are free for it (section "App roles and platform roles" below) | 403, `code`, `roleNames` | `role-not-held` + `roleNames` (comma separated) |
| `last-administrator`: the target effectively holds `UserManagement` now, not after the change, and **no other user** holds it (direct, through groups incl. nested, `xt_` shadow users through mappings via `IGroupRoleResolver`; **clients do not count**; a tenant with zero holders is not blocked) | 409, `code` | `last-administrator` |

- **Caller** = `RoleChangeCaller` (`sub`, `client_id`, `role` claims of the validated token; for methods the validated `CkMethodPrincipal`, never the informational `Caller`).
  A client-credentials caller has no `sub`: never self for a **user**, judged with the client's roles; since AB#8569 it is self for its **own client**
  (section "Client-credentials callers are self for their own client" below). No exemption for services (none calls these endpoints).
- **No CK change.** Error contract is `METHOD_FORBIDDEN` + `reason` (`CkMethodOutcome.Forbidden`); a new declared code would be a Major of System.Identity.
  REST answers `application/problem+json` (`RoleChangeProblems`, `code` extension, readable `title` that Studio shows). Hard switch, no warn mode.
- **Audit.** Methods: the existing `Identity.Method` event carries `reason` (+ `roleNames`). REST: one failure event `Identity.RoleChangeRefused` through
  `IIdentityAuditService` (caller, target rtId, reason, role names, request path; never a token or password) plus a WARN log.
- **REST SetRoles** validates every role id first (404 changes nothing; it used to strip the direct roles first) and writes only the difference.
- **Residual race:** two administrators removing each other's `UserManagement` in parallel can both pass the check (no cross-request lock); documented.
- The last-administrator search is only run when the target loses `UserManagement`: direct holders, members of groups whose subtree carries the role, then (rare path) every `xt_` user
  through `IGroupRoleResolver`.
- **Tests:** `Api/TenantApi/RoleChangeGuardTests` (every rule through REST and through the method handlers with the same assertions: self-grant, held/not held/custom, difference,
  client caller, last administrator direct/group/nested group/mapping/client-not-counted/zero holders, delete + merge, audit records), `UserRoleMethod*Tests` (updated parity),
  `RoleChangeCallerTests`. The tests that need "exactly one administrator" first remove every holder of the test database (`ClearAdministratorsAsync`).

### App roles and platform roles (AB#8564)

Tenant owners could not hand out the roles their own blueprints seed (e.g. `EnergyCommunityManagement` of EnergyCommunity.Base):
`role-not-held` judged every built-in role alike. Decision by Gerald (2026-11-08): holders of `UserManagement` may grant **app roles**;
**platform roles** keep the AB#7914 protection.

- **Platform role** = a built-in role (stored `RtWellKnownName`) that `System.Identity.Bootstrap` seeds (today the 17 roles of
  `seed-data/roles.yaml`: `TenantManagement`, `UserManagement`, `StreamDataAdmin`, `SecretManagement`, `DataModelManagement`, …).
  **App role** = every other built-in role, i.e. one a blueprint installed in the tenant seeds. Custom roles (no `RtWellKnownName`) stay free for everybody.
- **How the service knows.** `IPlatformRoleCatalog` / `BootstrapPlatformRoleCatalog` (`Authorization/RoleChange/PlatformRoleCatalog.cs`, singleton) reads the
  seed files of the **embedded** Bootstrap blueprint (`IBlueprintEmbeddedSource` of `System.Identity.Bootstrap`, the same resources the service applies to every
  tenant) once and collects `rtWellKnownName` and `rtId` of every `System.Identity/Role` entity. A role matches by either. No hand-kept name list: a role added to the
  Bootstrap seed is a platform role with the same build. **Fail closed:** when no role can be read, every built-in role counts as a platform role (the old rule) and an
  ERROR is logged. The engine stores no per-entity blueprint ownership (`BlueprintInstallation` has none), so the seed is the reliable source.
- **Rule** (`RoleChangeGuard.EvaluateGrantCoreAsync`, used by direct user roles, client roles, group roles, group membership, group nesting and mappings): an added
  built-in role the caller does not hold is allowed when the caller holds `UserManagement` **and** the role is not a platform role; otherwise `role-not-held`.
  A group (or nested group tree) with app **and** platform roles needs only its platform roles held; the refusal lists only those. `self-grant` and
  `last-administrator` are unchanged and still win (a tenant owner cannot add themselves to an app-role group). Callers without `UserManagement` get no relaxation.
  The data-policy protection of AB#5859 (`identity.administration`) is untouched.
- **Log.** Refusals are unchanged (WARN + `Identity.RoleChangeRefused`). An allowed grant of app roles the caller does not hold writes one INFO line
  `Role change allowed (app-role-grant): caller …, target …, app roles [...]` (`RoleChangeDecision.AppRolesNotHeld`); it is written only when the whole change is allowed.
- **Tests:** `Api/TenantApi/AppRoleGrantTests` (REST, real MongoDB, production catalog: direct grant to client and user, group membership, group roles, nesting, each with
  app role / platform role / mixed group, caller with and without `UserManagement`, self-grant still refused), `Authorization/RoleChangeGuardAppRoleTests` (rule and INFO log),
  `Authorization/PlatformRoleCatalogTests` (the 17 seed roles, app roles, rtId match, fail closed). The older guard tests create many distinct "built-in" roles; in the test host a
  role whose `rtWellKnownName` starts with `platform-` counts as a platform role (`Infrastructure/TestPlatformRoles.cs`), so those AB#7914/7927/7928 tests keep judging platform roles.

### Client-credentials callers are self for their own client (AB#8569)

A client-credentials client holding `UserManagement` (e.g. through `TenantOwners`) could add itself to `EnergyCommunityOperators` with its own token
and gain the app role: `self-grant` only knew user sessions. Decision by Gerald (2026-11-08): the self-grant block holds for app roles too
(four-eyes principle); a user administrator may grant app roles to others, never to themselves. The rule mirrors the user path, no new rule:

- **Who is self.** `RoleChangeCaller.SelfClientId` = the `client_id` of a token **without** `sub` (client credentials; an impersonated token carries the target's
  `client_id` and roles, so the target is self). A user session also carries a `client_id` (the application it signed in with); that client is not the user and is
  never self. The guard maps the id to the client of the tenant (`IOctoClientStore.FindRtClientByIdAsync`) and compares group members by rtId **and** by OAuth client id.
- **Judged like a user on its own user:** direct client roles (`PUT clients/{id}/roles`, `PUT clients/{id}/roles/{role}` through `EvaluateClientGrantAsync`:
  self-grant first, then the grant rule), group membership (`MemberAdded` of its own client, REST and `Group.AddMember`), a role added to a group its client reaches
  (`GroupRoles`, directly or through a parent group, REST and `Group.SetRoles`) and a group nested into such a group (`MemberAdded` of kind group); the walk is
  `RoleGraph.GroupsReachingClient`, the same as for users and as `GroupRoleResolver`. Answer and audit are those of the user path (`403 self-grant`, `METHOD_FORBIDDEN`
  + `reason=self-grant`, WARN `caller client <id>` + `Identity.RoleChangeRefused`). The `title` text still says "your own user" (shared with the user path).
- **Free:** removing its own roles or memberships, granting to other clients and users (AB#8564 unchanged), and every path that does not call the guard: the bus
  path (`DistClientDto.AssignedRoleNames`, pipeline service accounts of the communication controller), Bootstrap seed, setup, the scratch-tenant creator grant
  (`TenantOwners`), cross-tenant provisioning.
- **Consequence:** a scratch-tenant creator client (`Create --scratch`, member of `TenantOwners`) can no longer give itself an app role a blueprint seeds later;
  a user administrator or another client grants it.
- **Tests:** `Authorization/RoleChangeGuardClientSelfTests` (unit: membership by rtId and client id, group roles direct and nested, nesting, other client,
  removal, user session with the same `client_id`, direct client grant), `Api/TenantApi/AppRoleGrantTests` region "Client self-grant (AB#8569)" (REST) and the
  `*_AB8569` cases of `Api/Methods/GroupMethodTests`.

### Role change guard on groups, mappings and role definitions (AB#7927)

`IRoleChangeGuard` (above) also judges the group / mapping graph and role definitions, with the same reasons, status codes and audit
(`Identity.RoleChangeRefused`, written by `IRoleChangeRefusals`, scoped, used by the three controllers):

| Caller | Check |
|---|---|
| `GroupsController`: `PUT groups/{id}/roles`, `PUT members/users/{u}`, `PUT members/clients/{c}`, `PUT members/groups/{g}`, `DELETE members/users/{u}`, `DELETE members/groups/{g}`, `DELETE groups/{id}` | `EvaluateAsync(caller, RoleGraphChange)` (`GroupRoles`, `MemberAdded`, `MemberRemoved`, `GroupDeleted`). `DELETE members/clients/{c}` is not judged (nothing is granted, clients are no administrators); the scratch-tenant revoke marker stays |
| `ExternalTenantUserMappingsController`: create, update, delete | `MappingRoles` (existing id, or the source identity of a new mapping), `MappingDeleted` |
| `RolesController`: `PUT roles/{name}` with another name, `DELETE roles/{name}` | `EvaluateRoleDefinition(role, newName)`: a role with an `rtWellKnownName` answers 409 `built-in-role` (+ `roleNames`); custom roles and a same-name save are untouched |

- **One graph, one rule.** `RoleGraph` (`Authorization/RoleChange/RoleGraph.cs`, internal) loads groups (roles, child groups, user / client / mapping
  members), mappings (mapped role ids), all users, the mappings serving each `xt_` shadow user and the direct holders of `UserManagement`. A change is applied to a
  clone and `Holders()` (direct + groups incl. nested (depth 10, cycle safe) + mapping roles + groups of a mapping; existing **users** only, clients excluded)
  is compared before and after: refused (409) when holders existed and none is left. A tenant without holders is not blocked. Cost: one read of all groups,
  mappings and users per change (the 7914 check read the same data).
- **Granted roles** = for `GroupRoles` the added role ids, for `MemberAdded` the effective roles (own + nested) of the group (for a child group: of the child), for
  `MappingRoles` the added mapped role ids; a member that is already there grants nothing. **Self** = the caller is the added user, or the group whose roles
  grow (or the group a child is added to) is reached by the caller (member directly, via a mapping that serves it, or a parent group of it), or the mapping serves the
  caller (for a new mapping its source identity is in the caller's `xt_` chain). Since AB#8569 a client-credentials caller is self the same way for its own client
  (the added client, or a group its client reaches directly or as a parent group). Self wins over `role-not-held`; roles are resolved to names and judged with
  `EvaluateGrantAsync` (built-in only). Group create with roles is not judged (it has no members); the roles take effect only through a judged member add.
- **Not guarded on purpose:** `GroupStore`/`ExternalTenantUserMappingStore` and everything that uses them directly: Bootstrap seed, setup, scratch-tenant grant,
  cross-tenant provisioning (`AdminProvisioningController`), `LoginGroupAssignmentService`. Group methods (AB#7779) call `EvaluateAsync(caller, RoleGraphChange)`
  and answer `METHOD_FORBIDDEN` with the `reason`; direct client roles: AB#7928 (next section but one).
- **Tests:** `Api/TenantApi/GroupRoleChangeGuardTests` (REST on real MongoDB: self-grant direct / via parent / via child / via mapping, role-not-held for roles, members,
  clients, nested groups, mappings, idempotent re-add, last administrator for member removal, role removal, delete, child group, mapping update / delete, mapping-in-group,
  clients not counting, built-in role rename / delete, audit record, unchanged flows) and `Authorization/RoleGraphTests` (holders, clone, cycle, references).

### Role change guard on client roles (AB#7928)

A tenant administrator (`TenantManagement` is enough for the client endpoints) could give a client a built-in role they do not
hold (e.g. `UserManagement`) and then act as that client. `ClientsController` therefore runs the "grant only what you hold" part of
`IRoleChangeGuard` (`EvaluateGrantAsync`) before it writes a client role:

| Endpoint | Judged | Refusal |
|---|---|---|
| `PUT clients/{id}/roles` (replace-all, role ids) | every role id is resolved first (unknown or malformed id = 404, nothing written; it used to write the edge blindly); the **added** roles (not in the client's direct roles). Only the difference is written (`IClientRoleStore.ApplyRoleChangesAsync`), never the kept roles | 403 problem+json `code=role-not-held`, `roleNames` |
| `PUT clients/{id}/roles/{roleName}` | the role; a role the client already holds directly is answered 200 without a write | same |
| `DELETE clients/{id}/roles/{roleName}` | never (removing is no escalation) | - |

- **Built-in roles only** (stored `RtWellKnownName`); custom roles are free. No last-administrator rule for clients (clients are no
  administrators, AB#7914 decision 2). Since AB#8569 the self-grant rule applies to a client-credentials caller changing its own client
  (`EvaluateClientGrantAsync`, section below). The caller is the token (`RoleChangeCaller.FromPrincipal`): user or client-credentials token, judged with its own
  role claims. Hard switch, no warn mode.
- **Audit:** `IRoleChangeRefusals` writes the WARN line and the `Identity.RoleChangeRefused` event (caller, `client <clientId>`, reason, role names), as for groups.
- 🔴 **Write only what was judged.** `SetRoleIdsAsync` (replace-all) re-reads the assignments in its own transaction and inserts every missing
  wanted role. Used after the check, a role that a concurrent request removed between the check and the write would be restored by a caller who does
  not hold it (review finding on #224). The controller therefore writes only the judged additions and the removals; kept roles are never written.
  `SetRoleIdsAsync` stays for internal callers. Pinned by `ClientsControllerRoleGuardTests` (unit) and
  `ClientRoleAssignmentIntegrationTests.ApplyRoleChanges_WritesOnlyTheGivenDifference_AndNeverRestoresAnUnlistedRole`.
- **Not guarded on purpose:** the bus path (`CreateIdentityDataCommandRequestConsumer`, `DistClientDto.AssignedRoleNames`: service accounts and
  client mirroring between services, no caller) and `IClientRoleStore` itself; client mirrors get no roles anyway. Granting a client roles through
  a group (REST `PUT groups/{id}/members/clients/{c}`, method `Group.AddMember` with `memberKind=Client`) was already judged by AB#7927 / AB#7779.
- **No client role method exists** in System.Identity 2.29.0 (`Client` declares only `AddSecret` / `RemoveSecret`, AB#7780); the method transport for
  client roles is `Group.AddMember`. No CK change.
- **Tests:** `Api/TenantApi/ClientRoleChangeGuardTests` (REST on real MongoDB: not held / held / custom for both endpoints, `TenantManagement` without
  `UserManagement` cannot grant `UserManagement`, difference only, client-credentials caller, unknown / malformed id, audit record, guard not on the bus
  or store path), `ServiceAccountClientProvisioningIntegrationTests.BusPath_StillAssignsABuiltInRole_WithoutTheRoleChangeGuard`,
  `GroupMethodTests.AddMember_AClientIntoAGroupWithABuiltInRoleTheCallerLacks_IsRefused_RoleNotHeld` (method transport).

### First administrator is a member of TenantOwners (AB#7946)

`UserManagementService.CreateAdminUserAsync` (setup endpoints `setup/create-admin` and `v1/setup`) grants the first administrator the 13 direct roles and, since AB#7946,
also adds that user to the `TenantOwners` group (`AddToTenantOwnersAsync`, via `IGroupStore`). `TenantOwners` carries every non-secret built-in role (incl. `DataModelManagement`,
`StreamData*`), which the direct grants lack; without the membership the administrator holds fewer roles than the group and the guard above refuses adding anyone to it
(`role-not-held`). `SecretManagement` stays a direct grant only (not in `TenantOwners`). The step is idempotent (an existing membership is not added again; a setup
re-run is refused anyway while users exist) and optional like the file roles: a tenant without the group logs a warning and keeps the direct roles. The setup goes
through the stores, not the guarded controllers, on purpose. The scratch-tenant creator (`ScratchTenantGrantService`) and cross-tenant admin provisioning
(`AdminProvisioningController`) already put their subject into `TenantOwners`; nothing changed there.
Since AB#8529 the direct-role fallback (tenant without `TenantOwners`, `AddDirectAdministratorRolesAsync`) also grants `DataModelManagement`: the asset
repository's `DataModelManagementPolicy` requires that role for `ImportCk`, catalog imports, `FixAll`, blueprint install/update/uninstall and catalog
refresh, so a fallback administrator would otherwise be locked out of every data model change. `TenantOwners` already carries the role (bootstrap seed,
role `66…0B`), so no seed bump is needed.

- **Tests:** `UserManagementServiceTests` (membership added / not twice / missing group) and `Api/Setup/SetupAdminTenantOwnersTests` (real MongoDB: setup via REST, the admin adds
  another user to `TenantOwners`, control case without the membership = 403 `role-not-held`, re-run refused without a second edge, guard not injected into setup/group store).

### `User.ResetPassword` (AB#7774)

`UserResetPasswordHandler` (`src/IdentityServices/Methods/`, one row in `IdentityMethodHost.Handlers`, `CarriesSecret = true`: offered on the
bus only with `Methods:Identity:EnablePasswordMethods`, off = `METHOD_HANDLER_NOT_AVAILABLE` for the gateway; `ServesRestFacade = true`: local
only while the switch is off, for the REST facade `POST users/ResetPassword`, AB#8413). A user administrator (`UserManagement`) sets a new password
without the current one.

- **Caller.** The SDK evaluates the declared role before the handler; the handler checks `CallerPrincipal.Roles` for `UserManagement` again
  (defense in depth, `METHOD_FORBIDDEN` / `missing-role`) **before** the tenant is bound or the target is looked up, so an unauthorized caller gets the same answer
  for an existing and a missing target and `METHOD_TARGET_NOT_FOUND` is only seen by an authorized one. Service tokens with the role are allowed
  (actor `client <id>`, the `AuditActor` form; a user caller is named by the user name looked up from `sub`). A user without the role cannot reset their own password with it (`ChangePassword` is for that).
- **Order.** role, tenant, user, shadow user (`SHADOW_USER_PASSWORD_NOT_ALLOWED`), remember `IsLockedOutAsync`, `GeneratePasswordResetTokenAsync` +
  `ResetPasswordAsync` (policy failure = `PASSWORD_POLICY_VIOLATION`, codes only, **nothing else changes, the lockout stays**), then
  `SetLockoutEndDateAsync(user, null)` + `ResetAccessFailedCountAsync(user)` through `UserManager` (guarded, versioned store write of AB#7908; never write the user
  entity directly), then `IUserCredentialChangeService.OnPasswordChangedAsync(..., PasswordChangePath.MethodResetPassword, <caller user name>)` (security
  stamp, revocation of refresh tokens and authorizations; throws on failure = `METHOD_HANDLER_FAILED`).
- **REST difference** (`UsersController.ResetPassword`; since AB#8008 body-only, see "No credential values in request URLs"): REST does **not** lift the lockout and e-mails a second reset token; the method lifts
  the lockout and sends **no** e-mail (AB#7775 adds the notification).
- **Audit.** `IdentityMethodAuditWriter.RecordAsync(..., extraDetails)`: one `Identity.Method` event per call in a `finally` (success, every failure, and an
  exception as `METHOD_HANDLER_FAILED`), details as `ChangePassword` plus `lockoutLifted` (`true` only when the user was locked out at call time and the call succeeded).
- **Tests:** `Api/Methods/UserResetPasswordMethodTests` (real MongoDB; event repository and logger captured: locked-out user end to end, counter-only user,
  service token, missing role for existing and missing target, unknown target, policy violation, shadow user, failing revocation, forged caller on the host;
  password canary never in audit events or logs), `IdentityMethodHostTests` (switch, audit details).

### Group and data-permission methods (AB#7779)

`Group.AddMember`, `Group.RemoveMember`, `Group.SetRoles`, `DataPermission.GrantToRole`, `DataPermission.RevokeFromRole` (declared in System.Identity 2.29.0,
no model change). Five handlers in `src/IdentityServices/Methods/` (`GroupMemberMethodHandlerBase<T>` with `GroupAddMemberHandler` / `GroupRemoveMemberHandler`,
`GroupSetRolesHandler`, `DataPermissionRoleMethodHandlerBase<T>` with `DataPermissionGrantToRoleHandler` / `DataPermissionRevokeFromRoleHandler`) and five rows in
`IdentityMethodHost.Handlers`, all `CarriesSecret = false` (hosted whatever `EnablePasswordMethods` says). Shared flow in `IdentityAdminMethodHandlerBase<T>`
(caller rule, target id, tenant binding, one `Identity.Method` event per call in a `finally`); `IdentityMethodCallerRules.IsAdministrator` is the same rule the
user role handlers use (scope `octo_api` + role `UserManagement` on the **validated** principal, `METHOD_FORBIDDEN` / `role-required` otherwise).

| Rule | REST (`GroupsController`, `DataPermissionsController`) | Method |
|------|------|------|
| Caller | `IdentityUserAdministrationWritePolicy` | the same, repeated on the validated principal; forged bus caller rejected by the host |
| Target | 404 for an unknown group (data permission: unhandled exception) | `METHOD_TARGET_NOT_FOUND` |
| Guard (AB#7927) | `IRoleChangeGuard.EvaluateAsync(caller, RoleGraphChange.MemberAdded / MemberRemoved / GroupRoles)`: `self-grant`, `role-not-held`, `last-administrator` (403 / 409 problem) | the same call with the same change records; refusal = `METHOD_FORBIDDEN` + parameter `reason` (+ `roleNames`), audited with `reason` |
| Client removal | no guard (a client gives nothing to anybody); records the scratch tenant revocation (AB#7192) before the removal | the same, same `IScratchTenantGrantService.RecordRevocationAsync` |
| Data permission grant / revoke | no guard (data access, not roles) | none either |
| Unknown or duplicate member / role | engine error 500 / silent no-op | typed errors `MEMBER_NOT_FOUND`, `MEMBER_ALREADY_IN_GROUP`, `MEMBER_NOT_IN_GROUP`, `ROLE_NOT_FOUND`, `PERMISSION_ALREADY_GRANTED`, `PERMISSION_NOT_GRANTED` (stricter, never more) |

- **Member ids.** `memberKind` User or Client; `memberId` is the rtId (as in the REST route); for a client the OAuth client id is accepted too. `Group.SetRoles`
  takes role **names** (the model's parameter) and resolves them to the role ids the guard judges (`GroupRoles(groupId, roleIds)`); all names are checked first
  (one unknown role changes nothing).
- **Referenced entities (AB#7035).** The target is checked by the gateway (`dataAccess: Write`). Members and roles the method touches besides the target are checked
  with `IRtDataPermissionEvaluator` (`IdentityMethodCall.EvaluateAsync`, the caller's `RtSecurityContext` from the validated principal): not visible = `MEMBER_NOT_FOUND` /
  `ROLE_NOT_FOUND`; `DataPermission.GrantToRole` additionally needs `Write` on the role (the grant is stored on it), refusal = `METHOD_FORBIDDEN` / `reason` = `data-permission`.
  Without enforcing policies on those types (the default) every check is open, as in REST.
- **Audit.** `Identity.Method` event per call (success, every refusal, exception as `METHOD_HANDLER_FAILED`): group methods add `memberKind`, `memberId`, `rolesBefore` /
  `rolesAfter` (role names, `SetRoles`) and `reason` / `roleNames` of a guard refusal; data permission methods add `permissionId` and `roleName`. Identifiers only.
- **Nothing is revoked.** A group change shows in the next token (`OctoTokenClaimsService` reads the effective roles, groups included), as with REST.
- **Tests:** `Api/Methods/GroupMethodTests` (all operations, every refusal, caller theory, forged caller, audit, evaluator), `GroupMethodParityTests` (REST and method side
  by side per guard), `DataPermissionMethodTests` (operations, errors, caller theory, forged caller, REST parity, audit, evaluator), `Methods/IdentityMethodHostTests`
  (selection). The last-administrator tests clear the administrators of the shared test database first, like `GroupRoleChangeGuardTests`.

### Client secret methods `Client.AddSecret`, `Client.RemoveSecret` (AB#7780)

`ClientAddSecretHandler` and `ClientRemoveSecretHandler` (`src/IdentityServices/Methods/ClientSecretHandlers.cs`, shared flow in
`ClientSecretMethodHandlerBase`), declared in System.Identity 2.29.0 (no model change), two rows in `IdentityMethodHost.Handlers`, both
`CarriesSecret = true` (AddSecret has a `sensitive` result, RemoveSecret a `sensitive` parameter): **gated by `Methods:Identity:EnablePasswordMethods`**
like the password methods (production gate of 2026-10-23, B0); off = `METHOD_HANDLER_NOT_AVAILABLE`.

| Rule | REST (`ApiSecretsController`, unchanged) | Method |
|------|------|------|
| Caller | `IdentitySecretAdministrationPolicy` since AB#5861 (`octo_api` + `SecretManagement`, staged: in `Warn` also `TenantManagement`/`UserManagement`) | the same, repeated on the validated principal (`DecideClientSecretCaller`) before the target is read: `METHOD_FORBIDDEN` / `role-required`, identical for an existing and a missing target; forged bus caller rejected by the host |
| Target | client id in the route, 404 | target rtId of the client; unknown, not an object id or unknown tenant = `METHOD_TARGET_NOT_FOUND` |
| Generate | 32 bytes CSPRNG, URL-safe Base64, stored as Base64 SHA-256 | the same (`ClientMirrorSecrets.GenerateSecret`, `OctoSecretHasher.HashSecret`), record `Type = SharedSecret`; the clear text is the result, returned once |
| Public client | accepted | `CLIENT_SECRET_NOT_REQUIRED` (it never authenticates with a secret) |
| Expiration in the past | accepted | `METHOD_VALIDATION_FAILED` (`field=expirationDate`) |
| Remove | by the stored value (Base64 in the route); 404 without the value (since AB#7989; before it, the delete removed nothing, see below) | by the stored value **or** the clear text (hashed, fixed-time compare); every match removed with `RemoveAll` (AB#7989); no match = `SECRET_NOT_FOUND` without parameters |
| Write | `IOctoClientStore.MutateAsync` (version-checked since AB#7989, mirror sync) + `CorsClientsUpdate` | version-checked read-modify-write of the client (`MutateClientAsync`: read, change, replace with the read `rtVersion`, re-read and re-apply on `RtVersionConflictException`, 20 attempts), so concurrent adds keep every secret and an add never brings a removed secret back; then mirror sync and `CorsClientsUpdate`, both best effort (5 s bound for the publish: a committed change is never reported as failed) |
| Description | free text | `octo:mirror-own-secret` (the marker of a mirror's own secret, AB#5061) = `METHOD_VALIDATION_FAILED` (`field=description`) |

- **Authentication** goes through `OctoApplicationManager` (every unexpired record of the client), so a new secret authenticates at once and a removed one
  fails at once (entity caching is off).
- **Audit:** one `Identity.Method` event per call in a `finally` (success, every refusal, exception = `METHOD_HANDLER_FAILED`), details as the other methods plus
  `clientId`, `secretCount` (records after the write) and, for RemoveSecret, `removedCount`. Never the secret, the hash, `secretValue` or the description.
- **Secrets in logs:** the handlers log nothing. The engine's MongoDB command log at **Debug** (`MongoRepositoryClient`, off by default) renders the update
  command and therefore the stored hash of every client secret write (REST included); the clear text never reaches a log.
- **Tests:** `Api/Methods/ClientSecretMethodTests` (real MongoDB, real token endpoint: add -> stored value is the hash -> client credentials token OK ->
  remove -> token refused; remove by stored value; UserManagement and service token callers; caller theory without role/scope for existing and missing
  target; unknown target; public client; expiration; unknown value without echo; failing store audited; forged caller on the host; canary: the secret and a
  clear-text `secretValue` in no audit event and no log line at any level, the hash in none at Information or above; parallel adds + remove lose no
  update; reserved description; broker down still returns the committed secret), `Methods/IdentityMethodHostTests` (gate and caller rule),
  `Methods/ClientSecretHandlerFailureTests` (an exception is audited once as `METHOD_HANDLER_FAILED`).

### REST secret delete removes by predicate (AB#7989, Security)

`ApiSecretsController.DeleteSecretOfClient` / `DeleteSecretOfApiResource` (`DELETE {tenant}/v1/apiSecrets/client|apiResource/{id}/{base64(hash)}`)
answered 200 but removed nothing for an entity read from MongoDB: the `AttributeRecordValueList` of such an entity holds plain `RtRecord`s and
hands out **new** `RtSecretRecord` wrappers on every enumeration, so `Remove(wrapper)` found nothing and returned `false` silently; a revoked
client secret kept authenticating. Both endpoints now call `RemoveAll(predicate)` (as the `Client.RemoveSecret` method of AB#7780 does) and
answer 404 when nothing matched. **Every REST secret write** (POST, PUT, DELETE for clients and API resources) is now a version-checked
read-modify-write (`IOctoClientStore.MutateAsync`, `IOctoResourceStore.MutateApiResourceAsync`, helper `GuardedEntityMutation`: read in a transaction,
change, replace with the `rtVersion` that was read, re-read and re-apply on `RtVersionConflictException`, 20 attempts, then `409` problem). Before,
`UpdateAsync` replaced the snapshot unversioned, so two overlapping secret writes could bring a deleted secret back or drop an added one
(review finding on PR #225). **The full updates followed (AB#8015):** the client `PUT` (and the overlay URI endpoints and the flag `PATCH`) and the API
resource `PUT` applied their DTO to an entity read before and replaced it without an expected version, so a full update that overlapped a secret
delete wrote the deleted secret back. They now run as `MutateAsync` / `MutateApiResourceAsync` too (the DTO is applied to the fresh read, again on a
conflict; `409` problem after 20 attempts); `ClientStore.UpdateAsync` and `ResourceStore.UpdateApiResourceAsync` were removed, so no unversioned
client or API resource replace is left (`FullUpdates_ConcurrentWithSecretDeletes_NeverBringADeletedSecretBack`: six deletes and six full updates
at once, red on the old code: deleted secrets came back and the overlapping updates answered 400/500). 🔴 **Rule for every record list of a stored entity:** never `Remove(item)` / `Contains(item)` / `IndexOf(item)` with
an instance you enumerated; use `RemoveAll` / `FindIndex` with a predicate, and write a changed record back through the indexer (as
`ReplaceSecret` in the PUT endpoints does; the PUT endpoints were not affected). No 404 of the controller echoes the secret value (the stored hash)
any more. octo-cli (`DeleteApiSecretClient` / `DeleteApiSecretApiResource`, SDK `IdentityServicesClient`) is unchanged; Studio does not call
these endpoints. API resource secrets authenticate nothing since the OpenIddict migration, so only the client case has a token-endpoint
test. Tests: `ApiSecretsControllerTests` (`DeleteClientSecret_*` with the token endpoint, `DeleteApiResourceSecret_*`, unknown secret / owner,
403, PUT of an API resource secret persisted, no hash in the logs at the deployed levels, `ConcurrentSecretWrites_*`: four deletes and six creates at
once lose nothing and bring nothing back, red with the unversioned write).

### No credential values in request URLs (AB#8008, Security)

Found in the AB#7765 verification: the admin reset took the new password as a query parameter, and the ASP.NET Core request
log (INFO, `Microsoft.AspNetCore.Hosting.Diagnostics`) plus the TRACE argument log of `ControllerActionInvoker` wrote it into
the log file; ingress access logs and traces would capture such URLs too. The REST secret delete/get carried the stored hash
in the path. Decided by Gerald 2026-11-01:

- **Admin reset** `POST {tenant}/v1/users/ResetPassword`: body `ResetUserPasswordRequestDto { userName, password }` only.
  `[RefuseCredentialInQuery("password")]` (resource filter, `TenantApi/v1/Controllers/RefuseCredentialInQueryAttribute.cs`,
  the single place of the refusal) answers `400` problem details with an update hint when the query carries `password` - after
  authorization (an unauthorized caller still gets 401/403), before model binding, so the action and its TRACE argument log
  never run. Hard refusal, no fallback: octo-cli, the SDK (`IdentityServicesClient.ResetPassword`) and Refinery Studio
  (`@meshmakers/octo-services` `IdentityService.resetPassword`) send the body since AB#8008; release identity only together with
  or after them.
- **Audit actor:** `UsersController.ResetPassword` passes `AuditActor.FromPrincipal(User).Actor` (user name, else `client <id>`),
  not `User.Identity?.Name` (always null under `MapInboundClaims = false`, hence the former `(anonymous reset token)`).
- **Secrets:** `POST apiSecrets/{client|apiResource}/{id}/delete` and `.../lookup` with body `ApiSecretValueRequestDto { valueEncrypted }`
  (POST sub-resource, not DELETE with a body: no defined DELETE body semantics, proxies/clients may drop it, the API already uses POST
  action sub-resources). The path variants `DELETE`/`GET .../{secretValue}` stay **for one release** (removal is the follow-up of
  AB#8008); they no longer bind the value as an action argument (read from `RouteData` in `TakeLegacySecretValue`, the single place
  of the deprecated path), log one WARN `Deprecated API secret request: {Operation} for {OwnerKind} '{Owner}' ...` without the
  value, and overwrite the trace tag `url.path` with the masked path. `PUT` already carried the hash in the body.
- **Log redaction:** `Logging/CredentialLogRedaction.cs` - `AddCredentialLogRedaction()` (Program.cs, after `UseNLog()`) replaces the
  `ILoggerFactory` with a decorator whose loggers mask, in the structured values (`string`, `PathString`, `QueryString`, `Uri`) of every
  log line **and every scope** (the hosting scope carries `RequestPath`, and `nlog.config` renders scope properties into each record), the query parameters `password|newPassword|secret|secretValue|clientSecret` and the value segment of
  `/apiSecrets/{client|apiResource}/{id}/{value}` (not the `delete`/`lookup` action segments) with `***`; `{OriginalFormat}` is kept, so
  NLog renders the template with the masked values. A factory decorator, not a provider decorator: provider-specific filter rules keep
  working and providers added later (test hosts, `AddProvider`) are covered. A line without a match passes unchanged (same state
  instance). OpenTelemetry's ASP.NET Core instrumentation already redacts query values (`url.query`).
- Request DTOs are classes with a `ToString()` that never prints the value (a record's generated `ToString()` would print the password into
  the TRACE argument log).
- **Tests:** `Api/TenantApi/CredentialsNotInUrlTests` (a host logging everything at TRACE into a capturing provider: body reset works and
  the password is in no line; query reset 400 with hint, nothing changed, `password=***` in the request log; body + query refused; 403 before
  the hint for a caller without the role; audit `acting user 'client <id>'` and user name; secret lookup/delete by body for client and API
  resource with neither hash nor Base64 hash in any line and no deprecation WARN; body without value 400; reader 403; deprecated path variants
  work, WARN twice without value, path masked), `Logging/CredentialLogRedactionTests` (patterns, decorator, later providers, the real
  `nlog.config` JSON record), and the AB#7765/AB#5708 reset tests moved to the body form.

### Credential guard regression tests of the REST API (AB#7781)

`tests/IdentityServices.IntegrationTests/Api/TenantApi/IdentityCredentialGuardRestTests` pins that the tenant API v1 never returns
or accepts a credential: a user whose `PasswordHash`, `SecurityStamp`, authenticator key and recovery codes hold fixed dummy values
(written through `UserManager` and the user store, as the service does) is read through `users`, `users/GetPaged`, `users/{name|email|rtId}`,
`users/directory`, `users/{name}/roles|directRoles`, `groups` (all reads, the user as a member); `PUT users/{name}` and `POST users` with
`passwordHash` / `securityStamp` / `userTokens` / `password` in the body change no credential; `GET clients` (all reads) carries neither
the clear text nor the stored hash of a client secret, a secret record in a client body is not bound and `clientSecret` is stored hashed;
`apiSecrets/client/{id}` and its `lookup` return the stored hash (the handle, by design) but never the clear text. A capturing log provider
at Debug (the MongoDB command log of every store write included) must carry no dummy value, and must contain the rendered command of the
seed write (non-vacuous). There is no export endpoint in this service. Path table of all repositories: octo-documentation
`constructionKits/ckLanguage2/accessModifiers.md` § Regression tests.

### Blueprint-owned opt-in: `DataPolicy.ProtectBlueprintLocked` (AB#6384; System.Identity 2.24.0)

`ProtectBlueprintLocked` (optional Boolean, default `false`) is the opt-in of the engine's blueprint-lock write guard
(`DataPermissionWriteGuard` in `octo-construction-kit-engine`, message number 6384, `docs/blueprints.md` there). It is a
**restriction, not a grant**: for the policy's target CK types (derived types inherit) a non-system caller can no longer update or delete an
entity whose stored `RtBlueprintLocked` is `true`, nor set or change `RtBlueprintLocked`, `RtBlueprintSource` and `RtBlueprintAppliedAt`. The policy's own
`PolicyEnforcementMode` decides between refusal (`Enforce`) and audit only (`AuditOnly`).

- **Ownership: `SeedOwned`** (blueprint-owned) - the opposite of `PolicyEnforcementMode` / `PolicyScope`. The blueprint author decides which
  types are protected; every blueprint update or forced re-apply puts the product's value back, so a user with write access to `DataPolicy`
  cannot switch the protection off for good, and a later blueprint version can tighten or loosen it. A policy without the attribute reads as
  `false`. A seed that merely *omits* it does not switch a stored `true` off (the import's blanking guard keeps the value, AB#6313): ship an explicit
  `false` to take a protection back.
- **Default `false`**; an engine or tenant on an older System.Identity reads the attribute as `false`: existing policies and tenants are
  unaffected. The shipped `System.Identity.Bootstrap` policies do not opt in.
- **Blueprint authors:** ship one `DataPolicy` per opted-in type in a policy group of its own (never on shared master-data policies), with
  `ProtectBlueprintLocked: true`, the actions the roles need and a `PolicyPermission` granted to those roles - a policy with the flag still
  counts as a normal policy for the grant logic (only the listed roles get access). Raise the blueprint's `ckModelDependencies` floor to
  `System.Identity-[2.24.0,3.0)` (otherwise an older Identity silently drops the attribute). The policy table is cached per tenant for 60 s.
- Regression tests: `BlueprintLockProtectionIntegrationTests` (real MongoDB: compiled ownership, fresh install, update re-applies, missing
  attribute = false, bootstrap policies do not opt in, and an end-to-end check that a policy with the flag makes the engine guard refuse a user
  write on a locked entity while an unlocked one and the system stay writable).
- CK dependents: no CK model depends on `System.Identity`; blueprints pin it by ranges (`[2.11,3.0)` up to `[2.14.0,3.0)`), which 2.24.0 satisfied, so
  no dependent needed a rebuild. Only a blueprint that uses the flag needs the raised floor. **Since 3.0.0 (AB#8053) every `[2.x,3.0)` range is
  unsatisfied** (a range stays inside one major): each dependent blueprint needs a new version with `System.Identity-[3.0.0,4.0)`.

### Every attribute declares its ownership; the build enforces it (AB#6326)

`Persistence.IdentityCkModel.csproj` sets `OctoEnforceRuntimeStateMarkers=true`: the `CkLintRuntimeStateMarkers` task of
`Meshmakers.Octo.ConstructionKit.MsBuildTasks` fails the build with `OCTO-CK001` when an attribute in
`ConstructionKit/attributes/*.yaml` declares neither `ownership` nor the deprecated `isRuntimeState` (`OCTO-CK003` for both,
`OCTO-CK004` for an unknown value). AB#6326 made the existing behaviour explicit: 151 attributes got `ownership: SeedOwned`
(a restatement - the same resolved ownership, so `octo-ckc ValidateVersion` reports "no bump required" and System.Identity stays
2.24.0); the `TenantOwned` / `Secret` decisions of the table above and the four `isRuntimeState: true` URI lists are unchanged.
Assignment overrides on types (`Client`, `Resource`, `ApiResource`) are not linted; they still win over the definition.
**Review question for every new attribute:** could an operator or user type this value in the product? Yes → `TenantOwned` (or
`Secret` for a credential); a service writes it → `RuntimeState`; the product ships and corrects it → `SeedOwned`.

### Per-User Outbound Channel Preference (AB#5149, binding-specific)

`RtUser.PreferredChannelBindingId` (optional String, CK 2.18.0) stores the **rtId of the
`VerifiedExternalIdentifier`** the user chose as the target for **system-initiated** messages. The
channel KIND is never stored — it is DERIVED from the referenced binding (PhoneNumber ⇒ `"SIGNAL"`,
EntraIdObjectId ⇒ `"TEAMS"`, extensible in `PreferredChannelService.KindToChannel`), so a user with
several phone numbers picks the concrete number. The attribute name `PreferredChannelBindingId` is
a cross-repo contract: the mesh adapter reads it from the user entity and derives kind + target
itself. Synchronous replies keep using the channel the message came in on.
`IPreferredChannelService` / `PreferredChannelService`
(`IdentityServerPersistence/Services/SelfService/`): `GetOptionsAsync` lists every VALID own
binding of a channel-mapped kind, `SetPreferredChannelAsync` only accepts one of those (anything
else — malformed id, foreign/unknown binding, expired, unmapped kind ⇒
`Status=BindingNotEligible`, deliberately not distinguishing "not yours" from "does not exist");
clearing (null) is always allowed; `ClearIfReferencedAsync` is invoked by
`SelfServiceIdentifierService.RemoveAsync` so deleting the preferred binding clears the preference
in the same operation (a reference gone dangling via other paths reads as "no preference" without
a write). Persistence via `UserManager.UpdateAsync`. Self-service API on
`MyIdentifiersApiController`: `GET`/`PUT {tenantId}/api/manage/identifiers/preferredChannel`
(cookie + bearer schemes, current user only) — GET returns `{bindingId, channel, identifierValue,
options[]}`, PUT takes `{bindingId|null}` and answers `Success=false`/`Status=BindingNotEligible`
on refusal (no 400 path anymore). UI: radio group of CONCRETE targets ("Microsoft Teams",
"Signal (+43 …)" per bound number, "no preference") on the ClientApp my-identities page, options
served by GET. Tests:
`tests/IdentityServerPersistence.UnitTests/Services/SelfService/PreferredChannelServiceTests.cs`.

### Signal OTP Delivery — Per-Tenant Sender Resolution (AB#5134 / AB#5154)

The self-service phone OTP (AB#5123) is delivered over the `signal-cli-rest-api` bridge by
`SignalRestOtpDeliveryChannel` (`IdentityServerPersistence/Services/SelfService/`). Since AB#5154
the **sender number is tenant state, not deployment state**: the channel resolves its sender PER
TENANT at send time (the tenant id travels in `OtpDeliveryContext` — the channel is a singleton
with no HTTP-scoped tenant), with this fallback chain:

1. **The tenant's Studio-activated `System.Communication/SignalChannel`** (AB#5143/5145,
   rtWellKnownName `signal-channel`) in the `Registered` state (2) → its `Number` + `ApiUrl` win.
   Read by `TenantSignalChannelResolver` via `ISystemContext.TryFindTenantRepositoryAsync` — the
   same explicit-tenant access `ClientMirrorProvisioningService` uses (`ISystemContext` is a
   singleton, so the chain is singleton-safe). The entity belongs to the Communication Controller's
   CK model, so the read is a **generic `RtEntity` query by CK type id** (no generated type here)
   and strictly **read-only**. Guards mirror the controller's own projection
   (`AddSignalChannelConfigurationAsync`): a read failure — e.g. a tenant whose
   System.Communication model predates 3.34.0 — degrades to the next step with a warning, never
   breaks OTP delivery; a hand-crafted multi-channel tie is broken by lowest rtId with a warning
   (singleton is service-enforced in the controller).
2. **The env-bound `SignalBridgeOptions`** (`OCTO_SIGNALBRIDGE__APIURL` / `__NUMBER`) — unchanged
   semantics (including the THROW when `ApiUrl` is set but `Number` empty). This is the
   **local-dev fallback** where no Studio activation exists; in cluster deployments the env vars
   are now fully optional.
3. **Neither** → the `LoggingOtpDeliveryChannel` dev stub path (its loud warning, code in the
   log), exactly the previous unconfigured behavior. The stub is no longer registered as an
   `IOtpDeliveryChannel` itself — `SignalRestOtpDeliveryChannel` is always the Signal channel and
   delegates to the injected stub.

The chosen source is logged at Debug ("tenant SignalChannel" vs "SignalBridgeOptions fallback").
Tests: `SignalRestOtpDeliveryChannelTests` (chain behavior at the channel) and
`TenantSignalChannelResolverTests` (entity read: Registered-only, lowest-rtId tie-break,
read-failure degradation, read-only) in
`tests/IdentityServerPersistence.UnitTests/Services/SelfService/`.

### Client Role & Group Assignment (AB#4183)

A **Client** (machine-to-machine identity) can be assigned roles and group memberships with the same
semantics as a user, so a `client_credentials` access token carries the resolved role claims and can
call role-protected endpoints (e.g. the `FromHttpRequest` trigger node). CK model bumped to
`System.Identity-2.10.0`.

- **CK model:** `Client` gains the `AssignedRole` association (Client → Role); `Group` accepts
  `Client` as a `GroupMember` target (`ck-client.yaml` / `ck-group.yaml`). Adding associations is
  additive schema — no data migration.
- **`IClientRoleStore` / `ClientRoleStore`** (`IdentityServerPersistence/SystemStores/`): manages a
  client's `AssignedRole` edges (`GetDirectRoleIds`, `SetRoleIds`, `AddRole`/`RemoveRole` by name) and
  resolves the **effective role names** (direct + group-inherited) for token issuance. Audit-logged.
- **`GroupRoleResolver`** is now subject-agnostic: `ResolveEffectiveRoleIdsAsync(subjectRtId)` works for
  a user *or* a client. `GroupStore` gained `GetMemberClientIds` / `AddMemberClient` /
  `RemoveMemberClient` and a type-agnostic `GetAllMemberSubjectIds` (used by the resolver).
- **Token claims:** `TokenEndpointController` (`IdentityServices/Controllers/Protocol/`) resolves the
  client's effective roles via `IClientRoleStore` when handling the `client_credentials` grant and
  stamps them as **unprefixed `role`** claims on the token — identical shape to user tokens, so
  consumers need no client-specific code path. (Replaces the former Duende
  `ClientCredentialsRoleTokenValidator`.)
- **REST API:** `ClientsController` — `GET/PUT /clients/{id}/roles`, `PUT/DELETE /clients/{id}/roles/{roleName}`.
  `GroupsController` — `GET/PUT/DELETE /groups/{rtId}/members/clients[/{clientId}]`. `GroupDto` gained
  `MemberClientIds`; `ClientDto` gained `RtId` (read-only, identifies the client as a group member).
- **Blueprint cleanup gate:** `PreBlueprintCleanupMigration` now sweeps orphan `AssignedRole` edges for
  `RtClient` origins too (aligned with the user-side strategy). No capture/restore pass is needed for
  clients — the feature postdates the imperative seed, so no client held a random-rtId role edge at the
  one-time 17→18 cutover. Client role/group assignments are declarable in the blueprint seed via the
  generic `associations:` block.
- **Tests:** `tests/IdentityServices.IntegrationTests/Persistence/ClientRoleAssignmentIntegrationTests.cs`
  (Testcontainers MongoDB) covers direct-role assignment, group-inherited roles via client membership,
  and removal.

### `tenant_id` on Client-Credentials Tokens (AB#5032)

Until AB#5032 a `client_credentials` access token carried `client_id`, `scope` and (since AB#4183)
`role` — but **no `tenant_id`**. The claim had a single producer, the user profile/claims path, which
the client-credentials grant never reaches because it has no subject. `acr_values=tenant:X` on
`/connect/token` only selected which tenant's `ClientStore` resolved the client; nothing copied X into
the token.

Consequence downstream: every tenant gate on the platform (`TenantAuthorizationMiddleware` in
octo-common-services, the MCP server's `RuntimeSecurityContextResolver`, the mesh adapter's
`HttpRequestService`) detects "no `sub`" and **skips** — so with `ValidateAudience = false` on
asset-repo / platform-services / MCP, *any* client-credentials client of this authority could address
*any* tenant. Client mirroring (`AutoProvisionInChildTenants`) copies the same secret hash into every
child tenant, so one credential pair was literally valid instance-wide.

**`ClientCredentialsTenantProcessor`** (`IdentityServices/OpenIddict/`) therefore decides the issuing
tenant, and `TokenEndpointController.HandleClientCredentialsAsync` stamps it:

- The tenant comes from `HttpContext.Items[tenantId]`, which `OidcTenantResolutionMiddleware` wrote
  from `acr_values`. When no `acr_values` was sent, the client lookup ran against the **system
  tenant** — so that is what is stamped. ⚠️ **That fall-back was narrowed by AB#5058 (below): it now
  applies only when the client id is unambiguously bound to one tenant.**
- The claim is stamped **before** the roles. Under Duende the role branch returned early for a client
  with no roles, which would have left exactly the most likely legacy clients shipping tenant-less
  tokens; the ordering is kept because the invariant ("a role-less service client still carries its
  tenant") is what consumers depend on.
- 🔴 **The claim reaches the access token only because `OctoClaimsDestinations` routes it there.**
  OpenIddict emits nothing but `sub` without an explicit destination — a destination map that dropped
  `tenant_id` would leave every unit test green while no consumer ever sees the claim.
- Other grants are untouched: `OctoTokenClaimsService.PopulateUserClaimsAsync` already provides
  `tenant_id` for every user token, and the processor is reached only from the
  `client_credentials` branch of the token endpoint.
- **Gone with Duende:** the `ClientClaimsPrefix` dance (Duende prefixed claims added via
  `ValidatedRequest.ClientClaims` with `client_`, so the prefix had to be cleared per request) and the
  de-duplication against `RtClient.ClientClaims`. OpenIddict has no client-claims prefix and the
  controller composes the identity from scratch, so neither hazard exists any more.

Both big machine consumers already send `acr_values` and therefore get a *matching* tenant for free —
verified in code, not assumed: `octo-ai-services` `McpTokenIssuer.AcquireAccessTokenAsync` adds
`acr_values=tenant:{tenantId}` and caches one token **per tenant** (used against `/{tenantId}/mcp`),
and `octo-mesh-adapter` `ServiceAccountTokenService` adds it from the adapter's own
`ServiceAccountConfiguration.TenantId` on all three of its client-credentials call sites. So the
`tenant_id` match alone carries them; no client-id allow-list is needed for either.

Consumers narrow the exemption behind their own staged switch — see octo-common-services CLAUDE.md
§ "Tenant Authorization — the service-token exemption". This service also calls
`AddOctoTenantAuthorization(builder.Configuration)` so the switch is settable per environment
(`OCTO_TENANTAUTHORIZATION__…`); its defaults keep today's behaviour.

Tests: `tests/IdentityServices.UnitTests/Services/ClientCredentialsTokenClaimsTests.cs` (the tenant
decision, plus `ClientCredentialsClaimCompositionTests` for the destination routing) and — the
wire-level proof — `TokenShapeGoldenTests.ClientCredentials_AccessTokenShape_MatchesGoldenBaseline`,
whose recorded `client-credentials-access-token.json` now carries `tenant_id`. That is a **deliberate
golden re-record**, the third of the migration after the access-token identity claims (AB#5007) and
the on-behalf-of grant entry (AB#5026); the diff is exactly that one added claim.

### Ambiguous Tenant Binding on `client_credentials` (AB#5058)

AB#5032's fall-back — "no `acr_values` ⇒ the client store resolved against the system tenant, so
stamp the system tenant" — **does not survive client mirroring**. `AutoProvisionInChildTenants`
provisions the *same* `ClientId` with the *same* secret into every child tenant
(`ClientMirrorProvisioningService.CreateMirrorClient` copies `ClientSecrets` verbatim). For such a
client id, "found in the system tenant" is not evidence of "belongs to the system tenant" — the
binding is **ambiguous**, and a caller holding a child tenant's credentials could simply omit
`acr_values` and be handed a system-tenant token. Every authorization asking "is the caller in the
system tenant" — which is what the system-route hardening (AB#5055) builds on — was therefore
trivially satisfiable with a service token.

`ClientCredentialsTenantProcessor` now **refuses to guess**. On a `client_credentials` request
with no `acr_values` it decides the binding **server-side**, from state no caller can influence:

| Signal | Where it lives | Meaning |
|---|---|---|
| `RtClient.AutoProvisionInChildTenants` | resolved client | declared fleet credential ⇒ ambiguous |
| `RtClient.ProvisionedByParentTenantId` | resolved client | the resolved record *is* a mirror ⇒ ambiguous |
| `RtClientMirror` rows for the client id | system tenant | mirrors already materialized ⇒ ambiguous |

Ambiguous ⇒ `invalid_request` with a description naming the remedy (the token endpoint answers with
`Forbid`, which OpenIddict renders as the OAuth error response), plus a runtime-event-log entry
"Client Credentials Tenant Ambiguity" carrying the client id and the reason, persisted through
`IIdentityAuditService`. Unambiguous ⇒ unchanged AB#5032 behaviour, system tenant stamped.

> The Duende-era `ClientCredentialsTenantAmbiguityEvent` (category `ClientCredentials`, ID `50580`,
> expanded by `OctoEventSink`) is gone with the event sink itself. `IIdentityAuditService` is the
> OpenIddict-era replacement and takes the event name and the formatted fields directly — the same
> shape the ported delegation failures use, and the same "failures persist, successes are log-only"
> rule.

- 🔴 **The mirror lookup fails closed.** A repository error rejects the request rather than falling
  back to "system" — guessing there is exactly the escalation being closed. The blast radius is
  bounded: the probe runs *only* on the no-`acr_values` path.
- 🔴 **Ordering matters.** The processor runs **before any claim is composed**, so a refused request
  never carries a guessed `tenant_id`, and the AB#5032 invariant (tenant stamped before the roles) is
  preserved for every accepted request.
- **Caller inventory (checked across the whole `dev` checkout, not assumed).** No production caller
  is broken: `octo-mesh-adapter` `ServiceAccountTokenService` (all 3 call sites),
  `octo-ai-services` `McpTokenIssuer` and `octo-cli` (via `AuthenticatorOptions.TenantId`, guarded
  in `LogInClientCredentialsCommand`) all send `acr_values`. The only callers that omit it are the
  `octo-sdk` sample `Sdk.GraphQlCodeGenSample` (never assigns `AuthenticatorOptions.TenantId`) and
  the `curl` recipe in `demo-energy-iq/docs/data-access-fh-salzburg.md` — both use ordinary,
  unmirrored clients, so both keep working. Three call sites set the parameter only *conditionally*
  and would now surface a misconfiguration as a token error instead of a silent system-tenant token:
  `octo-sdk` `AuthenticatorClient.BuildClientCredentialsTokenRequest`, the two auto-re-acquisition
  branches of `octo-cli` `AuthenticationService`, and `ServiceAccountTokenService.EnsureTokenAsync`
  (the only one of the adapter's three grants without a fail-closed tenant guard).
- **No log-only stage.** The gap is an actual bypass, so an observing default would leave it open.
  What *is* log-only is the part that cannot be closed here (next bullet).
- ⚠️ **Residual, by construction of the mirroring feature.** A mirror shares the parent's secret, so
  whoever holds a mirror's credentials also holds the parent's and can ask for the system tenant
  *explicitly*. No token-endpoint check distinguishes those two callers. The processor logs a
  warning whenever a mirroring source obtains a system-tenant token, and **AB#5055 must not treat
  `tenant_id == systemTenant` on a client-credentials token as proof of provenance on its own.**
  Closing it for real needs per-tenant mirror secrets.

Tests: `tests/IdentityServices.UnitTests/Services/ClientCredentialsTenantAmbiguityTests.cs`
(flagged client / live mirror rows after the flag was switched off / mirror copy itself / lookup
failure ⇒ all refused with no tenant on the outcome; unmirrored client unchanged; mirrored client
*with* `acr_values` unchanged and the probe not even consulted; an accepted request is not audited)
and `Persistence/ClientMirrorProvisioningIntegrationTests.cs`
(`MirroredClient_TokenRequestWithoutAcrValues_IsRefused` /
`UnmirroredClient_TokenRequestWithoutAcrValues_StillCarriesTheSystemTenant` — the real processor over
a real mirror in MongoDB; the unit tests stub `GetMirrorsAsync`, so only these prove that an actually
provisioned mirror is what makes the id ambiguous).

### Per-Tenant Mirror Secrets (AB#5061) — step 1 of 2, gap still open

AB#5058 closed the *silent* half of the mirroring escalation. This is the start of the *explicit*
half: a mirror shares the parent's secret, so a child credential **is** a parent credential and can
ask for the system tenant outright.

Every mirror of a **confidential** parent now additionally carries its **own** generated secret,
marked `Description = "octo:mirror-own-secret"` (`ClientMirrorSecrets`). Public clients are mirrored
unchanged — and every mirrored client in the shipped seed is public
(`octo-data-refinery-studio`, `octo-cli`, the three swagger clients, `octo-mcpServices-device`), as is
every `octo-dcr-*` registration. None of them can obtain a `client_credentials` token at all, which is
why the fix could not simply forbid mirroring.

- **Distribution is the whole design question**, not generation. Secrets are stored SHA-256 hashed and
  are unrecoverable, and mirrors are materialized by a background loop with nobody present to receive
  a plaintext. So the value is issued on demand and returned **once**:
  `POST {parentTenant}/v1/clients/{clientId}/mirrors/{childTenantId}/secret` (`IdentityApiFullAccess`
  in the **parent**; 400 for a public client, 404 for an untracked pair). Calling again rotates and
  retires the previous value. Nothing recoverable is persisted and no endpoint reads a secret back —
  deliberately avoiding both a new class of reversible stored credential and a `System.Identity`
  schema bump, which would cascade through every dependent CK.
- 🔴 **Preservation is load-bearing.** `ReconcileOwnSecret` carries an already-issued own secret across
  re-provisioning *and* across parent-side secret rotation. Both paths rewrite the mirror from the
  **parent's** state, so without it every service restart would silently invalidate every per-tenant
  credential handed out. Same trap as the AB#5027 bus consumer's preserve branch.
- 🔴 **`CreateMirrorClient` now deep-copies `ClientSecrets`.** It previously assigned the parent's list
  *by reference*; appending an own secret to it would make `SyncMirrorsForClientAsync` hand child *N*
  the secrets of children 1..*N-1* — a cumulative credential leak between sibling tenants.
- ⚠️ **The inherited parent secret is still accepted, so the escalation is still open.** The caller
  inventory (whole `dev` + `main` checkout) found live fleet credentials that authenticate with the
  parent secret against child tenants and would break instantly: `ci-deploy` / `ci-deploy-{cluster}`
  (workload-deployment pipeline, one Vault pair per cluster — its own comments state the intent),
  `octo-ai-adapter` (`McpTokenIssuer`, one Helm/Vault pair per cluster) and `claude-agent`. None of
  them appears in any git-tracked config; all three are created with
  `octo-cli -c AddClientCredentialsClient … -apic`. **AB#5055 must keep treating
  `tenant_id == systemTenant` on a client-credentials token as unproven** until the follow-up step
  removes the inherited secret.
- The migration sequence, and the open decision between "own secrets only" and "forbid confidential
  mirroring entirely" (the counter-model being the per-tenant `octo-pipeline-sa-*` accounts of
  AB#5027), are in `docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md`.

Tests: `ClientMirrorOwnSecretTests` (own secret ≠ parent's, public client untouched, preservation on
both rewrite paths, sibling-leak regression, no secret in the **rendered** log output via
`CapturingLogger<T>`, and an explicit assertion that the inherited secret is *still* present — that
test must be inverted when the gap closes), `ClientMirrorSecretsTests` (hash convention pinned against
published SHA-256 digests; a divergence from `OctoSecretHasher` would store rotated secrets in a
shape the token endpoint can never match), `ClientMirrorControllerTests` (endpoint branching plus
`ToString()` redaction on both secret-carrying types) and
`ClientMirrorProvisioningIntegrationTests` (the same over real MongoDB, plus rotation retiring the
superseded value).

### Client Mirroring Is Intentional — and What It Does Not Prove

Worth stating plainly, because the AB#5032 / AB#5058 / AB#5061 sections above are all about the
escalation and read as if mirroring were a defect. It is not.

- **Mirroring is the point.** A client is described **once**, in one tenant, and made available to
  that tenant's children. Maintaining the same client per tenant — every redirect URI, scope, grant
  type and lifetime, kept in step across every tenant, with a new tenant silently missing whatever
  was forgotten — would be a substantial configuration burden.
- **Today it is used for OAuth clients — the interactive ones — not for authentication.** Every
  flagged client in the shipped seed and every `octo-dcr-*` registration is a **public client with no
  secret**. What is distributed there is a *login surface*, not a credential; none of them can get a
  `client_credentials` token. The confidential mirrored clients (`ci-deploy`, `octo-ai-adapter`,
  `claude-agent`) exist only as imperative setup and are the subject of the migration above.
- **Roles are not mirrored.** `ClientMirrorProvisioningService` copies `RtClient` *attributes* only —
  it touches no `AssignedRole` edge and no group membership. A mirror is therefore **authenticated but
  rightless** in the child tenant until somebody grants it roles *there*
  (`PUT {tenantId}/v1/clients/{clientId}/roles/{roleName}`). **That is the actual boundary
  downwards**, and it is the one to reason about.
- 🔴 **While the inherited secret is accepted, a `tenant_id` claim on a client-credentials token does
  not prove which tenant the caller came from** — only which tenant the token was issued *for*.
  Whoever holds a child's credentials holds the parent's. **Do not authorize on it** (this is exactly
  what blocks **AB#5055**: `tenant_id == systemTenant` is not proof of provenance). Authorization for
  service tokens belongs on **roles assigned to the client in the addressed tenant** — those are
  per-tenant by construction, and they answer the question authorization actually asks. Whether the
  inherited secret is still in use is now measured (**AB#5065**, below).

### Which Mirror Secret Matched (AB#5065) — step 3 of the migration

Step 4 (drop the inherited secret) cannot be justified without knowing that nobody uses it, and before
AB#5061 split the secrets there was nothing to tell apart. `MirrorSecretUsageTelemetry`
(`IdentityServices/OpenIddict/`) supplies that number.

- **Where it hangs — and why it moved.** Under Duende this decorated `ISecretsListValidator`, the one
  service that saw the presented credential and the client's whole secret list together. OpenIddict
  has no such service: client authentication runs through
  `OpenIddictApplicationManager.ValidateClientSecretAsync`, so **`OctoApplicationManager` is now that
  place** — it already owns the legacy-hash comparison and is the only code that knows *which* stored
  record matched. It calls the telemetry after the match; the decision itself is untouched, and a
  failed authentication is silent (a wrong guess says nothing about which secret was meant and would
  poison the count).
- 🔴 **The move came with a bug fix that is load-bearing on its own.** OpenIddict's application model
  carries exactly **one** client secret, and `OpenIddictApplicationStore.GetClientSecretAsync` can
  only project the *first* `RtSecretRecord`. Duende validated against the whole list.
  `OctoApplicationManager.ValidateClientSecretAsync(RtClient, secret, ct)` therefore iterates the
  stored records itself. Without it, whichever of a mirror's two secrets happened to be second would
  silently stop authenticating — and which one that is depends on list order, so the breakage would
  look random. The same applies to any client mid-rotation.
- **Classification without a store lookup.** The `octo:mirror-own-secret` marker rides on the
  `RtSecretRecord` the manager already read, so "is this a mirror with its own secret" is a string
  comparison over ≤2 records (indexed, so an ordinary client does not even allocate an enumerator).
  No mapping hop is involved any more — the Duende-era `RtSecretRecord → Secret` map that had to
  carry `Description` across is gone with the migration, and with it the risk that a mapping change
  would silently zero the measurement.
- **One guard became structural.** The Duende decorator had to exclude non-shared-secret credentials
  (private key JWT, mTLS), which would otherwise have been misreported as inherited use and blocked
  step 4 forever. `ValidateClientSecretAsync` *is* the shared-secret path, so no such credential
  reaches the code at all.
- **Output** — event id `50650`, structured `MirrorSecretKind` / `ClientId` / `TenantId`, rendered as
  `MirrorSecretUsage secretKind=inherited clientId=… tenantId=…`. Inherited use at **Warning**, own
  use at Information. Dash0 (dataset = cluster): filters `k8s.container.name is identity`,
  `otel.log.body contains MirrorSecretUsage`, `otel.log.body contains secretKind=inherited`
  (`/octo-logs` skill).
- 🔴 **No secret material is ever logged** — not the credential, not the stored hash, not a prefix.
  Pinned against the **rendered** output via `CapturingLogger<T>`, not against format strings.
- **Log-only on purpose.** AB#5058's refusal next door persists an audit entry via
  `IIdentityAuditService`, but that fires on a *rejected*
  request. This one fires on every
  *successful* authentication of the affected clients, so a runtime-event-log write per token request
  is precisely the hot-path cost being avoided — and "zero for a whole release" is a log-aggregation
  question anyway.
- **Telemetry never decides an authentication.** A throwing classification is caught and logged as an
  error; the caller stays authenticated.
- ⚠️ **Blind spot = a precondition, not a clean bill.** Mirror-ness is inferred from the *presence* of
  an own secret (the alternative is a DB round trip per token request), so a mirror that has none yet
  is invisible. A zero inherited-use count is only evidence once "every mirror holds its own secret"
  is verified per environment — which is already row 1 of the migration table in
  `docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md`.

Tests: `MirrorSecretUsageTelemetryTests` (both classifications over the real `OctoApplicationManager`
with real SHA-256 matching against real `RtClient` records; the second-stored-secret regression and
an expired record; no record for an ordinary client or for a secret whose description is not the
marker; unchanged failure path; unresolved tenant marked rather than guessed; measurement failure not
failing the authentication; nothing secret in the rendered log) and
`ClientMirrorProvisioningIntegrationTests.MirrorSecretUsage_DistinguishesInheritedFromOwn_ThroughTheRealStoredRecords`
(a real mirror in MongoDB read back through the repository and authenticated with **both** credentials
through the production manager — the test that catches a provisioning change dropping `Description`,
which would otherwise make the measurement silently read zero).

### Login Configuration (Self-Registration & Auto-Group Assignment)

Identity providers support login-time configuration via two attributes on the abstract `IdentityProvider` base type:

- **`AllowSelfRegistration`** (bool, default true): When false, new users cannot self-register via this provider — only existing users can authenticate. Applies to all provider types (Google, Azure, OctoTenant, LDAP, etc.)
- **`DefaultGroupRtId`** (string, optional): RtId of a group to which new users are automatically added on first login via this provider

Additionally, **`EmailDomainGroupRule`** entities map email domain patterns to groups:
- **`EmailDomainPattern`**: Domain to match (e.g., "meshmakers.com"), case-insensitive
- **`TargetGroupRtId`**: Group to add matching users to
- Unique index on `EmailDomainPattern`

Key components:
- **`ILoginGroupAssignmentService`** / **`LoginGroupAssignmentService`** (`IdentityServerPersistence/Services/Login/`): Orchestrates group assignment from provider defaults + email domain rules + external identity group claim sync
- **`IEmailDomainGroupRuleStore`** / **`EmailDomainGroupRuleStore`** (`IdentityServerPersistence/SystemStores/`): CRUD for email domain rules
- **`EmailDomainGroupRulesController`** (`TenantApi/v1/Controllers/`): REST API at `{tenantId}/v1/emailDomainGroupRules`
- **`AuthApiController`**: Self-registration gate + group assignment in external login callback, LDAP login, cross-tenant password login, and cross-tenant token login

### AD Group-to-OctoMesh Group Synchronization

When a user logs in via Microsoft AD (LDAP), their AD group memberships are automatically synchronized with OctoMesh groups on **every login** (not just first login). This enables role inheritance from AD groups.

**How it works:**
1. `MicrosoftAdAuthentication` reads the `memberOf` attribute directly from the LDAP user entry and extracts group CN names (e.g., `CN=FdaUsers,CN=Users,DC=...` → `FdaUsers`)
2. Group names are added as `JwtClaimTypes.Role` claims on the external identity
3. `LoginGroupAssignmentService.SyncExternalGroupClaimsAsync` (called on every login, for both new and existing users) matches each role claim against OctoMesh groups by normalized name (`FindByNameAsync`)
4. If a matching OctoMesh group exists, the user is added as a `GroupMember` (if not already a member)
5. The user then inherits all roles assigned to that group via `GroupRoleResolver`, which appear in the JWT token

**Prerequisites for AD group mapping:**
- An OctoMesh **Group** must exist in the tenant with the **same name** as the AD group (e.g., `FdaUsers`)
- That OctoMesh group must have **Roles** assigned via `AssignedRole` associations
- The AD user must be a member of the AD group (`memberOf` attribute)

**Error handling:** Group sync failures are logged but never block the login flow. Individual group assignment failures do not prevent other groups from being assigned.

The **Refinery Studio identity management UI** (Users, Roles, Clients) is available for **all tenants**, not just the system tenant. The `IdentityService` in `@meshmakers/octo-services` resolves the current tenant via `TENANT_ID_PROVIDER` and routes API calls to `{tenantId}/v1/...`.

- **Tenant-scoped login/consent redirects**: `AuthorizeController` (`Controllers/Protocol/`) issues login and consent redirects directly with the correct tenant prefix (resolved from `acr_values=tenant:{tenantId}` / `OidcTenantResolutionMiddleware`), so the former `TenantLoginRedirectMiddleware` — which rewrote Duende's hard-coded 302 redirects — was **deleted** in the OpenIddict migration. Logout redirects carry a self-contained data-protected `logoutId` handled by `EndSessionController`.
- **Auto-creation of `RtOctoTenantIdentityProvider`**: When a tenant has `ParentTenantId` set, the provider is auto-created during `SetupTenantAsync` (new tenants) and via `OctoTenantIdentityProviderMigration` (existing tenants, migration 8→9).

### Tenant Discovery (Email-First Flow)

When an OAuth client sends `/connect/authorize` **without** `acr_values=tenant:{tenantId}`, the `OidcTenantResolutionMiddleware` redirects to `/tenant-discovery` instead of defaulting to the System-Tenant. The user enters their email/username, the server discovers which tenants they belong to, and redirects back to the authorize URL with `acr_values` appended.

Key components:
- **`TenantDiscoveryService`** (`IdentityServerPersistence/Services/`): Searches all tenant databases for a user by email or username. Excludes cross-tenant shadow users (`xt_` prefix). Uses `ISystemContext` to iterate tenants in parallel.
- **`TenantDiscoveryApiController`** (`Controllers/Api/`): Rate-limited endpoint at `POST /api/tenant-discovery/lookup` (no `{tenantId}` prefix). Returns only the user's own tenants, never the full tenant list. Enforces 500ms minimum response time to prevent timing attacks.
- **Discovery scope (AB#5311).** An app host that serves one tenant subtree (the accounting app on `accounting.meshmakers.cloud`, root tenant `accounting`) passes it as a second, space-separated `acr_values` entry: `acr_values=tenant_scope:accounting`. `OidcTenantResolutionMiddleware.ParseScopeFromAcrValues` reads it (the `tenant:` parser ignores unknown prefixes, so older clients and the existing `tenant:` entry are unaffected), forwards it as `?scopeTenantId=` on the `/tenant-discovery` redirect (`BuildDiscoveryUrl`), and the SPA sends it with the lookup. `TenantDiscoveryService.FindTenantsForUserAsync(identifier, scopeTenantId)` resolves the user exactly as before — the home search is deliberately **not** restricted to the subtree, an administrator's home is usually above it — and then intersects the result with the descendants of the scope (`GetScopeDescendantsAsync`: a breadth-first walk through each tenant's own context, `ISystemContext.TryFindTenantContextAsync` → `ITenantContext.GetChildTenantsAsync`, direct and indirect, the scope itself excluded, a child without a resolvable context treated as a leaf, cycle-safe). 🔴 It is deliberately **not** built on `ISystemContext.GetAllTenantsAsync`: that enumeration constructs `OctoTenant` without the parent id (engine-mongodb `SystemContext.GetAllTenantsAsync`), so every tenant looks like a direct child of the system tenant and a scope below it has no descendants — the first cut shipped that way in 3.4.126 and returned "not found" for every scoped lookup on prod-1, while the unit tests, fed with hand-built parents, stayed green. A scope test must therefore go through the same API the service uses, not through a registry fixture. The scope only narrows: it never adds a tenant the user is not in, so the anti-enumeration properties of the lookup are unchanged; an unknown scope answers "not found", not the unscoped list. The single-session shortcut is gated the same way — a session cookie for a tenant outside the scope no longer skips the discovery. Once a tenant is chosen the SPA appends `tenant:{id}` next to the scope entry, so the authorize request carries both. **PAR (RFC 9126):** a scope-only `/connect/par` names no tenant, so nothing used to be captured and the follow-up `/connect/authorize?request_uri=…` ran an unscoped discovery. The middleware now reads the scope from the PAR form as well, captures the issued `request_uri` for it (`TokenToTenantMap[ScopeMapKey(request_uri)]`, same lifetime as the tenant entries, keyed apart so the two can never be confused) and restores it on the authorize call (`ExtractScopeFromRequestUri`) before the shortcut and the discovery redirect.
- **`TenantDiscoveryComponent`** (`ClientApp/src/app/features/tenant-discovery/`): Angular SPA page with email input, tenant selection (when multiple), and redirect logic.
- **`octo_last_tenant` cookie**: Shortcuts the discovery flow on repeat visits by redirecting directly with the last-used tenant's `acr_values`.
- **Interceptor exclusion**: The Angular `tenantInterceptor` skips `/api/tenant-discovery/` paths since this endpoint has no tenant context.

See `docs/CONCEPT-TENANT-SPECIFIC-OAUTH.md` § 9 for the full flow diagram and API specification.

### Tenant topology endpoint `GET /api/tenant-topology?scope={rootTenantId}` (AB#7044)

Tells an app acting for a signed-in user which of the user's allowed tenants lie below the app's root tenant and whether each has children — **without** any call to a tenant other than the token's tenant, which the user-token tenant gate (`TenantAuthorizationMiddleware`, AB#6728) rejects under `Enforce`.

- **Contract** (Freya's `@meshmakers/shared-auth` client depends on exactly this): `200 { "scope", "scopeHasChildren", "tenants": [ { "tenantId", "depth", "hasChildren" } ] }`; `depth` 1 = direct child of the scope, `hasChildren` = the tenant itself has children (never listed, not even their ids). Nothing else is ever returned: no scope entry, no tenant outside the claim or the subtree, no parent ids, no tenant data (pinned by `ResponseCarriesNoOtherFieldThanTheContract`).
- **Entitlement:** `tenants` = (the `allowed_tenants` claim of the validated user token) ∩ (strict descendants of `scope`). The claim is a *selection hint*, not an API authorization; here it only limits which topology facts are revealed (a boolean and a depth about tenants the user can already log into). `scopeHasChildren` is truthful only when the scope is in the claim or `tenants` is non-empty, otherwise `false` (no oracle for unrelated scopes). An unknown scope, a malformed scope (not a well-formed tenant id), a scope without entitled descendants and a foreign scope all answer the **same** `200` with an empty list and `scopeHasChildren=false`.
- **Status codes:** 401 no/invalid token; 403 client-credentials token (no `sub`) or a user token without the `octo_api` read scope (`IdentityApiReadOnlyPolicy`, no role needed); 400 missing `scope`; 429 rate limit (`Retry-After: 60`); **503** with a problem body when the hierarchy cannot be read completely (failing registry read, more than `TenantTopology:MaxNodes` tenants) — fail closed, never a partial list. A cycle in a hand-edited registry terminates (visited guard). Older identity builds answer 200 `text/html` (SPA fallback) for unknown /api paths; clients must treat a non-JSON 2xx like 404 (topology unknown).
- **No new exemption:** the route has **no** `{tenantId}` segment, and `TenantAuthorizationMiddleware` skips routes without a tenant segment — so nothing changes in octo-common-services and `IAllowParentTenantAdministration` is not used. `TenantGateInEnforceMode_AllowsTheTenantLessRoute_AndStillRefusesAForeignTenantRoute` (real pipeline, `X-Test-RealBearerPrincipal` so the gate actually sees a "Bearer" principal) and `Route_HasNoTenantSegment_…` fail if someone adds a tenant segment or an exemption marker.
- **Code:** `TenantTopologyApiController` (`Controllers/Api/`), `ITenantTopologyService`/`TenantTopologyService` (`IdentityServerPersistence/Services/`), `TenantSubtreeWalker` (the BFS walk, **extracted unchanged in behaviour** from `TenantDiscoveryService.GetScopeDescendantsAsync`, which now delegates to it and keeps its "unreadable ⇒ null" contract; the walk still goes through each tenant's own `ITenantContext.GetChildTenantsAsync`, see the discovery section for why not `GetAllTenantsAsync`), `TenantTopologyRateLimiter` (`Services/`).
- **Caching:** the subtree snapshot (tenantId, depth, hasChildren of the whole subtree) is cached per scope in the shared `IMemoryCache` for 45 s (`TenantRegistry.CacheTtl`) with single flight **per scope key** (in-flight table, entries live only while a read runs; a slow scope or unknown-scope spam never blocks the first request of another scope, `ASlowScope_DoesNotBlockOtherScopes_NorUnknownOnes`); the per-request cost is the intersection with the claim, no database access on a hit (`HundredRequests_ReadTheRegistryOnce`, `ConcurrentFirstRequests_ShareOneRead`). Only **registered** scopes are cached — an arbitrary `scope` value never grows memory — and a failed read is never cached.
- **Rate limit:** per **subject** (`sub`), sliding window of `TenantTopology:RateLimitPermitsPerMinute` (default 60; env `OCTO_IDENTITY__TENANTTOPOLOGY__RATELIMITPERMITSPERMINUTE`). The ASP.NET rate-limiter middleware runs *before* authentication in this host and cannot see the subject, so the controller asks `ITenantTopologyRateLimiter` after the token was validated; an invalid token is answered 401 first and never allocates a partition.
- **CORS:** the identity CORS policy is global and built from the `AllowedCorsOrigins` of every client of every tenant (`IdentityCorsPolicyProvider`, any header, any method), so a browser app whose client lists its origin (meshmakers-app `${scheme}://${tenantId}-accounting.${domain}`, energy-community `${scheme}://energy-community.${domain}`) can preflight and call this route with its bearer header; pinned by `AppOriginOfASeedClient_CanPreflightAndCallTheRouteFromTheBrowser`. No change was needed.
- **Logs:** counts and the scope id only — never claims or token content.
- **Tests:** `TenantTopologyServiceTests` (intersection, depth, hasChildren, legacy case, every fail-closed branch, cache), `TenantTopologyApiControllerTests`, `TenantTopologyRateLimiterTests`, `TenantTopologyEndpointTests` (real Mongo hierarchy, wiring, CORS). Documentation for app developers is a separate story (octo-documentation). The repository has no CHANGELOG file; this section is the change record.

### `allowed_tenants` Identity Resource

The `allowed_tenants` claim is registered as an `IdentityResource` in `DefaultConfigurationCreatorService.CreateIdentityResources()`. This makes it available in **ID tokens** (not just access tokens) when the `allowed_tenants` scope is requested. Used by Grafana's `org_attribute_path` for automatic organization mapping.

### Multi-Tenant Auth Scheme Isolation

External identity provider schemes (Google, Microsoft, Azure Entra ID, Facebook, OpenLDAP, Microsoft AD) are registered in the singleton `IAuthenticationSchemeProvider` with tenant-prefixed names: `{tenantId}:{providerName}`. This ensures all tenants' schemes coexist without conflicts.

- **`DynamicAuthSchemeService`**: Uses `ISystemContext.FindTenantRepositoryAsync(tenantId)` to load providers directly from any tenant's database (bypassing the HTTP-scoped `IOctoIdentityProviderStore`). Only removes/adds schemes for the specified tenant prefix.
- **`DynamicAuthSchemeServiceInitializer`**: At startup, registers schemes for the system tenant and all child tenants (same pattern as `DefaultConfigurationInitializationService`).
- **`AuthApiController`**: Filters schemes by tenant prefix (`{tenantId}:`) in `GetLoginContext` and `GetExternalProviders` endpoints. The full prefixed scheme name is passed to the frontend and back for challenge/login calls.
- **`IdentityProviderUpdateConsumer`**: Runtime reconfiguration only affects the specific tenant's schemes.

### OAuth Grant Storage (per tenant)

OAuth grants (authorization codes, refresh tokens, device codes, remembered consents) are stored **per tenant** in the new CK types `RtOAuthAuthorization`/`RtOAuthToken` via `OpenIddictAuthorizationStore`/`OpenIddictTokenStore` (System.Identity-2.12.0, migration 21→22). Grants are NOT centralized — the old "Centralized Grant Storage" design (system-tenant `RtPersistedGrant` with tenant id in `Description` and a SHA-256 hash fallback) was already stale since AB#1586 and is fully gone with the OpenIddict migration.

Because grants live per tenant, the `/connect/token` request must be wired to the right tenant before the store is consulted — that is `OidcTenantResolutionMiddleware`'s job (see Token Endpoint Tenant Resolution below). Access tokens are plain JWTs and get **no DB entry**. `TokenCleanupHostService` sweeps expired sessions, OAuth token entries, and legacy grants for the system tenant plus all child tenants.

### Pushed Authorization Request (PAR) Tenant Resolution

When backend OIDC clients (built on `Microsoft.AspNetCore.Authentication.OpenIdConnect` .NET 9+) authenticate, they automatically use **PAR (RFC 9126)** if the IdP advertises a `pushed_authorization_request_endpoint` — which OpenIddict does (as Duende did before). This means the authorization parameters (including `acr_values=tenant:{tenantId}`) are POSTed to `/connect/par`, and the subsequent browser redirect to `/connect/authorize` contains only `request_uri=urn:ietf:params:oauth:request_uri:...` — no `acr_values` on the URL.

`OidcTenantResolutionMiddleware` handles this in two stages:
1. On `POST /connect/par`, it reads `acr_values` from the form body, then wraps the response to capture the issued `request_uri` from the JSON body, and stores the `request_uri → tenantId` mapping (5-minute lifetime)
2. On `GET /connect/authorize?request_uri=...`, it looks up the tenant from this mapping before falling back to query-string `acr_values`

Without this, every PAR-using client would land on `/tenant-discovery` because the URL no longer carries `acr_values`.

### Token Endpoint Tenant Resolution

The `/connect/token` endpoint has no `{tenantId}` route segment. To ensure `OctoUserStore`, `ClientStore`, and other per-tenant stores use the correct tenant database, `OidcTenantResolutionMiddleware` resolves the tenant per grant type. All capture stages work against OpenIddict responses (golden-verified):

**Authorization codes:**
1. During `/connect/authorize`, the middleware wraps the response body and captures the authorization code, mapping it to the tenant in an in-memory `ConcurrentDictionary` (10-minute expiry). Supports both `response_mode=query` (code from 302 Location header) and `response_mode=form_post` (code from hidden form field in 200 HTML response, used by server-side OIDC clients like the Asset Repository Services' GraphQL Playground)
2. During `/connect/token` with `grant_type=authorization_code`, the middleware reads `code` from the form body and looks up the tenant

**Refresh tokens (in-memory only, preferring `acr_values`):**
1. Clients that know their tenant (the SPAs) send `acr_values=tenant:{tenantId}` with every refresh request — this is the preferred, restart-safe path
2. As a fallback, when `/connect/token` returns a new refresh token, the middleware captures it in the in-memory cache (30-day expiry) and looks it up on the next refresh

The refresh-token→tenant mapping is **in-memory only** — there is no persistent SHA-256 hash fallback anymore (that mechanism was tied to the retired centralized `RtPersistedGrant` storage).

**Device flow:** the middleware captures `user_code` → tenant on `/connect/deviceauthorization` and resolves `/connect/deviceverification` requests from it. The `verification_uri` in device authorization responses is rewritten to the SPA page `/{tenant}/device` with `?userCode=`.

**`client_credentials` and token exchange:** `acr_values=tenant:{tenantId}` from the form body — required.

### Per-Tenant Cookie Scoping

Auth cookies are scoped per tenant via `TenantCookieManager` (`src/IdentityServices/Cookies/TenantCookieManager.cs`). This prevents cross-tenant session leakage by appending `.{tenantId}` to cookie names (e.g., `.AspNetCore.Identity.Application.sbeg`).

Key components:
- **`OctoAuthSchemes`** (`src/Authentication/`): the cookie schemes — `Identity.Application` (tenant-scoped by `TenantCookieManager`) and `Identity.External`. The Duende `idsrv` / `idsrv.session` / `idsrv.external` cookies no longer exist.
- **`TenantCookieManager`**: Custom `ICookieManager` that scopes the `Identity.Application` cookie per tenant
- **`OidcTenantResolutionMiddleware`**: Resolves tenant for `/connect/*` OIDC endpoints from `acr_values`, `id_token_hint`, user_code, or authorization code → tenant mapping
- **`OctoTokenClaimsService`**: Adds `tenant_id` and `allowed_tenants` claims to tokens (used by endsession for cookie resolution and by backend middleware for tenant authorization)

See `docs/authentication.md` for detailed architecture and edge cases.

### Multi-Tenant Token Validation

Access tokens include `allowed_tenants` claims listing all tenants a user may access. Backend middleware validates the route tenant against these claims.

Key components:
- **`IAllowedTenantsResolver`** / **`AllowedTenantsResolver`** (`IdentityServerPersistence/Services/`): Resolves allowed tenants at token issuance time: the login tenant, the home tenants a shadow user's `xt_{home}_{name}` chain unwinds to, and every descendant reachable through cross-tenant user mappings (BFS that follows the xt_ chain tier by tier). It does **not** add ancestors by walking the `OctoTenantIdentityProvider` graph (AB#5170): a provider says where a tenant delegates authentication to, not that its users exist up there, and the blanket walk offered a locally created operating-tenant user the management tenant and the platform root — in `allowed_tenants`, the Studio switcher and the email-first tenant discovery — where no account of theirs exists and the switch gate refuses them. Pinned by `tests/IdentityServices.IntegrationTests/Persistence/AllowedTenantsResolverIntegrationTests.cs`
- **`ITenantRegistry`** / **`TenantRegistry`** (`IdentityServerPersistence/Services/`, AB#6393): cached tenant registry (id → `OctoTenant`, 45 s `IMemoryCache`, one re-read at most every 5 s on an unknown id) that opens tenant repositories without I/O via `ISystemContext.GetRegisteredTenantRepository` — no existence probe, admin session or CK auto-import. Used by `AllowedTenantsResolver` and `CrossTenantAuthenticationService`. 🔴 An id that is not in the registry yields `null` (fail closed); never fall back to `FindTenantRepositoryAsync` for hot paths. The system tenant is not a registry entry and is handled separately.
- **`OctoTokenClaimsService`** (`IdentityServices/OpenIddict/`): Adds `allowed_tenants` claims to all issued tokens (replaces the former `UserProfileService`)
- **`TenantAuthorizationMiddleware`** (`octo-common-services`): Validates route tenant against `allowed_tenants` claims; registered after `UseAuthorization()` in all backend services

The resolver algorithm: (1) always includes the login tenant; (2) for cross-tenant users (xt_), includes the home tenant; (3) walks up the ancestor chain from the login tenant via `RtOctoTenantIdentityProvider.ParentTenantId`; (4) BFS down through descendant tenants, checking `ExternalTenantUserMapping` by `SourceTenantId` + `SourceUserName` and following the `xt_{parentTenantId}_{parentUsername}` naming chain through each tier. This ensures cascading tenants (e.g., `octosystem → meshtest → subtenant1`) include both ancestors and descendants in `allowed_tenants`.

See `docs/authentication.md` § "Multi-Tenant Token Validation" for full architecture details.

### Multi-Tenancy

### Identity Provider REST API (IdentityProvidersController)

The `IdentityProvidersController` exposes CRUD endpoints for identity provider configurations at `{tenantId}/v1/identityProviders`. All provider types are serialized/deserialized via JSON polymorphism on `IdentityProviderDto`:

| Provider Type | DTO | Enum Value |
|--------------|-----|------------|
| Google | `GoogleIdentityProviderDto` | 0 |
| Microsoft | `MicrosoftIdentityProviderDto` | 1 |
| Azure Entra ID | `AzureEntraIdProviderDto` | 2 |
| Microsoft AD | `MicrosoftAdProviderDto` | 3 |
| OpenLDAP | `OpenLdapProviderDto` | 4 |
| Facebook | `FacebookIdentityProviderDto` | 5 |
| Octo Tenant | `OctoTenantIdentityProviderDto` | 6 |

`OctoTenantIdentityProviderDto` has a `ParentTenantId` property identifying the parent tenant for cross-tenant authentication. `IdentityProviderDtoMapper` / `IdentityProviderEntityMapping` (`src/IdentityServices/Mapping/`) map between `RtOctoTenantIdentityProvider` and `OctoTenantIdentityProviderDto`.

### Multi-Tenancy

The service supports multi-tenancy via tenant ID in routes. The route pattern is `{tenantId:tenantId=System}/{controller=Home}/{action=Index}/{id?}`.

### API Versioning and Route Prefix

All API endpoints use a single tenant-scoped route prefix: `{tenantId:tenantId}/v{version:apiVersion}` (e.g., `octosystem/v1` for the default system tenant, `MyTenant/v1` for a specific tenant). The system tenant ID defaults to `OctoSystem` (normalized to lowercase in URLs) and is configurable via `OctoSystemConfiguration.SystemTenantId`.

Authorization policies (`src/IdentityServices/Authorization/IdentityApiAuthorizationPolicies.cs`, AB#5859):
every administration endpoint requires the `octo_api` scope (read: or `octo_api.read_only`) **and** a
tenant role — `UserManagement` for users/roles/groups/mappings/data permissions, `TenantManagement` or
`UserManagement` for clients/mirrors/API resources/scopes/secrets/identity providers/e-mail domain rules/
admin provisioning, the operational roles for directory reads (role names, a client's roles/actors), and
`TenantManagement` in the system tenant for the log level. Exception: `GET users/directory` (id + display
name only, for assignee pickers) needs no role but `IdentityUserDirectoryReadPolicy` — the token's `tenant_id`
must equal the route tenant, unconditionally (`IdentityApiOwnTenantRequirement`); the guard pins it. The role check probes the raw `role` claim and
`ClaimTypes.Role` (RoleClaimType trap, AB#4969/AB#5539). `OCTO_IDENTITYAPIAUTHORIZATION__ROLEENFORCEMENT=Warn`
logs instead of denying (transition); default `Enforce`. 🔴 A new controller action must use one of these
policies — `IdentityApiAuthorizationPolicyTests.EveryTenantApiEndpoint_RequiresARole_UnlessExplicitlyAllowListed`
fails otherwise. Full table: `docs/system-api.md` § Authorization Policies.

**API secret writes need `SecretManagement` (AB#5861).** `IdentitySecretAdministrationPolicy` (scope `octo_api` +
`SecretManagement`, shared `IdentityApiAuthorizationPolicies.SecretAdministrationRequirement`) guards every create/rotate/
delete in `ApiSecretsController`, the mirror secret rotation (`ClientMirrorController.RotateSecret`), a `clientSecret` in `POST/PUT clients` (checked in the action via
`IAuthorizationService`) and the `Client.AddSecret`/`RemoveSecret` handlers (`DecideClientSecretCaller`; the CK model's
declared roles stay `TenantManagement`/`UserManagement`). Reads keep `IdentityTenantAdministrationReadPolicy`. Staged by
`OCTO_IDENTITYAPIAUTHORIZATION__SECRETMANAGEMENTROLEENFORCEMENT` = `Warn` (**default**: the previous roles still pass,
logged `...SecretManagementRoleEnforcement=Enforce (AB#5861)`) | `Enforce` — because the role was granted only once to
local human admins (AB#5544), not to `TenantOwners`, cross-tenant admins or clients. `Warn` never allows less than
before; `RoleEnforcement=Warn` relaxes it too. A refused `IdentityApiRoleRequirement` answers 403
`{"message": "...requires the role 'X'..."}` (`IdentityApiForbiddenReasonResultHandler`, AB#5227 shape). Tests:
`ApiSecretsControllerTests` (role x verb x kind x mode matrix, TenantOwners member, client create/update),
`IdentityApiAuthorizationPolicyTests`. Inventory: `scripts/identity-secret-management-role-check.sh`.

### Bootstrap blueprint lines and version order (AB#5544, AB#6457)

`System.Identity.Bootstrap` carries two independent lines that each bump exactly once, in a fixed order
(decision Gerald 2026-10-11): the **Files line** is 1.5.0 (FileManagement/FileViewer roles 660…61/62) and 1.6.0
(System.Files data permissions/policies 660…52–55, FileManagement for pipeline service accounts); the **SECRET
line** is **1.7.0** (SecretManagement role 660…60 and its grants) on top of it. There is no 1.4.0. The CK model
follows the same rule: 2.23.0/2.24.0 belong to the ownership markers (AB#6324/6443/6384), **2.25.0** turns the
identity-provider `ClientSecret` into the Secret value type (AB#5540). Whoever bumps next re-bumps above the
published maximum (`octo-ckc -c ValidateVersion` against the catalogs). The upgrade path is pinned by
`BootstrapUpgradeToSecretLineIntegrationTests` (frozen 1.5.0 / 1.6.0 seed snapshots under
`tests/IdentityServices.IntegrationTests/BootstrapSnapshots/`): nothing is lost, and from 1.6.0 the delta is exactly the
SecretManagement role (no TenantOwners edge: human administrators only) and the direct grants to existing local administrators. A new bootstrap version
that changes seeds should add its own snapshot.

## Logging: credentials never reach a log property (AB#5792)

`nlog.config` renders JSON with `includeEventProperties="true"`, which serializes every message-template
argument **by reflection over its public properties** — bypassing any redacting `ToString()`. Two leaks
followed from that, both closed:

- **OpenIddict messages (INFO).** `OpenIddictServerDispatcher` logs `{Response}` / `{Request}`; the message
  text was redacted, but the JSON property carried `AccessToken`, `IdToken`, `RefreshToken`, `client_secret`
  and `code` in clear text. `Program.cs` calls `RegisterSecretRedaction()` (`Logging/LogSecretRedaction.cs`)
  **before** `LoadConfigurationFromFile`: an NLog object transformation renders `OpenIddictMessage`,
  `OpenIddictRequest` and `OpenIddictResponse` through their own redacting `ToString()` in every layout.
  Register new secret-bearing library types there, not in the layout.
- **API DTOs (TRACE).** ASP.NET Core logs action arguments through `ToString()`; the compiler-generated
  record `ToString()` printed `Password`, 2FA `Code`, `RecoveryCode`, `Token`, `SharedKey`. Every DTO in
  `Controllers/Api` with such a string member overrides
  `protected virtual bool PrintMembers(StringBuilder) => RedactingDtoPrinter.Print(this, builder)`, which
  prints `[REDACTED]` for any member whose name matches `Password|Code|Secret|Token|SharedKey`.
  🔴 **A new DTO with such a member needs that one line** — `SensitiveDtoToStringTests` scans the whole
  namespace by reflection and fails for a DTO that renders the value.

Tests: `tests/IdentityServices.UnitTests/Logging/LogSecretRedactionTests.cs` runs the **real**
`nlog.config` (Console target swapped for a memory target) and includes a control that proves the leak
without the registration; `tests/IdentityServices.UnitTests/Controllers/SensitiveDtoToStringTests.cs`.
🔴 The DTO mechanism protects `ToString()` output only (the text ASP.NET Core logs), **not** NLog event
properties: a credential-bearing DTO passed as a message-template argument (`{Dto}` / `{@Dto}`) is still
reflected by the JSON layout. Never do that unless an NLog object transformation in
`LogSecretRedaction` covers the type; log selected non-secret members instead.

**Token values (AB#8324, Security).** OpenIddict logs issued tokens as plain string arguments at Trace/Debug
(EventId 6013 `A new '{Type}' JSON Web Token was successfully created: {Payload}.` = the complete signed access
token; also `{Token}`, `{ReferenceId}`), which the object transformation above never sees. `CredentialLogRedaction`
(the `ILoggerFactory` decorator of AB#8008) therefore also masks, for every provider and level: JWT-shaped values
(JWS/JWE, `eyJ…`) and Data Protection payloads (`CfDJ8…`) in every string value and in the formatted message of any
state; every value whose argument name is in `CredentialLogRedaction.TokenValueNames` (opaque reference tokens;
not `Code`, the dev OTP stub logs its code on purpose); `Payload` in `OpenIddict.*` categories only. The line stays
with `***`. Not covered: exception texts (IdentityModel hides token content unless `ShowPII`, Development only).
🔴 A new log line that carries a token must use one of those argument names or rely on the shape rule; never log a
token under another name in a non-JWT shape. Tests: `Logging/TokenLogRedactionTests` (shapes, names, OpenIddict
templates, non-list state, real `nlog.config` JSON record at Trace) and
`Api/Protocol/TokenValuesNotInLogTests` (real token endpoint at Trace: the issued access token, its signature and
the client secret are in no line; the 6013 line is present and masked).

### Administrator switches off a user's second factor (AB#7879; System.Identity 2.30.0)

The recovery path of AB#7830 (option a). `IUserTwoFactorAdministrationService` (`Services/UserTwoFactorAdministrationService.cs`, scoped) is
the one implementation; two transports call it:

| Transport | Caller rule | Answer |
|---|---|---|
| CK method `User.DisableTwoFactor-1` (`UserDisableTwoFactorHandler`, one row in `IdentityMethodHost.Handlers`, `CarriesSecret = false`: hosted whatever `EnablePasswordMethods` says) | `IdentityAdminMethodHandlerBase`: scope `octo_api` + `UserManagement` on the validated principal, `METHOD_FORBIDDEN` / `role-required` before the target is read | success; `METHOD_TARGET_NOT_FOUND`; `METHOD_HANDLER_FAILED` when a write or the revocation fails |
| REST `POST {tenant}/v1/users/{userName}/disableTwoFactor` | `IdentityUserAdministrationWritePolicy` | `200 { twoFactorWasEnabled }`, 404 unknown user |

Effect, in this order, all through `UserManager` (guarded, versioned store writes of AB#7908, never the entity): remove the authenticator
key and the recovery codes (`[AspNetUserStore]` tokens `AuthenticatorKey`, `RecoveryCodes`), `TwoFactorEnabled = false`, then
`IUserCredentialChangeService.OnSecondFactorDisabledAsync` (the AB#7765 helper: security stamp, revocation of every refresh token and
authorization of the user in this tenant, one `Information` audit line `Second factor switched off by an administrator: tenant, subject,
acting user, path (AdminRest|MethodDisableTwoFactor), two-factor was enabled`). Idempotent (a user without 2FA gets the same treatment).
Any failure throws: never a success while the key or old refresh tokens survive. The method writes the `Identity.Method` event with the
extra detail `twoFactorWasEnabled`. No key, code or token value is logged or audited. The user's own `POST api/manage/2fa/disable`
(with a verification code) is unchanged. No self rule: an administrator may switch off their own second factor (the REST endpoint never
had one either). Tests: `Api/Methods/UserDisableTwoFactorMethodTests` (method and REST on real MongoDB: end to end with sign-in by password
and a new enrolment over HTTP, idempotent, service token, caller theory for existing and missing target, unknown target, failing revocation,
forged caller, REST 404/403, no authenticator material in audit or logs).

### `User.CreateUser` and the only ways to create a user (AB#7777)

A user is created only by this service: the static CK method `User.CreateUser-1` (REST `POST {tenant}/v1/users` is its facade since AB#8413)
(`UserCreateUserHandler`, one row in `IdentityMethodHost.Handlers`, `CarriesSecret = true` because of the optional `sensitive`
`password`: **offered on the bus only with `Methods:Identity:EnablePasswordMethods`**, also for invitations without a password - the
switch is per method; off = `METHOD_HANDLER_NOT_AVAILABLE` for the gateway, while the handler is hosted local only for the REST facade,
AB#8413). Both share `IUserCreationService` (`Services/UserCreationService.cs`, scoped):
`UserManager.CreateAsync` with or without the password (user validators, password policy before the user is stored, normalised name
and e-mail, security stamp), then the welcome notification (with password: e-mail confirmation; without: the invitation to set a
password). Since AB#8064 the service also refuses an e-mail address another user of the tenant already has (see the table).

| Rule | REST | Method |
|---|---|---|
| Caller | `IdentityUserAdministrationWritePolicy` | `IdentityMethodCallerRules.IsAdministrator` on the validated principal (scope `octo_api` + `UserManagement`), `METHOD_FORBIDDEN` / `role-required`; the gateway refuses a caller without the declared role first; a forged bus caller is rejected by the host |
| `xt_` user name | 400 | `USER_NAME_RESERVED` |
| Duplicate user name (AB#8083, case-insensitive; also `PUT users/{userName}` when it renames) | `409 application/problem+json`, `code: USER_ALREADY_EXISTS`, `field: userName` (`UserCreationProblems.DuplicateUserName`; the name is not echoed or logged) | `USER_ALREADY_EXISTS`, parameter `field=userName` |
| Duplicate e-mail (AB#8064, normalised = case-insensitive; blank e-mail not checked) | `409 application/problem+json`, `code: USER_ALREADY_EXISTS`, `field: email` (`UserCreationProblems`; the address is not echoed or logged) | `USER_ALREADY_EXISTS`, `field=email` |
| Password policy | 400 with the identity errors | `PASSWORD_POLICY_VIOLATION`, details = rule codes only |
| Missing / invalid user name or e-mail | 400 | `METHOD_VALIDATION_FAILED` (`field`) |
| Result | `200` (empty) | rtId of the new user (`UserCreateUserResult.Value`); on the wire `resultJson` is the bare JSON string `"<rtId>"` (AB#8079, host of octo-common-services), so the GraphQL `result` is the rtId itself |

**Duplicate e-mail: only new conflicts are refused (AB#8064 create, AB#8084 change).** The rule lives in `UserEmailUniqueness`
(`Services/UserEmailUniqueness.cs`); `UserCreationService` uses it (`IdentityResult.Failed(DuplicateEmail)`), so REST and method cannot drift. A taken user name wins (the check runs only when the name is
free), so creating the same user twice answers `409` with `field=userName` on REST (before AB#8083: `400 DuplicateUserName`). The controller maps the identity error `DuplicateUserName` (create and rename; the user validator raises it on update too). `IdentityOptions.User.RequireUniqueEmail` stays **off** on
purpose: the user validator runs on every `UserManager.UpdateAsync` / `SetEmailAsync` / `SetUserNameAsync` too, and in a tenant that
already holds two users with one address `FindByEmailAsync` returns one of them, so the other could no longer be updated (profile edit,
role change, security-stamp write, password change). Existing duplicates are not migrated; updates and sign-in of those users are
unchanged (`FindByEmailAsync` returns the first match, as before).

**E-mail change (AB#8084).** `PUT users/{userName}` refuses a **change** of the address to one another user has with the same
`409` (`UserCreationProblems.DuplicateEmail`, logged without the address), before anything is written. `UserEmailUniqueness.ChangesAddress`
decides what a change is: the new address is not blank and differs normalised from the stored `Email` (not from `NormalizedEmail`,
which a stale write could leave behind); keeping the address, changing only its casing and clearing it are not checked, so users
that already share an address stay editable. The owner found by `FindByEmailAsync` must be another `RtId`. Other e-mail write paths,
checked for this story: no CK method changes the e-mail (System.Identity 2.30.0), `Email` is `MethodOnly` (generic GraphQL, `ImportRt`,
blueprint seeds and pipelines cannot write it), `ManageApiController` has no e-mail change, the self-service e-mail enrolment
(`SelfServiceIdentifierService`) writes a verified identifier, not `RtUser.Email`.

**Deliberately not checked (existing decisions, product decision needed to change them):**

| Path | Behaviour | Why |
|---|---|---|
| External-login and LDAP auto-provisioning (`AuthApiController.CreateUserFromExternalProvider`) | creates a separate `{Provider}_{email}` user even when a local user has the address | Bug 3430 (`docs/authentication.md` § External Login Security Model): never link by e-mail (privilege escalation); refusing would lock the external user out |
| Cross-tenant shadow users (`CrossTenantUserProvisioningService`) | created with, and synced on every login to, the home user's address | a dedicated account of the home identity (excluded from tenant discovery); refusing locks the person out of the child tenant, linking would hand a local user's roles to the home identity |
| Tenant admin bootstrap (`UserManagementService`) | not checked | runs only in a tenant without users |

Pinned by `CrossTenantUserProvisioningServiceTests.FindOrCreate_LocalUserWithTheSameEmail_*` / `…_SyncsAnEmailAnotherUserHas` and
`ExternalLoginDeduplicationTests`. Check and write are not atomic (no unique index on runtime entities). Tests:
`Api/TenantApi/UsersCreateTests` (409 also in other casing, name keeps 400, no e-mail not checked, legacy duplicates update and sign in),
`Api/TenantApi/UsersUpdateEmailTests` (change to a taken address 409 also in other casing and from no address, nothing written; free
address, clearing, legacy duplicates keep / re-case their address, a sharing user cannot move to another taken address) and
`Api/Methods/UserCreateUserMethodTests`.

Audit: one `Identity.Method` event per call (success, every refusal, `METHOD_HANDLER_FAILED`), `targetRtId` = the new user (success
only), details `userName`, `withPassword`. The password reaches only the user manager - never a log, audit record or error parameter.
`ResetPasswordOnLogin` is `false` (REST default).

**The generic paths refuse a new user** (engine `GenericCreateReplacement`, driven by `replacesGenericCreate` of `User.CreateUser-1` since System.Identity 3.0.0, AB#8053; AB#7777 used a runtime rule until 2.30.0):
GraphQL generic/typed/query-row create, MCP create, mesh-adapter inserts, caller `ImportRt` and blueprint seeds answer
`GENERIC_CREATE_REPLACED_BY_METHOD` naming `System.Identity/User.CreateUser-1`; an existing user (rtId stored) is updated as before.
Nothing in this service is affected (repository writes are not generic paths). Tests:
`Api/Methods/UserCreateUserMethodTests` (real MongoDB, host with the switch on: password user signs in, normalised fields and stamp,
invitation without password, duplicate name (also other casing) and e-mail, policy, reserved name, validation, caller theory, service
token, forged caller, audit, welcome notification, no password in audit or logs), `Methods/IdentityMethodHostTests`,
`IdentityMethodDeclarationsIntegrationTests` (declared role `UserManagement`, flag still off), `Api/Methods/UserCreateUserWireFormTests` (AB#8079: the envelope through the real host core, in-process transport, carries the bare rtId string, not `{"value": ...}`).

### `User.Merge` and the one merge of a duplicate user (AB#7778)

REST `POST {tenant}/v1/users/{userName}/merge` and the CK method `User.Merge-1` (`UserMergeHandler`, one row in
`IdentityMethodHost.Handlers`, `CarriesSecret = false`: hosted whatever `EnablePasswordMethods` says) share `IUserMergeService`
(`Services/UserMergeService.cs`, scoped). The model declares the method since 2.29.0; no CK change.

Steps of the service, in this order: same user = `SameUser` (nothing written); role change guard on the **deletion** of the source user
(`RoleChangeRequest(caller, source, directRoles, null)`, AB#7914: `last-administrator`); every external login removed from the source and
added to the target (remove first: `AddLoginAsync` refuses a login another user still owns); `IUserSessionRevocationService.RevokeAsync(source)`
(security stamp, refresh tokens, authorizations, server-side sessions of the source in this tenant; new for REST too); `DeleteAsync(source)`.
**Nothing else moves**: roles, group memberships, claims and cross-tenant mappings of the source go away with it, so a merge never grants
the target a role and the guard only has to judge the deletion.

| Rule | REST | Method |
|---|---|---|
| Caller | `IdentityUserAdministrationWritePolicy` | `IdentityAdminMethodHandlerBase` (scope `octo_api` + `UserManagement` on the validated principal, `role-required` before the target is read); forged bus caller rejected by the host |
| Target | by name, 404 | target rtId, `METHOD_TARGET_NOT_FOUND` |
| Source | by name, 404 | `SOURCE_USER_NOT_FOUND`; missing `sourceUserName` = `METHOD_VALIDATION_FAILED` |
| Source data permission (AB#7035) | none | `IRtDataPermissionEvaluator` on the source user: not readable = `SOURCE_USER_NOT_FOUND`, not writable = `METHOD_FORBIDDEN` / `data-permission` (stricter, never looser; open without enforcing policies) |
| Same user | 400 | `CANNOT_MERGE_INTO_ITSELF` |
| Guard | 409 problem `last-administrator` + `Identity.RoleChangeRefused` | `METHOD_FORBIDDEN` / `reason` |
| Login or delete failure | 400 with the identity errors | `MERGE_FAILED`, parameters `step` (`removeLogin` / `addLogin` / `deleteSource`) and `loginProvider`, details = error codes |

Audit: one `Identity.Method` event per call with `sourceUserName`, `sourceRtId`, `transferredLogins`, `revokedTokens` (and `reason` for
a refusal); the revocation writes its own log line with the acting user. A failing revocation throws (REST 500, method
`METHOD_HANDLER_FAILED`) before the source is deleted. Tests: `Api/Methods/UserMergeMethodTests` (REST and method on identical fixtures
compared state by state, audit, every refusal, data permission, last administrator, forged caller, `MERGE_FAILED` mapping),
`Api/TenantApi/UsersMergeTests` (REST), `RoleChangeGuardTests` (REST guard). Since this handler every declared System.Identity method has
one; `UserChangePasswordMethodTests.AMethodWithoutHandler_…` uses an undeclared id.

### REST facades of the role and merge endpoints (AB#8412)

`UsersController.UpdateUserRoles` (`PUT users/{u}/roles`), `AddUserToRole` (`PUT users/{u}/roles/{r}`), `RemoveRoleFromUser`
(`DELETE users/{u}/roles/{r}`) and `MergeUsers` (`POST users/{u}/merge`) are **facades** of `User.SetRoles-1`, `User.AddRole-1`,
`User.RemoveRole-1` and `User.Merge-1`. They contain no role-change or merge rule of their own (no `AddToRoleAsync`,
`RemoveFromRoleAsync` or `IUserMergeService` call): they resolve the user name to the rtId (and SetRoles the role ids to names),
call the method through `IIdentityMethodFacade` (`src/IdentityServices/Methods/IdentityMethodFacade.cs`) and map the envelope with
`CkMethodFacadeResults.ToActionResult` (octo-common-services, AB#8411) plus per-endpoint `CkMethodFacadeOptions`.

- **In-process.** `IdentityMethodHost.AddIdentityCkMethodHost` registers `AddCkMethodDispatcher()` and the facade; `Program.cs` adds
  `AddCkMethodHandlerRegistryFeed()` to the event hub. The identity service hosts the handlers, so the dispatcher runs them in this
  process (transport `in-process`, nothing on the broker, same invocation core as a bus call: declared authorization, validation,
  audit, `ck.method.*` metrics). The four methods carry no secret and are hosted whatever `Methods:Identity:EnablePasswordMethods`
  says, so the endpoints work on every cluster. AB#8413 (create, reset - see the next section) and AB#8414 reuse
  `IIdentityMethodFacade` (password methods with `HandleLocalOnly` while the switch is off).
- **Caller.** `CkMethodPrincipal.FromClaimsPrincipal(User)` in a `CkMethodPrincipalScope`. The write policy of the endpoints already
  requires scope `octo_api` and role `UserManagement`, which is what the handlers check again; no token reaches the facade without it.
- **Audit.** Every REST call writes exactly one `Identity.Method` event (the handler's). A guard refusal (`METHOD_FORBIDDEN` with
  `reason` `self-grant` / `role-not-held` / `last-administrator`) is turned back into the AB#7914 answer: 403/409 problem+json via
  `RoleChangeProblems`, the WARN log and the `Identity.RoleChangeRefused` record (REST contract, kept).

Parity table (REST before -> facade; the method wins unless the REST contract would change):

| Point | REST before | Now |
|---|---|---|
| Routes, request and response bodies, status codes | - | unchanged (success `200` empty, `MapSuccess`) |
| User / role not found | 404 `NotFoundErrorDto` | unchanged: resolved in the controller; `METHOD_TARGET_NOT_FOUND` / `ROLE_NOT_FOUND` (race) map to the same 404 |
| SetRoles unknown role id | 404, nothing changed | unchanged (ids resolved before the call) |
| AddRole of a role held **through a group** | 400 "already has role" (`IsInRoleAsync`) | **kept** in the facade (read-only `IsInRoleAsync` pre-check); the method alone would add the direct role |
| RemoveRole of a role held **only through a group** | 200, nothing changed | **kept**: `ROLE_NOT_ASSIGNED` maps to 200; audit outcome `ROLE_NOT_ASSIGNED` |
| Guard refusals | 403/409 problem, `Identity.RoleChangeRefused`, WARN | unchanged, plus the `Identity.Method` event |
| Audit of a success | none | one `Identity.Method` event (`rolesBefore`/`rolesAfter`; merge: `sourceUserName`, `sourceRtId`, `transferredLogins`, `revokedTokens`) |
| Merge source data permission (AB#7035) | none | method wins: not readable = 404 "Source user ... not found", not writable = 403 problem `METHOD_FORBIDDEN` (`data-permission`) |
| Merge login/delete failure | 400, `failedDetails` with code + description | 400, same message, `failedDetails` with `code` only (the envelope carries codes) |
| Unexpected failure | merge: 500 `InternalServerErrorDto(exception message)`; roles: unhandled 500 | merge: 500 `InternalServerErrorDto("Merging the users failed.")`; roles: 500 problem `METHOD_HANDLER_FAILED`; no exception text leaves the service |
| `RoleEnforcement=Warn` (not the default) | caller without `UserManagement` let through and logged | refused by the method (403 problem, `role-required`) |
| Merge `sourceUserName` | as sent | trimmed by the method |

Fix on the way: `UserMergeHandler` looked the acting user up by `sub` and threw for a subject that is no object id; it now skips
the lookup. Tests: `Api/TenantApi/UserRestMethodFacadeTests` (one `Identity.Method` event per REST call incl. refusal and merge,
REST and the dispatcher call side by side, in-process transport, both switch values, group-inherited role contract) plus the
unchanged REST suites (`RoleChangeGuardTests`, `UsersMergeTests`, `UserRoleMethodParityTests`, `TenantApiRoleAuthorizationTests`).
`UserMergeMethodTests.Method_MergingAwayTheLastUserAdministrator…` now expects two `Identity.Method` events (its method call and its
REST call each write one).

### Deprecation of the role and merge endpoints: identity wave 1 (AB#8415)

The four endpoints above carry `[OctoRestDeprecated(Wave = IdentityRestDeprecation.UsersWave1, Link = …)]`
(`src/IdentityServices/TenantApi/v1/IdentityRestDeprecation.cs`; octo-common-services `docs/rest-deprecation.md`). Links:
`User.SetRoles/AddRole/RemoveRole` -> `…/identityService/methods#user-roles`, `User.Merge` -> `…#usermerge`.

- **No dates in code.** Gerald's rule (2026-11-07): deprecated from the delivery of the release that contains it, sunset one
  week after that release runs on prod-1 **and** prod-2. Both dates come from `RestDeprecation:Waves:IdentityUsers1:Since|Sunset`
  (env `OCTO_RestDeprecation__Waves__IdentityUsers1__Since|Sunset`, Helm `restDeprecation.waves.IdentityUsers1.since|sunset` in
  octo-helm-core). Unset -> no `Deprecation`/`Sunset` header; `Link`, OpenAPI `deprecated` and the counter
  `octo.rest.deprecated.calls` always apply. An invalid configured date fails the start.
- **Not in this wave**: `POST users` and `POST users/ResetPassword` (password, AB#8418 after B0) and the account pages of
  `ManageApiController` (facades without deprecation, Odin 2026-11-07). AB#8418 decides whether they join `IdentityUsers1`
  (same release) or get a wave of their own (another release, other dates).
- **Tests**: `Api/TenantApi/UsersRestDeprecationTests` — headers per endpoint with and without configured dates, a counted
  successful call (`client_id` `octo-cli`, endpoint template, no user name or tenant), unmarked user endpoints without headers,
  exactly the four endpoints carry the attribute.

### REST facades of create user and password reset (AB#8413)

`UsersController.Post` (`POST users`) and `UsersController.ResetPassword` (`POST users/ResetPassword`) are **facades** of the static
`User.CreateUser-1` and of `User.ResetPassword-1`, through `IIdentityMethodFacade` like the role and merge endpoints (AB#8412; the target
rtId is `null` for the static create). Creation, policy, lockout, session revocation and audit exist only in the handlers.

- **Password in-process only, whatever the switch says.** With `Methods:Identity:EnablePasswordMethods=false` (staging-1, prod-1, prod-2
  until B0) the two handlers are registered with `HandleLocalOnly` (`IdentityMethodHandlerRegistration.ServesRestFacade`,
  `IdentityMethodHost.SelectLocalOnlyHandlers`): not announced, no queue, so GraphQL `User.CreateUser` / `User.ResetPassword` still answer
  `METHOD_HANDLER_NOT_AVAILABLE` and no password reaches the broker. With the switch on they are bus handlers and the dispatcher still runs the
  REST call in-process (AB#8411). One row in `IdentityMethodHost.Handlers` stays the single list (`For<THandler>(id, carriesSecret,
  servesRestFacade)` builds both registration forms).
- **Notification.** The method does not send the password-reset notification yet (AB#7775); the facade sends it after a success. When
  AB#7775 lands, remove that call: `UserPasswordRestMethodFacadeTests` counts exactly one notification per REST reset.
- **REST-only field.** `RegisterUserDto.ResetPasswordOnLogin` has no method parameter; when true the facade sets it on the new user after the
  method returned (the rtId is the bare result string). If the user is not found or that update fails, the endpoint answers `500`
  (`ResetPasswordOnLoginNotSetMessage`), never `200` — the user then exists without the flag (`RestCreate_ResetPasswordOnLoginWriteFails_Is500_NotASilentSuccess`).
- **Error bodies.** The envelope carries only rule codes; the facade rebuilds the REST `details` (code + description) of a policy violation or an
  invalid user name / e-mail from `UserManager.ErrorDescriber` and the password options, so `OperationFailedErrorDto` keeps its shape.

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, request and response bodies, status codes | - | unchanged (create and reset: `200` empty) |
| `EnablePasswordMethods=false` | own code, worked | works: handlers local only, in-process, nothing on the broker |
| Password in the query string (AB#8008) | 400 | unchanged (`[RefuseCredentialInQuery]`, `CredentialsNotInUrlTests`) |
| Create without password | 400 (model validation, `Password` is `[Required]`) | unchanged; an invitation without password stays method-only |
| Create: user name / e-mail | stored as sent | trimmed by the method; a blank e-mail is stored as `null` |
| Create: duplicate name / e-mail | 409 problem `USER_ALREADY_EXISTS`, `field` | unchanged (`USER_ALREADY_EXISTS` mapped by `field`) |
| Create: reserved `xt_` name | 400 message | unchanged (pre-check; `USER_NAME_RESERVED` maps to the same answer) |
| Policy violation / invalid name or e-mail | 400 `OperationFailedErrorDto`, details code + description | unchanged (descriptions rebuilt from the codes) |
| Create: welcome notification | once | once (`IUserCreationService` in the handler) |
| Reset: lockout | left in place | **lifted** (`LockoutEnd = null`, `AccessFailedCount = 0`) |
| Reset: sessions | revoked (`PasswordChangePath.AdminResetPassword`) | revoked (`PasswordChangePath.MethodResetPassword` in the "Password changed" log line) |
| Reset: acting user in that log line (AB#8008) | `AuditActor`: `preferred_username`, else `client <id>` | user name looked up from `sub`, else `client <id>`, else the subject |
| Reset: notification | once | once (facade, until AB#7775) |
| Reset: unknown user / shadow user | 404 / 400 | unchanged (pre-checks; `METHOD_TARGET_NOT_FOUND` / `SHADOW_USER_PASSWORD_NOT_ALLOWED` map to the same) |
| Audit | none (reset: the credential-change log line) | one `Identity.Method` event (create: `userName`, `withPassword`; reset: `lockoutLifted`) |
| Unexpected failure | 500 `InternalServerErrorDto(exception message)` | 500 `InternalServerErrorDto("Creation of user failed." / "Reset of password failed.")`, no exception text |
| `RoleEnforcement=Warn` (not the default) | caller without `UserManagement` let through and logged | refused by the method (403 problem) |

Fix on the way: `UserResetPasswordHandler` looked the acting user up by `sub` and threw for a subject that is no object id (like
`User.Merge`, AB#8412); it now skips the lookup. Tests: `Api/TenantApi/UserPasswordRestMethodFacadeTests` (both switch values: locked-out
user reset over REST - sign-in, lockout lifted, refresh tokens revoked, one audit event, one notification, no `CkMethodRequest` on the event
hub, canary absent from logs, audit and activity tags; REST create the same; policy violation; REST and dispatcher side by side for create
with password, invitation, duplicate name and e-mail, policy violation, unknown user, shadow user), `Methods/IdentityMethodHostTests`
(local-only selection, registration forms, never both), plus the unchanged REST suites (`UsersCreateTests`, `ShadowUserPasswordTests`,
`CredentialsNotInUrlTests`, `PasswordChangeRevokesSessionsTests`, `TenantApiRoleAuthorizationTests`).

### Account pages run the password methods (AB#8414; System.Identity 3.2.0)

`ManageApiController.ChangePassword` (`POST {tenant}/api/manage/change-password`) and `ManageApiController.SetPassword`
(`POST {tenant}/api/manage/set-password`) - the backend of the identity account SPA, session cookie, same origin - are **facades** of
`User.ChangePassword-1` and of the new `User.SetPassword-1` (`UserSetPasswordHandler`). They stay facades **without deprecation**
(Odin, 2026-11-07: same-origin account pages, not a public API). Password rules, lockout, session revocation and audit exist only in
the handlers.

- **`User.SetPassword-1`** (`ck-user.yaml`, System.Identity 3.2.0, additive Minor): `allowSelf`, `newPassword` sensitive, errors
  `PASSWORD_POLICY_VIOLATION`, `PASSWORD_ALREADY_SET`, `SHADOW_USER_PASSWORD_NOT_ALLOWED`. Self only like `ChangePassword` (the handler
  answers `METHOD_FORBIDDEN`/`not-self` before any lookup, also for an administrator). Order: tenant, user, shadow user, existing password
  (`PASSWORD_ALREADY_SET`: without a current password this method never replaces one), `AddPasswordAsync`, then
  `IUserCredentialChangeService.OnPasswordChangedAsync(..., PasswordChangePath.MethodSetPassword, ...)`. One audit event per call.
- **Caller of the cookie path.** A session cookie carries no OAuth scope, and the evaluator requires `octo_api` for every call.
  `IIdentityMethodFacade.InvokeForAccountOwnerAsync` therefore builds the caller itself: subject = the cookie's user id, **no role**,
  scope `octo_api` only, target = that user. With no role the declaration can admit it only through `allowSelf` on its own user - never
  an administrator path, never another user. The facade refuses (`METHOD_FORBIDDEN`, no call) a principal that is not an authenticated
  `Identity.Application` identity or whose user id is not the target. No evaluator change; the token path is unchanged: a bearer token
  never reaches the account endpoints (their default scheme is the cookie), and through GraphQL a token without `octo_api` gets
  `METHOD_FORBIDDEN` (`AccountPasswordMethodFacadeTests.ATokenWithoutTheApiScope_*`).
- **Switch.** Both rows of `IdentityMethodHost.Handlers` carry `ServesRestFacade = true`: with `EnablePasswordMethods=false` they are
  registered local only (in-process, no queue, not announced), so the account pages work and no password reaches the broker.
- **Session.** The method rotates the security stamp; the controller re-reads the user and calls `RefreshSignInAsync` with it, so the
  page's own cookie carries the new stamp and stays valid while every other session ends at its next stamp validation.
- **Answers.** The pre-checks of the controller (user, shadow user, confirmation mismatch; set-password: existing password, read-only,
  to keep the answer order) are unchanged. Envelope mapping: `CURRENT_PASSWORD_INVALID` -> `Errors = ["Incorrect password."]`
  (describer), `USER_LOCKED_OUT` -> `"The account is locked out. Try again later."`, `PASSWORD_POLICY_VIOLATION` -> descriptions rebuilt
  from the rule codes (`Methods/PasswordPolicyErrorDescriber`), `PASSWORD_ALREADY_SET` -> the earlier message, anything unexpected ->
  `500` with `Success=false` and the generic message.

Parity table (account page before -> facade):

| Point | Before | Now |
|---|---|---|
| Routes, bodies, status codes | - | unchanged (`200` + `PasswordResultDto`) |
| `EnablePasswordMethods=false` | own code, worked | works: handlers local only, in-process, nothing on the broker |
| Wrong current password | `Errors = ["Incorrect password."]`, not counted | same answer, **counted as a failed sign-in** (lockout) |
| Locked-out user changes the password | allowed | **refused** (`USER_LOCKED_OUT`) |
| Policy violation | descriptions of the failed rules | unchanged (rebuilt from the codes) |
| Set-password with an existing password / shadow user | refused | unchanged (pre-check; the method refuses as well) |
| Sessions | other refresh tokens revoked, own cookie refreshed | unchanged; the cookie is refreshed from the stored user (new stamp) |
| "Password changed" log line | path `ChangePassword` / `SetPassword` | `MethodChangePassword` / `MethodSetPassword` |
| Audit | none | one `Identity.Method` event per call |
| Unexpected failure | unhandled exception | `500`, `Success=false`, generic message |

Tests: `Api/Manage/AccountPasswordMethodFacadeTests` (both switch values: change - new works, old fails, refresh tokens revoked, this
session stays and another session ends with the stamp validated per request, one audit event, nothing on the event hub, canary absent
from logs, audit and activity tags; set the same; wrong current password counted; lockout; policy descriptions; set-password method:
`PASSWORD_ALREADY_SET`, shadow user, another user and an administrator `METHOD_FORBIDDEN`; tokens without `octo_api` refused; a bearer
token does not reach the endpoints; the facade guard), `Api/Methods/UserChangePasswordMethodTests` (switch off: local only),
`Methods/IdentityMethodHostTests`, `IdentityMethodDeclarationsIntegrationTests` (declaration, sensitive parameter, `CarriesSecret` vs.
model), plus the unchanged `PasswordChangeRevokesSessionsTests` and `ShadowUserPasswordTests`. `UsersController.DescribeIdentityErrors`
is a pure mapper onto `PasswordPolicyErrorDescriber` since AB#8415 (33d0dbbe); no REST or account path builds password-policy texts
itself. `Api/PasswordPolicyMessageParityTests` (AB#8523) keeps it that way: one password that breaks several rules gets the same rule
codes from `User.CreateUser`, `User.ResetPassword` and `User.ChangePassword`, and REST `POST users`, REST `POST users/ResetPassword`
(code + description) and the account page's `change-password` and `set-password` (descriptions) show exactly
`PasswordPolicyErrorDescriber.Describe` of the method envelope, in `en` and `de` (same `Accept-Language` on every path).

### System.Identity 2.x -> 3.x needs migration entries (AB#8157)

The CK engine refuses a schema-only bridge across a major (`CkMigrationMajorVersionGuard`, AB#4924 G3) as soon as the target model ships
a `migration-meta.yaml`, which System.Identity does. System.Identity 3.0.0 shipped without an entry from 2.x: every tenant upgrade failed with
"No migration path found from System.Identity-2.30.0 to System.Identity-3.0.0" and the identity service stopped (test-2 outage). 3.0.1 adds
one entry per 2.x minor from 2.9.0 to 2.30.0, all pointing at the empty script `2.x-to-3.0.1.yaml` (`steps: []`; nothing is migrated - the
3.0.0 change is access modifiers only); tenants below 2.9.0 take the 2.8.0 -> 2.9.0 data migration first. **Whoever publishes another 2.x
on a release line must extend the list.** Test: `SystemIdentityMajorUpgradeIntegrationTests` (the real published 2.30.0 imported into a tenant
and upgraded through `SetupAsync`; the path finder for every 2.x minor from 2.0.0). The earlier asset-repo `IdentityMajorUpgradeFlowTests`
missed the outage because its embedded 3.0.0 snapshot carries no migration-meta (no-migrations bridge).

### Identity-owned User fields are refused on the generic paths (AB#8042, AB#8053)

Generic writes of the identity-owned User fields are refused by the model since System.Identity 3.0.0 (AB#8053): `NormalizedUserName`,
`NormalizedEmail`, `EmailConfirmed`, `PhoneNumberConfirmed`, `TwoFactorEnabled`, `LockoutEnabled`, `LockoutEnd`, `AccessFailedCount`,
`ResetPasswordOnLogin`, `Claims` (`UserClaims`), `UserLogins` and `PreferredChannelBindingId` are `access: MethodOnly` in `ck-user.yaml`
(with `UserName` and `Email` from 2.28.0), and their definitions are `securitySensitive: true`. The generic access guards enforce it for
every caller: asset-repo GraphQL (`ATTRIBUTE_NOT_WRITABLE`), `ImportRt` and blueprint seeds (OCTO-CK139), the mesh-adapter write nodes. The
engine keeps only the **associations** in a list (`IdentityOwnedWrites.AssociationRoleIds`: `AssignedRole`, `GroupMember`, `ChildGroup`,
`MayActAs`, `GrantsPermission`; asset-repo GraphQL, mesh-adapter write nodes, caller `ImportRt`, message 140) because the CK access model
cannot restrict association writes. In 2.x (AB#8042) the attributes were a runtime list, because tightening attributes that were never
`securitySensitive` is a Major (row T7, AB#6585). **Nothing in this service is affected**: every identity write (stores, REST, methods,
provisioning, migrations, the bus consumer's `MayActAs`/`AssignedRole` edges, the preferred-channel self-service) goes through
`ITenantRepository`, which the guards do not touch, and the Bootstrap seed (TenantOwners `AssignedRole` edges) is a system import.

### Administrator revokes all sessions of a user (AB#7899)

`POST {tenant}/v1/users/{userName}/revokeSessions` and the bulk `POST {tenant}/v1/users/revokeSessions?scope=shadowUsers`
(dry run unless `dryRun=false`) rotate the security stamp, revoke OAuth tokens and authorizations and delete the
`RtServerSideSession` records of the subject in the current tenant (`IUserSessionRevocationService`, policy
`IdentityUserAdministrationWritePolicy`). Issued JWT access tokens stay valid until expiry. Details:
`docs/authentication.md` § Administrator Revokes All Sessions of a User; tests `UserSessionRevocationTests`.

### Password change ends the user's sessions (AB#7765, review finding M3)

Redeeming a refresh token checks only `CanSignInAsync`, never the security stamp, so a password change
revokes explicitly. **Every** REST password path calls `IUserCredentialChangeService.OnPasswordChangedAsync`
(`Services/UserCredentialChangeService.cs`, scoped) after the new password is persisted:
`POST {tenant}/api/manage/change-password`, `.../set-password` (through `User.ChangePassword` / `User.SetPassword` since
AB#8414), admin `POST system/v1/users/ResetPassword` (through `User.ResetPassword` since AB#8413)
and the anonymous `POST {tenant}/api/auth/reset-password`. The helper (1) rotates the security stamp,
(2) revokes every token and authorization of the user's subject (`RtId`) through the OpenIddict stores of
the **current tenant** (other users and the same user in another tenant are untouched; the old refresh
token answers `invalid_grant`), (3) writes one `Information` audit log line naming tenant, subject, acting
user (`(anonymous reset token)` for the token reset; the admin REST reset passes `AuditActor.FromPrincipal(User).Actor`
since AB#8008, i.e. the user name or `client <id>` for a client-credentials caller) and path - never a password, hash or token value.
A failing revocation throws, so the endpoint never reports success while old refresh tokens still work;
the caller keeps a new sign-in via `RefreshSignInAsync` (change/set-password). A new password path - REST or
CK method handler (AB#5672, AB#7774) - must call the same helper. Tests:
`UserCredentialChangeServiceTests`, `Api/Manage/PasswordChangeRevokesSessionsTests` (all four paths against the
real token endpoint), `Persistence/PasswordChangeRevocationTenantIsolationIntegrationTests`.

**Revoke before and after the password write (AB#8018, Security; decision OD-6: ordering, no outbox).** The user store and
the token/authorization stores are separate writes without a shared transaction (each store opens its own session), so a
stop between the password write and the helper above left old refresh tokens redeemable. `OctoUserManager` overrides
`ChangePasswordAsync`, `ResetPasswordAsync` and `AddPasswordAsync` (bodies follow the framework step by step) and calls
`IUserTokenRevocation.RevokeAllAsync` (`IdentityServerPersistence/Services/UserTokenRevocation.cs`, registered in `Program.cs`,
optional constructor parameter of the manager) between the in-memory hash update and `UpdateUserAsync`: only after the current
password / reset token was verified and the policy passed, so a request refused before the write (or a forged one) revokes
nothing; a store write that fails after the revocation (`ConcurrencyFailure`, a user validator) keeps the old password with the
sessions ended (accepted, safe direction; review finding on #234). A failing revocation
throws before the password is stored. `UserCredentialChangeService` uses the same `IUserTokenRevocation` for the second
revocation. 🔴 A new password write must go through these `UserManager` methods (or call `IUserTokenRevocation` before its own
write); the manager built by `CrossTenantSecondFactorVerifier` has no revocation and must never write a password. Tests:
`IdentityServerPersistence.UnitTests/Stores/OctoUserManagerPasswordWriteTests` (order, refusals, failing revocation) and the
`CrashAfterPasswordWrite_*` tests in `PasswordChangeRevokesSessionsTests` (six paths: REST change/set/admin reset/token reset,
methods `User.ChangePassword`/`User.ResetPassword`; the post-write helper is replaced by a failing one, the new password works and
the old refresh token answers `invalid_grant`; red without the pre-write revocation) plus `FailedPasswordChange_RevokesNothing`.

### Two-factor enabled without a usable second factor is refused (AB#7830)

ASP.NET Core Identity challenges only when `TwoFactorEnabled` is set **and** a provider is valid, so a user with
`TwoFactorEnabled = true` but no authenticator key would sign in with the password alone. That state arises in a
tenant cloned with ExportRt/ImportRt under System.Identity 2.27.0 (`UserTokens` is `Secret` since AB#7766, `TwoFactorEnabled`
was exported; since 2.28.0 `ImportRt` refuses users), after a restore from another environment (key ring), after an
import of edited user data, or when an admin deletes `UserTokens`. Rule (decided by Gerald 2026-10-30, option a, fails closed):
`POST {tenant}/api/auth/login` verifies the password with `CheckPasswordSignInAsync` (no cookie) for such a user and,
if it is correct, answers `200 { success: false, secondFactorSetupRequired: true, errorMessage: "Your second factor must be
set up again. Please contact your administrator." }`, writes a warning log + `User Login Failure` audit entry (user name
only) and issues no cookie. A wrong password follows the normal failure path (lockout counted once; the answer does not
confirm the password). The login UI shows the translated text (`LOGIN.ERROR_SECOND_FACTOR_SETUP_REQUIRED`).
*Usable* means an authenticator key only: the confirmed-e-mail provider is valid for ASP.NET Identity but its code is
not delivered (tracked as its own bug), recovery codes only work after a challenge. Recovery: an admin switches
the second factor off with `User.DisableTwoFactor-1` or `POST {tenant}/v1/users/{userName}/disableTwoFactor` (AB#7879, section
below; since AB#8042 a generic GraphQL/ImportRt write of `TwoFactorEnabled` is refused); the user signs in and enrols again. The cross-tenant password login refuses the
same state on top of AB#7804: when `ICrossTenantSecondFactorVerifier.GetOptionsAsync` reports
`CanUseAuthenticator = false` for the source user, `Login` answers `secondFactorSetupRequired` instead of issuing
a challenge. Tests: `Api/Auth/TwoFactorUnusableLoginTests` (with and without confirmed e-mail, wrong password,
recovery after 2FA off), `CrossTenantSecondFactorTests.PasswordLogin_SourceUserWithTwoFactorButNoAuthenticator_*`.

### User store concurrency: every user write advances `rtVersion` (AB#7770, AB#7908)

`OctoUserStore` writes users with the expected `rtVersion` (engine guard, AB#7769). The rules:

- **`UpdateAsync`** replaces the user with the `RtVersion` the instance was read with. A concurrent change of the same
  user (profile, password, lockout, counter, token) returns `IdentityResult.Failed(ConcurrencyFailure)` instead of
  last-writer-wins; the caller (REST `PUT users/{name}`, self-service) shows the error and the user retries from a fresh
  read. The instance's `RtVersion` is left unchanged on a conflict.
- **One read-modify-write, `MutateUserGuardedAsync` (`OctoUserStore.Atomic.cs`).** Every other write of a stored user goes
  through it: read the user in a transaction, change it, replace it with the read version (so `rtVersion` advances), re-read
  and re-apply on `RtVersionConflictException` (at most `MaxConcurrencyAttempts` = 40), MongoDB write conflicts are retried
  inside by `MongoWriteRetry`. Callers: `RecordAccessFailureAsync` / `ResetAccessFailedCountAtomicallyAsync` (the
  `IAtomicUserLockoutStore` that **production** uses through `OctoUserManager`, AB#7854), the static cross-tenant variants
  (`RecordAccessFailureAsync(ITenantRepository, …)`, `ResetAccessFailedCountAsync(ITenantRepository, …)`), recovery-code
  redemption, `SetTokenAsync` / `RemoveTokenAsync` and the `IUserLockoutStore` members below.
  🔴 AB#7908: the atomic lockout store used to replace *without* an expected version and kept the old `rtVersion`, so a stale
  `UpdateAsync` (profile edit, admin edit, password rehash) that read the user before a failure/lockout/reset succeeded and
  wrote the pre-lockout counter and lockout end back. Never write a stored user without the version it was read with.
- **`IUserLockoutStore` members** `IncrementAccessFailedCountAsync`, `ResetAccessFailedCountAsync`,
  `SetLockoutEndDateAsync` are kept (the interface requires them) as guarded read-modify-writes through the same helper. They
  are **not** reached in production, because `OctoUserManager` bypasses them for failure counting and reset; they stay
  covered by `PlainUserManager_ParallelFailedSignIns_AreAllCounted` and `ParallelFailedSignIns_ReturnDistinctCounts` so a plain
  `UserManager<RtUser>` over the store (tests, tools) is also correct.
- **Version follow-up.** After such a write the caller's instance takes over the new `RtVersion` only if the stored user was
  still the version the instance holds (nothing else changed): the `UpdateAsync` that `UserManager` calls right after stays
  valid. If another writer was in between (including a failed sign-in or reset by another request), the instance keeps its old
  version, so its `UpdateAsync` reports the conflict and never overwrites the other writer's fields.
  `OctoUserManager.AccessFailedAsync` itself always returns `Succeeded`: the failure is counted regardless of the caller's
  copy.
- A write that must detect concurrent changes passes the expected version; never combine it with `AttributeNewerThanGuard`,
  atomic RecordArray item updates or linked binaries in the same update (the engine rule throws).
- The counter restarts at 0 when the lockout triggers (ASP.NET Core Identity behaviour). Tests:
  `UserStoreConcurrencyIntegrationTests` (real MongoDB, **`OctoUserManager` as in production**; 10 parallel failures x 20
  rounds, threshold lockout, reset after a successful sign-in, parallel reset + profile update, concurrent profile updates,
  a stale `UpdateAsync` after a counted failure / threshold lockout / reset returns `ConcurrencyFailure` and keeps the
  lockout). They assert the final state, never the number of retries.

## Configuration

Environment variables are prefixed with `OCTO_`. Key configuration sections:
- `Identity`: Identity service options
- `System`: System configuration

Key identity options (`OctoIdentityServicesOptions`):
- `AuthorityUrl`: Public URL of the Identity service (default: `https://localhost:5003`)
- Token signing: `KeyFilePath` / `KeyFilePassword` (static PKCS#12 certificate) — unchanged by the OpenIddict migration. The `Identity:IdentityServerLicenseKey` option was **removed** with the migration (no license required).
- `RefineryStudioUrl`: Public URL of the Data Refinery Studio SPA. When set, the `octo-data-refinery-studio` OIDC client is auto-provisioned in all tenants with correct redirect URIs, CORS origins, and front-channel logout. Example: `OCTO_IDENTITY__RefineryStudioUrl=https://studio.example.com`
- `CorsPolicyCacheSeconds` (env `OCTO_IDENTITY__CORSPOLICYCACHESECONDS`, default `60`, AB#5487): lifetime of the cached Identity CORS policy (`IdentityCorsPolicyProvider`). The policy is rebuilt from the client origins of all tenants after this time, so a missed `CorsClientsUpdate` (other pod, client written without event) or a removed origin heals on its own. A policy with an **empty origin list is never cached** (it is rebuilt on every request until origins exist), so a tenant provisioned after the first request is not blind to the SPA. `0` or less disables the time-based expiry (events only). Events stay the fast path: `CorsClientsUpdate` is published by `ClientsController` (every write, and the overlay endpoint **unconditionally**, also when 0 URIs were added) and by `ClientMirrorProvisioningService` (new mirror, sync, removal; one event per affected child tenant, publish failures are logged and never fail the provisioning). **Single-flight (AB#8035):** the requests that find the entry expired or invalidated share one load (`IdentityCorsPolicyProvider.GetEntryAsync`, `_inflight` per generation under a lock); before, every concurrent request at expiry read the clients of every tenant itself (prod-1: paired rebuilds 2-30 ms apart every minute). A new load starts only after an invalidation (new generation; the old load still never publishes) or when the shared one has finished; the slot is cleared before the task completes, so a failed load reaches its waiters and the next request retries. An empty policy is still not cached, but concurrent requests share one load meanwhile. Logging: the rebuild line at Debug, `Identity CORS origins changed: n origins (added: …; removed: …)` at Information only when the origin set differs from the previous load. Tests: `IdentityCorsPolicyProviderTests` (parallel requests at expiry, invalidation during a load, empty list, failure with waiters, log levels). The common-services `CorsPolicyProvider` (other services) is a separate follow-up.
- `ClientMirrorReconciliationInterval` (env `OCTO_IDENTITY__CLIENTMIRRORRECONCILIATIONINTERVAL`, default `300` seconds, AB#8019): interval of the periodic client mirror reconciliation; `0` or less switches it off. See "Periodic mirror reconciliation" above.
- `DataProtectionKeysPath`: **Legacy / seed-only.** When set and the directory contains `key-*.xml` files, those keys are imported once into MongoDB at startup (zero-logout migration from old PVC). Safe to leave unset in new deployments; DataProtection keys are now always persisted in MongoDB.
- `DynamicClientRegistration.Enabled` (env `OCTO_IDENTITY__DYNAMICCLIENTREGISTRATION__ENABLED`, default `true`): RFC 7591 Dynamic Client Registration (AB#4338) so interactive MCP clients (Claude Code) that require DCR can self-register a public authorization-code+PKCE client via `POST /connect/register`. Enabled by default (set `false` to disable per deployment). Hard-gated (loopback redirects, PKCE, no secret, server-fixed scopes, per-IP rate limit, per-tenant cap, TTL). Registers into the system tenant + mirrors to all tenants; tenant resolved at authorize by §9 email-first discovery. Also `AllowedScopes` / `ClientTtlDays` / `MaxClientsPerTenant` / `RateLimitPermitsPerMinute`. See `docs/authentication.md` § Dynamic Client Registration and `docs/CONCEPT-MCP-DYNAMIC-CLIENT-REGISTRATION.md`.

### Password Policy (mirrored client-side — keep in sync)

User passwords are validated by ASP.NET Core Identity's default `PasswordOptions`
(minimum length 6; requires digit, lowercase, uppercase, and non-alphanumeric) — the
policy is **not** overridden in this repo. `UsersController.Post` enforces it atomically
via `UserManager.CreateAsync(rtUser, password)` (AB#4503 / Task 4516): an invalid password
persists no user.

**The Refinery Studio frontend duplicates this policy** in `octo-frontend-refinery-studio`
(`src/octo-mesh-refinery-studio/src/app/shared/validators/password-policy.validator.ts`) as
a pre-submit UX check — there is no endpoint exposing the policy over the wire. The two
copies are kept in sync by hand: **if you override `PasswordOptions` here (or bump a
`Require*` / `RequiredLength`), you MUST update that frontend validator and its inline message
to match** (AB#4503 / Task 4524), otherwise the client-side hint silently diverges from what
this service actually enforces.

The policy error descriptions come from `IdentityTexts` (`src/IdentityServices.Resources`, English +
German) in the **server culture**; clients must branch on `IdentityError.Code`, never on the
description. `tests/IdentityServices.UnitTests/Resources/PasswordPolicyTextsTests.cs` pins that every
German and English policy text is complete (CK v2 D7, AB#5902: the German `PasswordRequiresDigit` text
was truncated to "wörter müssen …").

User secrets ID: `173d8e91-b831-4e8a-a43f-672c57e6a4da`

## Angular ClientApp (LCARS UI)

The Identity Services includes an Angular SPA frontend in `src/IdentityServices/ClientApp/` with LCARS theme styling.

### Angular Build Commands

```bash
cd src/IdentityServices/ClientApp

# Install dependencies
npm install

# Development server
npm start

# Production build
npm run build

# Linting (REQUIRED before every commit)
npm run lint
```

### Linting (REQUIRED)

**CRITICAL: Always run the linter before every commit!**

```bash
cd src/IdentityServices/ClientApp
npx ng lint
```

The CI/CD pipeline will fail if there are any lint errors. Common issues:
- **Unused imports**: Run with `--fix` flag to auto-remove (`npx ng lint --fix`)
- **Unused variables**: Prefix with `_` (e.g., `_unusedParam`)
- **Empty functions**: Add a comment or remove the empty function

### Toolchain (AB#5075)

- Build, serve and extract-i18n run on `@angular/build` (esbuild/Vite); `@angular-devkit/build-angular`
  is gone. The `application` builder writes a **flat `dist/`** (`outputPath.browser: ""`) because
  `IdentityServices.csproj` copies `ClientApp/dist/**` to `wwwroot` and checks for `dist/index.html`.
- Unit tests: Vitest on jsdom via `@angular/build:unit-test` (AB#6993, same setup as Refinery Studio).
  Run `npm test` (= `ng test --watch=false`) in `ClientApp`; a single spec:
  `npm test -- --include='**/device-confirm.component.spec.ts'`. Never call `npx vitest` directly.
  Specs live next to the component (`*.spec.ts`), `tsconfig.spec.json` pulls in `vitest/globals`.
- `allowScripts` in `package.json` lists the six packages npm >= 11.16 may run install scripts for
  (`esbuild`, `lmdb`, `msgpackr-extract`, `@parcel/watcher`, `fsevents`, `@progress/kendo-licensing`).
  A new dependency with an install script produces an `npm warn allow-scripts` line until it is
  approved with `npm approve-scripts --no-allow-scripts-pin <pkg>`. `fsevents` is macOS-only and only
  shows up as pending on a clean install.
- No `.npmrc`: the lockfile resolves without `legacy-peer-deps`. If `npm install` reports `ERESOLVE`,
  fix the peer conflict instead of restoring the flag.
- The only deprecation `npm install` still prints is `@angular/animations`: peer-required and imported
  at runtime by Kendo 24, it stays until Kendo drops it (same as every other Meshmakers Angular app).
  `@angular/platform-browser-dynamic` was removed (unused since the standalone bootstrap in `main.ts`).
- Expected result of a clean `npm ci` + `npm run build`: no allow-scripts advisory, no other
  deprecation, 0 vulnerabilities, no build warnings.

### Device flow loop guard (AB#6993)

`/{tenant}/device/confirm` loads `GET /connect/deviceverification` (tenant-free URL; the tenant comes
from the in-memory `user_code` -> tenant map of `OidcTenantResolutionMiddleware`, fallback system
tenant). On 401 it navigates **once** to `/{tenant}/login` with a `loginAttempted=1` marker inside the
`returnUrl`; the login page's "already signed in" shortcut (AB#4961) sends an authenticated user straight
back. If the endpoint still answers 401 with the marker present, the page stops and shows
`DEVICE.ERROR_SESSION_REJECTED` (EN/DE) instead of bouncing forever. The consent page has no 401
redirect and `AuthorizeController` strips `prompt=login` and signs out stale sessions, so neither loops.

### Device confirm feedback (AB#7090)

`POST /connect/deviceverification` always answers **HTTP 200** with `{ success, errorMessage, error }`
(`OctoDeviceVerificationResponseHandler`; `error` is the OAuth code: `access_denied` = denied by the user
or cross-tenant refused, `invalid_token` = code used/expired/unknown). `DeviceVerificationController` also
returns that shape itself for a code that is not pending any more. `GET` answers 404 for such a code.
"Pending" = the user code token (`principal.GetTokenId()`) still has status `valid`: OpenIddict keeps
authenticating an approved/denied code on the verification endpoint, and a second `SignIn` for it throws
(HTTP 500), so the controller checks the status itself (`IsUserCodePendingAsync`). Never use `Forbid` for
the unknown-code case: the challenge handler needs an authenticated principal and throws.
The page always ends in a visible state: success, denied (`DEVICE.DENIED`), or an error
(`DEVICE.ERROR_CODE_USED`, `ERROR_SESSION_REJECTED`, `ERROR_NO_CONFIRMATION` for a 2xx/unparsable body of
unknown outcome, server text for e.g. cross-tenant). Terminal errors hide the consent dialog; retryable
ones (HTTP 5xx, cross-tenant refusal) show a banner above the buttons. Specs:
`device-confirm.feedback.spec.ts`, `OctoDeviceVerificationResponseHandlerTests`,
`DeviceVerificationFeedbackTests`.

### Angular Project Structure

- `src/app/core/` - Services, interceptors, models
- `src/app/shared/` - Reusable LCARS components (lcars-panel, lcars-header, etc.)
- `src/app/features/` - Feature components (login, logout, consent, device, manage, grants, error, setup)
- `src/styles/` - LCARS design system (variables, mixins, Kendo overrides)

### i18n (AB#5137)

The ClientApp is fully internationalized with **@ngx-translate/core 17** — the same library and
pattern as the meshmakers-app (custom `TranslateLoader` over `HttpClient` in `app.config.ts`, no
`@ngx-translate/http-loader` package). Resources live in `src/assets/i18n/en.json` and `de.json`
(nested `GROUP.KEY` structure, one group per feature, keys **sorted alphabetically**; EN and DE key
sets must stay identical). `LanguageService` (`core/services/language.service.ts`) picks the
initial language: persisted override in `localStorage['identity-ui.language']` → browser language
(prefix match en/de) → `en`; the EN/DE switcher sits in the `lcars-header` top-right corner and
persists the choice. Translations are loaded in the app initializer **before** first render, so
`translate.instant(...)` is safe in every TypeScript code path. Rules:

- Every user-facing string goes through the `translate` pipe (templates) or
  `TranslateService.instant` (TS error/success paths) — never hardcode UI text.
- Backend-provided messages (`result.errorMessage`, `error.error?.message`, scope display
  names/descriptions, provider/client display names, server validation `errors[]`) are rendered
  as-is; client-side keys only serve as fallbacks when the backend sends nothing.
- German is professional Sie-Form.
- Never JSON-roundtrip the i18n files with tooling — edit them textually (preserves ordering and
  diffs).

### SPA Version Display

The version label in the dialog footer (`lcars-panel`) comes from
`src/environments/currentVersion.ts`, generated by `src/environments/version.ts`
(runs on npm `postinstall` and explicitly from the MSBuild SPA targets). The
generator prefers the `OCTO_VERSION` environment variable — injected by
`BuildClientApp` / `PublishRunWebpack` in `IdentityServices.csproj` as
`$(OctoServiceVersion)` — and falls back to `package.json` (`0.0.0`) when the
variable is unset or a wildcard NuGet pin (`0.1.*` / `3.4.*`).

`OctoServiceVersion` is fed by the CI Docker build as the
`OCTO_SERVICE_VERSION` build arg carrying `$(Build.BuildNumber)` (see
`azure-pipelines.yml` extraBuildArgs), matching the .NET InformationalVersion.
**Do not use `$(OctoVersion)` for display**: on main/dev/test CI builds
update-build-number.yml deliberately sets it to the floating NuGet pin
`0.1.*`; it is exact only on r-tag builds. When `OctoServiceVersion` is not
provided it falls back to `$(OctoVersion)`, so local DebugL builds show
`v999.0.0`. Never edit `currentVersion.ts` manually.

### API Controllers for Angular SPA

Located in `Controllers/Api/`:
- `AuthApiController` - Login, logout, external providers, cross-tenant auth, cross-tenant auto-login (token-based), tenant switch
- `ConsentApiController` - OAuth consent flow; its device methods drive the OpenIddict end-user verification endpoint (`/connect/deviceverification`, form-encoded) via the SPA's `ConsentApiService`
- `DeviceApiController` - Holds the device-flow DTOs only (the flow itself runs through `/connect/deviceverification`)
- `ManageApiController` - User profile, password, external logins
- `MyIdentifiersApiController` - Self-service verified identifiers (phone/e-mail OTP, certificate) at `{tenantId}/api/manage/identifiers`, plus the AB#5149 preferred outbound channel (`GET`/`PUT .../preferredChannel`); accepts cookie AND bearer schemes
- `GrantsApiController` - OAuth grants management
- `OemApiController` - OEM configuration
- `SetupApiController` - Anonymous initial admin user setup (returns 404 after setup complete)
### Data Protection Key Persistence

ASP.NET Data Protection keys are always persisted in MongoDB (system tenant, `RtDataProtectionKey` entities) via `DataProtectionKeyStore : IXmlRepository` (registered as a singleton). The application name remains `OctoIdentityServices` (set via `SetApplicationName()`), so key isolation is unchanged from the previous file-based implementation.

The `DataProtectionKeysPath` option (`OCTO_IDENTITY__DataProtectionKeysPath`) is **legacy / seed-only**: when set and the directory contains `key-*.xml` files, those keys are imported once into MongoDB on startup (zero-logout migration from the old PVC). After the import succeeds the path can be left unset in all new deployments. The Helm chart's `services.identity.dataProtection` toggle and the associated PVC have been removed; ship order is identity image first, then the updated chart.

**Encryption at rest (AB#5530).** Registration: `AddOctoDataProtectionKeyRing()` (`SystemStores/DataProtection/`). The secret part of every key (`masterKey`) is wrapped with the **platform key ring** `SecretEncryption` (`OCTO_SECRETENCRYPTION__KEYS__<id>` / `ACTIVEKEYID`, AES-256-GCM via the engine's `ISecretAttributeProtector`, envelope `enc:v2:<kid>:…`) — no certificate, no new secret. The stored XML is ASP.NET's own encrypted form (`<encryptedSecret decryptorType="…PlatformKeyRingXmlDecryptor, IdentityServerPersistence">`), written by `DataProtectionKeyStore` itself (not `KeyManagementOptions.XmlEncryptor`) so it can decide per write and so `decryptorType` carries no assembly version. Key id, dates and key material never change, so nobody is logged out.
- `Identity:DataProtection:EncryptExistingKeys` (`OCTO_IDENTITY__DATAPROTECTION__ENCRYPTEXISTINGKEYS`, default `false`): `false` = stored keys stay as they are, new keys are written **plain while the store holds keys** (old pods of a rolling update keep reading them) — a store without any key (fresh install) gets encrypted keys. `true` = new keys encrypted, and the startup step rewrites every plain key encrypted in place (idempotent, every pod may run it).
- `DataProtectionKeyRingStartupService` (hosted): refuses to start (`DataProtectionKeyRingException`) when the flag is on without a `SecretEncryption` key, or when a stored key is wrapped with a key id that is not configured; re-wraps keys with a non-active key id (platform key rotation — remove the old id only after the re-wrap); other failures (DB) are logged and retried next start.
- **Never rename or move `PlatformKeyRingXmlDecryptor`** — stored keys reference its type name. **Rollback** to an image without the decryptor after keys are encrypted logs every user out (old image cannot read the keys, creates new ones). Rollout/rollback: `docs/rollout-identity-dataprotection-encryption.md`.
- Tests: `PlatformKeyRingXmlEncryptionTests` (unit, real ASP.NET stack), `DataProtectionKeyEncryptionIntegrationTests` (Mongo: multi-replica, migration, rotation, raw DB dump has no key material).

## Docker

Build image using `src/IdentityServices/Dockerfile`. Requires build args:
- `OCTO_PRIVATE_NUGET_SERVICE`: Private NuGet feed URL
- `OCTO_PRIVATE_NUGET_CERTIFICATE`: Path to CA certificate
- `OCTO_VERSION`: Package version to use

### .NET runtime of the image and the Shared Framework findings (AB#6724, AB#6717)

- The runtime stage uses the own base image `meshmakers/dotnet_aspnetcore-runtime-node` (build stage: `dotnet_sdk-node`), currently `1.4.0.0`
  (built from `mcr.microsoft.com/dotnet/aspnet:10.0-noble`, .NET runtime 10.0.13). Bump the tag when `dockerimages` publishes a rebuilt image.
- `System.Security.Cryptography.Pkcs` and `System.Security.Cryptography.Xml` come from the **.NET Shared Framework** (via OpenIddict and
  DataProtection), not from a package reference. A direct `PackageReference` pin in the web project fails with `NU1510` (package pruned by the
  framework), so **no package pin is possible**. `dotnet list package --vulnerable` may keep reporting them at the version of the build SDK
  while restore stays silent: that is a known, covered false positive.
- The control is the **image runtime**: since `tpl-v1.7.0` the template step `verify-dotnet-runtime.yml` (inside `build-and-push-docker.yml`) fails
  the image build when the final stage ships a .NET runtime below the minimum (10.0.13, one place: `minRuntimeVersion` in the template). Do not chase
  these findings with pins; see AB#6717 for the package-level part and AB#6724 for the runtime check.

## Documentation Guidelines

**CRITICAL REQUIREMENT:** Documentation MUST be updated after EVERY change. This is mandatory, not optional.

### Language Requirement

All documentation MUST be written in **English**. This includes:
- README.md files
- Concept documents in `docs/`
- Code comments
- API documentation
- Architecture documents
- CLAUDE.md files

### Mandatory Documentation Updates

After making ANY code changes, you MUST update the relevant documentation:

1. **For Bug Fixes**:
   - Document the fix in relevant architecture docs if it clarifies behavior
   - Update troubleshooting sections if applicable

2. **For New Features**:
   - Update `docs/` with new feature documentation
   - Add API endpoint documentation for new endpoints
   - Update architecture documents if new patterns are introduced
   - Update this `CLAUDE.md` if project structure changes

3. **For Refactoring**:
   - Update architecture documents to reflect new structure
   - Update code flow diagrams if applicable

4. **For Configuration Changes**:
   - Update `docs/configuration.md` with new options
   - Update environment variable documentation

### Documentation Files

| File | When to Update |
|------|----------------|
| `docs/README.md` | Project overview changes |
| `docs/architecture-overview.md` | Structural changes |
| `docs/authentication.md` | Auth flow changes |
| `docs/persistence.md` | Data layer changes |
| `docs/system-api.md` | API endpoint changes |
| `docs/configuration.md` | Config option changes |
| `CLAUDE.md` | Project structure changes |

## File roles, System.Files data policies and machine clients (AB#6180, AB#6467, AB#6457)

Blueprint `System.Identity.Bootstrap` 1.6.0 seeds the roles `FileManagement` / `FileViewer`, the data permissions
`files.read` / `files.manage` (660…52/53) and the enforcing policies 660…54/55 on `System.Files/FileSystemEntity`
(FileViewer reads; FileManagement reads and writes; the asset repository carries the same rules as a built-in
baseline). Details, the one-time `FileRoleGrant` (Reporting roles → File roles), the one-time
`TenantAdministratorFileRoleGrant` (AB#6578: human tenant administrators → `FileManagement`, own marker so tenants with the
Reporting marker still get it) and the recurring
`PipelineServiceAccountRoleGrant` are in `docs/persistence.md`. Rules to remember:

- Pipeline service accounts (`octo-pipeline-sa-*`) always hold the baseline roles of
  `PipelineServiceAccountBaselineRoles` — `FileManagement` (tenant setup: only with System.Files) and
  `StreamDataReader` (AB#8581: the stream-data gate of AB#8559; covers legacy accounts without `AssignedRoleNames`):
  granted by `CreateIdentityDataCommandRequestConsumer` in the command that creates/touches them (kept by the
  declarative sync, additive for a `null` list) and caught up at every tenant setup (not run-once, not on the nightly
  `CacheOnly` update). Only seeded roles, only the exact prefix; a system grant, not through the role change guard.
  A new baseline role is one entry in `PipelineServiceAccountBaselineRoles`, never a second copy of the grant.
- The prefix octo-pipeline-sa- is the only trust check and it is not reserved: since AB#7928 a client administrator may
  not grant platform roles it does not hold, but it can create a prefixed client that the setup pass then grants the
  baseline roles. Known gap, tracked in AB#8618.
- Customer client-credentials clients and octo-cli `LogInClientCredentials` carry no roles: 403 on the Files API
  until the client is given a File role. Reporting uses in-process system sessions and needs nothing.
- Tests: `FilesDataPermissionsSeedTests`, `PipelineServiceAccountRoleGrant*Tests`,
  `PipelineServiceAccountBaselineRolesTests`, `TenantAdministratorFileRoleGrant*Tests`,
  `PipelineServiceAccountBaselineRolesConsumerIntegrationTests` (own class: the other provisioning tests assert
  exact role sets).

## Scratch tenants: the creator becomes administrator (AB#7192)

An agent that creates a scratch child tenant with its client-credentials client has to work in it and clean it up without a human
login. `CreateTenant` takes an opt-in `scratch` flag (asset repository, octo-cli `--scratch`, MCP `create_tenant`); a `Restore` has none - restoring into an existing scratch tenant keeps its marker; the tenant then
carries a `ScratchTenantMarker` (octo-sdk `Communication.Contracts`) in the **system tenant configuration**, key `ScratchTenant.<tenantId>`:
parent tenant, creator client id, time, and later `RevokedAtUtc` / `RevokedBy` (`GrantedAtUtc` is not written: a grant must never rewrite the marker a concurrent revoke persists; the grant time is in the audit event). It lives outside the child's database on
purpose: it has to exist before the child (identity sets a tenant up the moment it is created), a dump does not carry it, and it survives the
drop and re-create of a restore. Removed with the tenant (`Delete` / `Detach`); an id that is gone loses a stale marker on the next
create / attach / plain restore.

- **Grant** = membership of the creator's **mirror** (the child's client record with `ProvisionedByParentTenantId` = the marker's parent, same
  `ClientId`) in the child's `TenantOwners` group - one `GroupMember` edge, exactly that client, exactly that tenant. A client of the same id
  that is no mirror (local, or from a restored dump) is never granted. The client has to be flagged `AutoProvisionInChildTenants` (e.g.
  `AddClientCredentialsClient -apic`), or it has no mirror and nothing is granted (`ScratchGrantStatus.MirrorMissing`, WARN in the log).
- `ScratchTenantGrantService.EnsureGrantAsync` re-applies the grant from the marker: at the end of `DefaultConfigurationCreatorService.SetupTenantAsync`
  (after the blueprint apply - the group has to exist - and the mirror provisioning; a **non-system parent**'s mirror is provisioned there first,
  automatic mirroring only covers the system tenant) and after every `ClientMirrorProvisioningService` pass over a child (a re-provisioned mirror is a
  new record without the old edges). So it survives an identity restart, a restore and a re-provisioned mirror. The marker is honoured only while its
  parent is the tenant's actual parent (`ParentMismatch` otherwise).
- **Revoke** = removing the creator's mirror from `TenantOwners` through the groups API (`DELETE .../groups/{rtId}/members/clients/{clientId}`):
  `GroupsController` hands every client-member removal to `RecordRevocationAsync`, which persists `RevokedAtUtc`/`RevokedBy` when it is exactly that
  edge. A revoked marker is never granted again (`ScratchGrantStatus.Revoked`). The revoke is persisted **before** the membership is
  removed, so a failure in between can never end in a re-grant. **Unprovisioning or deleting the mirror is not a revoke**
  (`UnprovisionClientFromTenant`, `DeleteClient` in the child): the next mirror provisioning creates the mirror again and the grant with it.
- **Audit:** grant and revoke are information events (source IdentityService) in the event log of the tenant **and** of the system tenant (which
  outlives the tenant); no secret is in the text.
- The child token of the agent is the ordinary one: `client_credentials`, `acr_values=tenant:<child>`, `scope=octo_api`, with the mirror's own
  secret (`RotateMirrorSecret`) or - while AB#5061 keeps the inherited secret - the parent client's secret.
- Tests: `ScratchTenantCreatorGrantIntegrationTests` (real MongoDB: grant only for the creator, none without a marker, repeated setup, re-provisioned
  mirror, persisted revoke, foreign parent, non-mirror client, non-system parent, audit without secrets), `GroupsControllerScratchRevokeTests`.

## One broken tenant database must not slow every token request (AB#8177)

Token issuance (`AllowedTenantsResolver`: cross-tenant mapping probe of **every** registered tenant database),
tenant discovery (user search in every tenant) and the CORS policy rebuild (client origins of every tenant) read from
tenant databases other than the one the request is for. With the MongoDB user of one tenant missing, each of those
probes waited ~10 s for the failed SCRAM authentication, 2-3 times per request: `POST /connect/token` and
`GET /connect/authorize` of unrelated tenants took 18-30 s.

`ITenantProbeGuard` / `TenantProbeGuard` (singleton) wraps these probes: a per-tenant circuit breaker with a probe
timeout (`TenantProbeGuard:ProbeTimeout`, default 3 s) and an open duration (`TenantProbeGuard:OpenDuration`, default
60 s). A failed or timed-out probe opens the circuit; while open, that tenant answers "unavailable" at once without any
I/O; then one request probes again (half-open). Callers fail closed and do **not** cache an "unavailable" answer.
The opening is logged once at error level with tenant, database and the MongoDB user name (the signal that names the
missing user). Every new per-request loop over other tenants' databases must go through the guard. Tests:
`TenantProbeGuardTests`, `AllowedTenantsResolverBrokenTenantTests` (dropped user of tenant X: the token path of tenant Y
stays fast and does not touch X). The creator service of the owning service re-creates the user, see octo-common-services.

**A RUNNING tenant heals itself (AB#8177, round 2).** When a probe fails with an authentication error (MongoDB 18/13, also
the pooled-connection case) or times out, the guard asks `TenantDatabaseUserHealer` (octo-common-services,
rate-limited to once a minute per tenant) to re-create the tenant's MongoDB user **in the background** and closes the
circuit as soon as the user was missing and is back, so no restart is needed. The healer needs the admin MongoDB
connection; a service without it just logs a warning. A token request that hits an unreachable tenant database is no
longer an unhandled 500: `TokenEndpointDatabaseFailureMiddleware` (before `UseOidcTenantResolution`, so the tenant lookup is covered; `/connect/token`
only) answers `503 temporarily_unavailable` with `error_description` naming the tenant and the cause, and octo-sdk maps it
to `TenantTokenDenialCause.TenantUnavailable`, so octo-cli shows the reason instead of "could not be reached". Tests:
`TenantProbeGuardTests` (healing), `TokenEndpointDatabaseFailureMiddlewareTests`.

**A wrong secret during the healing is 401 or 503, never 500 (AB#8281).**
`ClientMirrorReconciliationTests.WrongSecret_WhileTheChildDatabaseUserIsHealed_IsNever500_AndEndsAs401` drops the user of a
child tenant's database, drops the token host's cached clients and asks for a token with a wrong secret until it is 401:
`503 temporarily_unavailable` while the database cannot be read, then 401, then the right secret works again. The 500s of
identity build 65204 (r3.5.61) were not this path: the integration test process ran out of memory because no MongoDB
repository client was ever released (every test host left its clusters, monitor threads and sockets behind; fixed in
octo-construction-kit-engine-mongodb, see its CLAUDE.md "Repository clients are released, not only dropped"). A 5xx answer
in that class prints the response body to the test output.
