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
dotnet test Octo.Identity.sln -c Release
```

- Gilt für **jeden** Commit und **jeden** Push — auch für vermeintlich triviale Änderungen, Doc-Updates, Renames oder "nur einen Index hinzufügen".
- Gilt für Unit- **und** Integration-Tests. Wenn Testcontainers/Docker lokal nicht verfügbar sind, das **explizit** dem User melden und auf Freigabe warten — **nicht** stillschweigend nur Unit-Tests laufen lassen.
- **Niemals** `--no-verify`, `git commit -n` oder Hook-Skips verwenden, um diese Regel zu umgehen.
- **Niemals** auf "die CI fängt es schon ab" verlassen — die CI ist die letzte, nicht die erste Verteidigungslinie.
- Bei rotem Test: erst fixen, dann committen. Niemals "fix in einem nachfolgenden Commit" versprechen.

Build #35223 (PR #95) ist genau wegen Verstoß gegen diese Regel fehlgeschlagen. Wenn lokale Validierung übersprungen wird, sind alle anderen Pre-Commit-Regeln (Lint etc.) ebenfalls hinfällig.

## Build Configurations

- **Debug/Release**: Standard configurations
- **DebugL**: Local development mode that sets version to 999.0.0 and uses local NuGet sources from `../nuget`

## Architecture

### Project Structure

- **IdentityServices** (`src/IdentityServices/`): Main ASP.NET web application and entry point. Contains the OpenIddict protocol configuration (`Configuration/OpenIddictConfiguration.cs`), the passthrough protocol controllers (`Controllers/Protocol/`), the OpenIddict integration layer (`OpenIddict/`), plus controllers for account management, consent flows, device authorization, and the System API (v1).

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

The `Persistence.IdentityCkModel` project uses YAML-based model definitions that are transformed into C# code at build time. Model files are in `src/Persistence.IdentityCkModel/ConstructionKit/`. The model ID is `System.Identity-2.12.0` with dependency on `System-[2.0,3.0)`. Generated types live in namespace `Persistence.IdentityCkModel.Generated.System.Identity.v2`.

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
- **`ExternalTenantUserMappingStore`**: Persistence for cross-tenant user role mappings
- **`ExternalTenantUserMappingsController`**: System API CRUD for managing mappings (per-tenant, requires `allowed_tenants`)
- **`AdminProvisioningController`**: Cross-tenant provisioning via system tenant (see below)

**Cross-tenant auto-login** (token-based, no credential re-entry):
- `POST /{parentTenantId}/api/auth/cross-tenant-token` — Generates a DataProtection-encrypted token (60s expiry) for the authenticated parent-tenant user
- `POST /{childTenantId}/api/auth/cross-tenant-login` — Exchanges the token for a session in the child tenant
- The Angular login component automatically attempts token-based auto-login when clicking "LOGIN VIA {parent}". If no parent session exists, it redirects to the parent tenant's login page (where all auth methods are available); after authentication there, it redirects back with a `crossTenantAutoLogin` query param to auto-complete the token exchange

**Cross-tenant role sync**: When a cross-tenant user logs in (via `FindOrCreateCrossTenantUserAsync`), `SyncMappedRolesAsync` resolves mapped role IDs to role names by querying the tenant repository directly (via `IMultiTenancyResolverService.GetTenantRepository()`), then calls `UserManager.AddToRoleAsync` with the role **name** (not ID). This runs on every login, ensuring existing users get role updates. Important: `RoleManager<RtRole>` must NOT be used for this — it may resolve to the wrong tenant context during cross-tenant login. The tenant repository approach reads from `HttpContext.Items["tenantRepository"]` which is correctly set by the inline middleware.

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
- **v1 issues no exchanged refresh token** (short-lived B tokens, re-exchanged from
  the still-valid A token). See `docs/CONCEPT-CROSS-TENANT-TOKEN-EXCHANGE.md` and
  `docs/authentication.md` § Cross-Tenant Token Exchange. Coverage:
  `tests/IdentityServices.IntegrationTests/Persistence/TenantExchangeIntegrationTests.cs`
  (privilege-escalation regression: resolved roles == B subset, not A's full set).

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

- `ClientStore.UpdateAsync` fires `SyncMirrorsForClientAsync` after commit
  when the post-update client carries `AutoProvisionInChildTenants=true`.
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
The next startup-time provisioning loop re-converges the state for any
mirror that fell behind because of a transient failure.

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
`ClientStore.UpdateAsync` so the post-commit upkeep hook (#4044) fires
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

### Admin Provisioning (Cross-Tenant Pre-Provisioning)

The `AdminProvisioningController` allows users with TenantManagement role to pre-provision cross-tenant user mappings in a **target tenant** without needing `allowed_tenants` for that tenant. It is routed via the system tenant: `{tenantId}/v1/adminProvisioning/{targetTenantId}`.

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

The `provisionCurrentUser` endpoint extracts `sub`, `preferred_username`, and `tenant_id` from the JWT, fetches all roles from the target tenant, and creates an `RtExternalTenantUserMapping` with all role IDs. It also adds the mapping as a member of the **TenantOwners** group (via `GroupMember` association), so the user inherits all roles through group membership. If a mapping already exists for the user, it returns the existing one.

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

Current identity schema (migration) version: `22` (System.Identity-2.12.0; migration 21→22 added the `RtOAuthAuthorization`/`RtOAuthToken` OpenIddict store types)

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
- **`TenantDiscoveryComponent`** (`ClientApp/src/app/features/tenant-discovery/`): Angular SPA page with email input, tenant selection (when multiple), and redirect logic.
- **`octo_last_tenant` cookie**: Shortcuts the discovery flow on repeat visits by redirecting directly with the last-used tenant's `acr_values`.
- **Interceptor exclusion**: The Angular `tenantInterceptor` skips `/api/tenant-discovery/` paths since this endpoint has no tenant context.

See `docs/CONCEPT-TENANT-SPECIFIC-OAUTH.md` § 9 for the full flow diagram and API specification.

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
- **`IAllowedTenantsResolver`** / **`AllowedTenantsResolver`** (`IdentityServerPersistence/Services/`): Resolves allowed tenants at token issuance time by checking cross-tenant user mappings across child tenants and walking up the ancestor chain
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

`OctoTenantIdentityProviderDto` has a `ParentTenantId` property identifying the parent tenant for cross-tenant authentication. AutoMapper maps between `RtOctoTenantIdentityProvider` and `OctoTenantIdentityProviderDto` in `MapperProfile`.

### Multi-Tenancy

The service supports multi-tenancy via tenant ID in routes. The route pattern is `{tenantId:tenantId=System}/{controller=Home}/{action=Index}/{id?}`.

### API Versioning and Route Prefix

All API endpoints use a single tenant-scoped route prefix: `{tenantId:tenantId}/v{version:apiVersion}` (e.g., `octosystem/v1` for the default system tenant, `MyTenant/v1` for a specific tenant). The system tenant ID defaults to `OctoSystem` (normalized to lowercase in URLs) and is configurable via `OctoSystemConfiguration.SystemTenantId`.

Two authorization policies:
- `IdentityApiReadOnlyPolicy`: Requires `IdentityApiFullAccess` or `IdentityApiReadOnly` scope
- `IdentityApiReadWritePolicy`: Requires `IdentityApiFullAccess` scope

## Configuration

Environment variables are prefixed with `OCTO_`. Key configuration sections:
- `Identity`: Identity service options
- `System`: System configuration

Key identity options (`OctoIdentityServicesOptions`):
- `AuthorityUrl`: Public URL of the Identity service (default: `https://localhost:5003`)
- Token signing: `KeyFilePath` / `KeyFilePassword` (static PKCS#12 certificate) — unchanged by the OpenIddict migration. The `Identity:IdentityServerLicenseKey` option was **removed** with the migration (no license required).
- `RefineryStudioUrl`: Public URL of the Data Refinery Studio SPA. When set, the `octo-data-refinery-studio` OIDC client is auto-provisioned in all tenants with correct redirect URIs, CORS origins, and front-channel logout. Example: `OCTO_IDENTITY__RefineryStudioUrl=https://studio.example.com`
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

# Run tests
npm test
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

### Angular Project Structure

- `src/app/core/` - Services, interceptors, models
- `src/app/shared/` - Reusable LCARS components (lcars-panel, lcars-header, etc.)
- `src/app/features/` - Feature components (login, logout, consent, device, manage, grants, error, setup)
- `src/styles/` - LCARS design system (variables, mixins, Kendo overrides)

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
- `GrantsApiController` - OAuth grants management
- `OemApiController` - OEM configuration
- `SetupApiController` - Anonymous initial admin user setup (returns 404 after setup complete)
### Data Protection Key Persistence

ASP.NET Data Protection keys are always persisted in MongoDB (system tenant, `RtDataProtectionKey` entities) via `DataProtectionKeyStore : IXmlRepository` (registered as a singleton). The application name remains `OctoIdentityServices` (set via `SetApplicationName()`), so key isolation is unchanged from the previous file-based implementation.

The `DataProtectionKeysPath` option (`OCTO_IDENTITY__DataProtectionKeysPath`) is **legacy / seed-only**: when set and the directory contains `key-*.xml` files, those keys are imported once into MongoDB on startup (zero-logout migration from the old PVC). After the import succeeds the path can be left unset in all new deployments. The Helm chart's `services.identity.dataProtection` toggle and the associated PVC have been removed; ship order is identity image first, then the updated chart.

## Docker

Build image using `src/IdentityServices/Dockerfile`. Requires build args:
- `OCTO_PRIVATE_NUGET_SERVICE`: Private NuGet feed URL
- `OCTO_PRIVATE_NUGET_CERTIFICATE`: Path to CA certificate
- `OCTO_VERSION`: Package version to use

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
