# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Octo Identity Services is a .NET 10 identity and authentication service built on Duende IdentityServer. It provides OAuth2/OpenID Connect authentication with support for multiple identity providers (Google, Facebook, Microsoft, Azure Entra ID, OpenLDAP, Microsoft AD).

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

- **IdentityServices** (`src/IdentityServices/`): Main ASP.NET web application and entry point. Contains controllers for account management, consent flows, device authorization, and the System API (v1).

- **Authentication** (`src/Authentication/`): Razor class library with authentication schemes and handlers. Implements dynamic authentication for multiple providers:
  - OAuth providers: Google, Facebook, Microsoft, Azure Entra ID
  - LDAP providers: OpenLDAP, Microsoft AD

- **IdentityServerPersistence** (`src/IdentityServerPersistence/`): Data persistence layer implementing IdentityServer stores (ClientStore, ResourceStore, PersistentGrantStore, IdentityProviderStore). Uses Octo Runtime Engine with MongoDB.

- **Persistence.IdentityCkModel** (`src/Persistence.IdentityCkModel/`): Construction Kit model definitions (YAML files in `ConstructionKit/`) for identity entities. Uses Octo source generation to create runtime types.

- **IdentityServices.Resources** (`src/IdentityServices.Resources/`): Localized string resources (resx files).

### Key Dependencies

This service depends on Octo framework packages (versioned via `$(OctoVersion)` in Directory.Build.props):
- `Meshmakers.Octo.Runtime.Engine.MongoDb`: MongoDB persistence
- `Meshmakers.Octo.Services.Infrastructure`: Base service infrastructure
- `Meshmakers.Octo.ConstructionKit.SourceGeneration`: Code generation from CK models

### Construction Kit (CK) Model

The `Persistence.IdentityCkModel` project uses YAML-based model definitions that are transformed into C# code at build time. Model files are in `src/Persistence.IdentityCkModel/ConstructionKit/`. The model ID is `System.Identity-2.7.0` with dependency on `System-[2.0,3.0)`. Generated types live in namespace `Persistence.IdentityCkModel.Generated.System.Identity.v2`.

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

- **`TenantExchangeGrantValidator`** (`IdentityServices/Services/`, a Duende
  `IExtensionGrantValidator` for `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
  registered in `Program.cs` via `.AddExtensionGrantValidator<>()`): validates the
  caller's home-tenant (A) access token (`subject_token`) via `ITokenValidator`,
  reads the target tenant B from `acr_values=tenant:B`, asserts the request was
  wired to B (fail closed → `invalid_target`), gates on
  `ValidateCrossTenantAccessAsync(B, A, subA)` (→ `unauthorized_client`), then
  `FindOrCreateCrossTenantUserAsync` for the B-shadow user and returns a
  `GrantValidationResult` whose **`sub` is the B-shadow user's `RtId`**. This is
  the security linchpin: the token runs on the B-shadow sub, so
  `UserProfileService`/`OctoUserStore` stamp `tenant_id=B` + B-resolved roles
  automatically — A's roles never leak into B. Reuses `CrossTenant*` services and
  `AllowedTenantsResolver` unchanged.
- **`OidcTenantResolutionMiddleware.ResolveTenantFromTokenRequestAsync`** has a
  `token-exchange` branch that resolves B from `acr_values` exactly like the
  `client_credentials` branch, wiring B's repo into `HttpContext.Items` before the
  token is minted.
- **Audit**: `TokenExchangeSuccessEvent` / `TokenExchangeFailureEvent`
  (`IdentityServices/Services/TokenExchangeEvents.cs`). Failure events persist to
  the runtime event log (`OctoEventSink`); success events are log-only.
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

### Delegation / On-Behalf-Of Grant (AB#5026)

A service-account `Client` authenticates with its own client credentials **and** presents a user's
access token as `subject_token`; the issued token runs on the **user's** `sub` but carries only the
**intersection** of both parties' effective roles, plus `act` = the service account's `client_id`.

- **Grant type:** `urn:meshmakers:params:oauth:grant-type:on-behalf-of` — an **own URN**, deliberately
  not the RFC 8693 token-exchange one. Duende binds one `IExtensionGrantValidator` per grant type, so
  a shared URN would also share the per-client opt-in, and the only client carrying the token-exchange
  grant today (`octo-mcpServices-device`) is a **public client with no secret**.
- **`IDelegatedIdentityResolver` / `DelegatedIdentityResolver`** (`IdentityServerPersistence/Services/`):
  the policy, **free of every Duende type** (prepares the OpenIddict migration, Epic 4989, and makes
  the rule unit-testable without protocol mocks). Service-account roles via
  `IClientRoleStore.GetEffectiveRoleNamesAsync`, user roles via `IUserRoleStore<RtUser>`
  (= `OctoUserStore`); both therefore include **group-inherited** roles. Intersection compares role
  names case-insensitively (role lookups key off the upper-invariant `NormalizedName` everywhere).
  Unknown client / user return a `DelegationDenialReason`, never an exception.
- **`OnBehalfOfGrantValidator`** (`IdentityServices/Services/`): a thin protocol adapter — raw
  parameters → out-of-context `subject_token` validation (`JsonWebTokenHandler`, same rationale as
  `TenantExchangeGrantValidator`) → same-tenant gate → resolver → `GrantValidationResult`. Registered
  in `Program.cs` alongside the token-exchange validator (additive; `AddCustomTokenRequestValidator`
  is **not** touched — that one is singular and already holds `ClientCredentialsRoleTokenValidator`).
- 🔴 **`UserProfileService.ApplyDelegationClaims` is load-bearing.** Because the token runs on the
  user's `sub`, `AddAspNetIdentity<RtUser>` + `ProfileService<RtUser>` resolve that user's **full**
  role set into `IssuedClaims`. Left alone, the intersection never reaches the token and the grant is a
  placebo. The method detects the `act` claim on `context.Subject` and replaces every `role` claim with
  the intersection (carried as internal `octo_delegated_role` claims on the grant result). `act` is
  added unconditionally to `IssuedClaims` — the proven `tenant_id` / `allowed_tenants` route — so **no
  blueprint bump or `octoAPI` ResourceClaims change was needed**.
- 🔴 **`OidcTenantResolutionMiddleware.ResolveTenantFromTokenRequestAsync` needed a new branch.** Its
  if/else chain is a closed list of grant types; an unlisted URN falls through to `null`, no tenant is
  wired into `HttpContext.Items`, and every per-tenant store reads the **system** tenant instead.
- **Same-tenant only (v1):** `acr_values` tenant == request tenant == `subject_token.tenant_id`, else
  `invalid_target`. Cross-tenant delegation is v2; the token-exchange grant covers cross-tenant today.
- **Empty intersection is a success**, not an error — the token carries no `role` claim so role-gated
  consumers fail closed.
- 🔴 **`offline_access` is rejected with `invalid_scope`** (audited as a `DelegationFailureEvent`), not
  just discouraged. The intersection is computed **at issuance**; a `grant_type=refresh_token` request
  rebuilds the access token from the persisted grant and never re-enters an extension grant validator,
  so the intersection would freeze and a role revoked on **either** side would keep working for the
  refresh token's whole lifetime. The check sits in `OnBehalfOfGrantValidator` because Duende derives
  its refresh-token decision (`ValidatedResources.Resources.OfflineAccess`) solely from the requested
  scope and validates scopes **before** the extension grant runs — and because `GrantValidationResult`
  has no "no refresh token" switch. `AllowOfflineAccess=false` on the client is a seeding convention,
  not an invariant, so it is not relied on. The error description states the reason so an integrator
  is not left guessing.
- **Audit:** `DelegationSuccessEvent` / `DelegationFailureEvent` (`DelegationEvents.cs`, category
  `Delegation`, IDs `50260` / `50261`). `OctoEventSink` persists failures and expands their fields.
- **No seeded service account here** — the client must carry the URN in `AllowedGrantTypes` or Duende
  rejects the request before the validator runs. The real pipeline service account is created by the
  Communication Controller over the bus; see "Service-Account Clients over the Distribution Event Hub"
  below (AB#5027).

### Service-Account Clients over the Distribution Event Hub (AB#5027)

The Communication Controller provisions one `client_credentials` service account per mesh adapter, so
pipeline execution runs under a real identity. It can only reach this service **over the bus**: the
REST `ClientsController` needs an `octo_api` bearer token, i.e. the very identity being created, and
no client-credentials client with a secret is seeded anywhere. `CreateIdentityDataCommandRequestConsumer`
therefore had to learn three things it could not do before — it hard-coded `RequireClientSecret=false`,
never wrote a `ClientSecrets` entry and never touched an association:

| `DistClientDto` field (octo-common-services `Meshmakers.Octo.Services.Contracts`) | Consumer behaviour |
|---|---|
| `ClientSecret` (**plaintext**, optional) | Hashed with the same `Sha256()` extension `ClientsController` uses (`Duende.IdentityServer.Models`) and written as the single `ClientSecrets` entry. **Never** persisted or logged in the clear. |
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
`PUT {tenantId}/v1/clients/{clientId}/roles/{roleName}` or `octo-cli AddClientToRole`.

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

Full per-tenant ASP.NET auth tickets (~3 KB each, sent with every request and on OAuth loopback-callback redirects) were overflowing small loopback servers and bloating all browser traffic. Duende server-side sessions are now enabled via `.AddServerSideSessions<ServerSideSessionStore>()`.

**What changed:**
- The per-tenant `.AspNetCore.Identity.Application.{tenantId}` cookie now carries **only a short session key** (hundreds of bytes) instead of the full encrypted ticket. The ticket itself lives in MongoDB per-tenant via the CK runtime.
- `TenantCookieManager` naming convention (`{name}.{tenantId}`) is **unchanged**.
- `ConfigureApplicationCookie` sets `ExpireTimeSpan = 7 days` sliding; this bounds both the cookie lifetime and the session record lifetime.
- `ServerSideSessionStore` (in `IdentityServerPersistence/SystemStores/`) implements Duende's `IServerSideSessionStore` against the per-tenant CK runtime repository.

**CK types added in System.Identity-2.7.0 (migration 16 → 17):**
- `RtServerSideSession`: stores the encrypted ticket with a **Unique** `SessionKey` index and ascending indexes on `SubjectId`, `SessionId`, and `ExpirationDateTime`.
- `RtDataProtectionKey`: stores the DataProtection key ring (see Data Protection Key Persistence section).

**Session lookup semantics:** `GetSessionAsync` treats expired-but-not-yet-cleaned records as missing (returns `null`). Expired records are physically removed by Duende's built-in background sweep (`GetAndRemoveExpiredSessionsAsync`), which runs every 10 minutes by default. The sweep follows the `TokenCleanupHostService` pattern: it iterates the system tenant plus all child tenants to cover every per-tenant session store.

**Write-conflict retry:** Concurrent session renewals (two browser tabs refreshing simultaneously) can trigger a transient MongoDB write conflict (`MongoCommandException` with a 'Write conflict' message). `ServerSideSessionStore` shares the `MongoWriteRetry` helper (also used by `PersistentGrantStore`) to retry transient write conflicts transparently.

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

Current identity schema version: `IdentitySchemaVersionValue = 17`

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
- **Token claims:** `ClientCredentialsRoleTokenValidator` (`IdentityServices/Services/`, an
  `ICustomTokenRequestValidator` registered via `.AddCustomTokenRequestValidator<>()`) injects the
  client's effective roles as **unprefixed `JwtClaimTypes.Role`** claims into the `client_credentials`
  token — identical shape to user tokens. It clears the per-request `ClientClaimsPrefix` so consumers
  need no client-specific code path.
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
`role` — but **no `tenant_id`**. `UserProfileService` is the only producer of that claim and Duende
invokes `IProfileService` only for tokens with a subject, so the client-credentials grant never
reached it. `acr_values=tenant:X` on `/connect/token` only selected which tenant's `ClientStore`
resolved the client; nothing copied X into the token.

Consequence downstream: every tenant gate on the platform (`TenantAuthorizationMiddleware` in
octo-common-services, the MCP server's `RuntimeSecurityContextResolver`, the mesh adapter's
`HttpRequestService`) detects "no `sub`" and **skips** — so with `ValidateAudience = false` on
asset-repo / platform-services / MCP, *any* client-credentials client of this authority could address
*any* tenant. Client mirroring (`AutoProvisionInChildTenants`) copies the same secret hash into every
child tenant, so one credential pair was literally valid instance-wide.

`ClientCredentialsRoleTokenValidator` therefore stamps the issuing tenant as well:

- The tenant comes from `HttpContext.Items[tenantId]`, which `OidcTenantResolutionMiddleware` wrote
  from `acr_values`. When no `acr_values` was sent, the client lookup ran against the **system
  tenant** — so that is what was stamped. ⚠️ **That fall-back was narrowed by AB#5058 (below): it now
  applies only when the client id is unambiguously bound to one tenant.**
- The claim is emitted **before** the role branch, which returns early for a client with no roles —
  otherwise exactly the clients most likely to be legacy would keep shipping tenant-less tokens.
- `ClientClaimsPrefix` is cleared (as it already was for roles), so the claim is `tenant_id`, not
  `client_tenant_id`. Side effect worth knowing: any claim configured on the client itself is now
  also emitted unprefixed. Nothing in the platform writes `RtClient.ClientClaims` today, and every
  client with roles was already in that state.
- An existing `tenant_id` in `ClientClaims` is left alone rather than duplicated — a duplicate turns
  the consumers' single-valued `FindFirstValue` into an arbitrary pick.
- Other grants are untouched: `UserProfileService` already provides `tenant_id` there, and adding it
  as a *client* claim would duplicate it on every interactive token.

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

Tests: `tests/IdentityServices.UnitTests/Services/ClientCredentialsTokenClaimsTests.cs`.

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

`ClientCredentialsRoleTokenValidator` now **refuses to guess**. On a `client_credentials` request
with no `acr_values` it decides the binding **server-side**, from state no caller can influence:

| Signal | Where it lives | Meaning |
|---|---|---|
| `RtClient.AutoProvisionInChildTenants` | resolved client | declared fleet credential ⇒ ambiguous |
| `RtClient.ProvisionedByParentTenantId` | resolved client | the resolved record *is* a mirror ⇒ ambiguous |
| `RtClientMirror` rows for the client id | system tenant | mirrors already materialized ⇒ ambiguous |

Ambiguous ⇒ `invalid_request` with a description naming the remedy, plus a persisted
`ClientCredentialsTenantAmbiguityEvent` (category `ClientCredentials`, ID `50580`; expanded by
`OctoEventSink`). Unambiguous ⇒ unchanged AB#5032 behaviour, system tenant stamped.

- 🔴 **The mirror lookup fails closed.** A repository error rejects the request rather than falling
  back to "system" — guessing there is exactly the escalation being closed. The blast radius is
  bounded: the probe runs *only* on the no-`acr_values` path.
- 🔴 **Ordering matters.** The ambiguity probe runs **before** `AddTenantIdClaim`, so a refused
  request never carries a guessed `tenant_id`, and the AB#5032 invariant (claim stamped *before* the
  role branch's early return) is preserved for every accepted request.
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
  *explicitly*. No token-endpoint check distinguishes those two callers. The validator logs a
  warning whenever a mirroring source obtains a system-tenant token, and **AB#5055 must not treat
  `tenant_id == systemTenant` on a client-credentials token as proof of provenance on its own.**
  Closing it for real needs per-tenant mirror secrets.

Tests: `tests/IdentityServices.UnitTests/Services/ClientCredentialsTenantAmbiguityTests.cs`
(8 cases: flagged client / live mirror rows after the flag was switched off / mirror copy itself /
lookup failure ⇒ all refused; role branch never reached; unmirrored client unchanged; mirrored
client *with* `acr_values` unchanged and the probe not even consulted; the AB#5032 ordering
invariant) and `Persistence/ClientMirrorProvisioningIntegrationTests.cs`
(`MirroredClient_TokenRequestWithoutAcrValues_IsRefused` /
`UnmirroredClient_TokenRequestWithoutAcrValues_StillCarriesTheSystemTenant` — the real validator over
a real mirror in MongoDB; the unit tests stub `GetMirrorsAsync`, so only these prove that an actually
provisioned mirror is what makes the id ambiguous). `IdentityServices.csproj` grants
`InternalsVisibleTo` to the integration test project for the shared constants.

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
published SHA-256 digests; a divergence from Duende's `Sha256()` would store rotated secrets in a
shape the token endpoint can never match), `ClientMirrorControllerTests` (endpoint branching plus
`ToString()` redaction on both secret-carrying types) and
`ClientMirrorProvisioningIntegrationTests` (the same over real MongoDB, plus rotation retiring the
superseded value).

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

- **`TenantLoginRedirectMiddleware`**: Intercepts IdentityServer's 302 redirects to `/System/login` (and `/logout`, `/consent`, etc.) and rewrites the tenant prefix based on `acr_values=tenant:{tenantId}` in the authorize request ReturnUrl. For logout redirects (which carry a `logoutId` instead of a `ReturnUrl`), the middleware falls back to the tenant ID stored in `HttpContext.Items` by `OidcTenantResolutionMiddleware` (resolved from the `id_token_hint` JWT). Registered before `UseIdentityServer()` in the middleware pipeline.
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

### Centralized Grant Storage

The `PersistentGrantStore` always uses the **system tenant database** for all OIDC grants (authorization codes, refresh tokens, consent grants), regardless of the current HTTP tenant context. This is critical because:

- `/connect/authorize` resolves tenant from `acr_values=tenant:{tenantId}` via `OidcTenantResolutionMiddleware`
- `/connect/token` resolves tenant from the authorization code → tenant mapping (see below), but `PersistentGrantStore` bypasses the per-request tenant and always uses the system DB
- `TokenCleanupHostService` runs without HTTP context

Storing grants centrally ensures the authorization code created during authorize can always be found during the token exchange. Grant keys (authorization codes, refresh tokens) are globally unique, so there is no collision risk across tenants.

### Pushed Authorization Request (PAR) Tenant Resolution

When backend OIDC clients (built on `Microsoft.AspNetCore.Authentication.OpenIdConnect` .NET 9+) authenticate, they automatically use **PAR (RFC 9126)** if the IdP advertises a `pushed_authorization_request_endpoint` — which Duende IdentityServer does by default. This means the authorization parameters (including `acr_values=tenant:{tenantId}`) are POSTed to `/connect/par`, and the subsequent browser redirect to `/connect/authorize` contains only `request_uri=urn:ietf:params:oauth:request_uri:...` — no `acr_values` on the URL.

`OidcTenantResolutionMiddleware` handles this in two stages:
1. On `POST /connect/par`, it reads `acr_values` from the form body, then wraps the response to capture the issued `request_uri` from the JSON body, and stores the `request_uri → tenantId` mapping (5-minute lifetime)
2. On `GET /connect/authorize?request_uri=...`, it looks up the tenant from this mapping before falling back to query-string `acr_values`

Without this, every PAR-using client would land on `/tenant-discovery` because the URL no longer carries `acr_values`.

### Token Endpoint Tenant Resolution

The `/connect/token` endpoint has no `{tenantId}` route segment or `acr_values` parameter. To ensure `OctoUserStore`, `ClientStore`, and other per-tenant stores use the correct tenant database, `OidcTenantResolutionMiddleware` resolves tenant via a two-tier strategy:

**Authorization codes:**
1. During `/connect/authorize`, the middleware wraps the response body and captures the authorization code, mapping it to the tenant in an in-memory `ConcurrentDictionary` (10-minute expiry). Supports both `response_mode=query` (code from 302 Location header) and `response_mode=form_post` (code from hidden form field in 200 HTML response, used by server-side OIDC clients like the Asset Repository Services' GraphQL Playground)
2. During `/connect/token` with `grant_type=authorization_code`, the middleware reads `code` from the form body and looks up the tenant

**Refresh tokens (two-tier: in-memory + persistent):**
1. When `/connect/token` returns a new refresh token, the middleware captures it in the in-memory cache (30-day expiry)
2. `PersistentGrantStore` also stores the tenant ID in the `Description` field of the `RtPersistedGrant` entity
3. On refresh, the middleware first checks the in-memory cache; if missing (e.g., after service restart), it hashes the token (SHA256) and queries the persistent grant store for the tenant, then re-populates the in-memory cache

This two-tier approach ensures token refresh operations survive service restarts and deployments without requiring users to re-authenticate. `PersistentGrantStore` always uses the system tenant database regardless of the per-request tenant context.

### Per-Tenant Cookie Scoping

Auth cookies are scoped per tenant via `TenantCookieManager` (`src/IdentityServices/Cookies/TenantCookieManager.cs`). This prevents cross-tenant session leakage by appending `.{tenantId}` to cookie names (e.g., `.AspNetCore.Identity.Application.sbeg`).

Key components:
- **`TenantCookieManager`**: Custom `ICookieManager` that scopes `Identity.Application`, `idsrv`, and `idsrv.session` cookies per tenant
- **`OidcTenantResolutionMiddleware`**: Resolves tenant for `/connect/*` OIDC endpoints from `acr_values`, `id_token_hint`, or authorization code → tenant mapping
- **`UserProfileService`**: Adds `tenant_id` and `allowed_tenants` claims to tokens (used by endsession for cookie resolution and by backend middleware for tenant authorization)

See `docs/authentication.md` for detailed architecture and edge cases.

### Multi-Tenant Token Validation

Access tokens include `allowed_tenants` claims listing all tenants a user may access. Backend middleware validates the route tenant against these claims.

Key components:
- **`IAllowedTenantsResolver`** / **`AllowedTenantsResolver`** (`IdentityServerPersistence/Services/`): Resolves allowed tenants at token issuance time by checking cross-tenant user mappings across child tenants and walking up the ancestor chain
- **`UserProfileService.GetProfileDataAsync`**: Overrides the base class to add `allowed_tenants` claims to all issued tokens
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
- `ConsentApiController` - OAuth consent flow
- `DeviceApiController` - Device authorization flow
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
