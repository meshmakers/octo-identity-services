---
description: Projects, dependencies, CK model id, API versioning, consumers, configuration options, password policy, data protection keys, Docker
applies_to: {Program,IdentityApi*,*KeyStore}.cs, *.csproj, Dockerfile, appsettings*.json, azure-pipelines.yml, **/{Configuration,Mapping,Consumers,DataProtection}/**
---

# Architecture, configuration and operations

## Project Structure

- **IdentityServices** (`src/IdentityServices/`): Main ASP.NET web application and entry point. Contains the OpenIddict protocol configuration (`Configuration/OpenIddictConfiguration.cs`), the passthrough protocol controllers (`Controllers/Protocol/`), the OpenIddict integration layer (`OpenIddict/`), plus controllers for account management, consent flows, device authorization, and the System API (v1). Entity ↔ DTO mapping is explicit code in `Mapping/` (no mapping library; see `docs/persistence.md` § DTO Mapping).

- **Authentication** (`src/Authentication/`): Razor class library with authentication schemes and handlers. Implements dynamic authentication for multiple providers:
  - OAuth providers: Google, Facebook, Microsoft, Azure Entra ID
  - LDAP providers: OpenLDAP, Microsoft AD

- **IdentityServerPersistence** (`src/IdentityServerPersistence/`): Data persistence layer. Contains the Octo-native stores (ClientStore, ResourceStore, IdentityProviderStore, GroupStore, …) and the custom OpenIddict stores in `SystemStores/OpenIddict/` (application/scope/authorization/token stores over the existing CK entities). Uses Octo Runtime Engine with MongoDB.

- **Persistence.IdentityCkModel** (`src/Persistence.IdentityCkModel/`): Construction Kit model definitions (YAML files in `ConstructionKit/`) for identity entities. Uses Octo source generation to create runtime types.

- **IdentityServices.Resources** (`src/IdentityServices.Resources/`): Localized string resources (resx files).

## Key Dependencies

This service depends on Octo framework packages (versioned via `$(OctoVersion)` in Directory.Build.props):
- `Meshmakers.Octo.Runtime.Engine.MongoDb`: MongoDB persistence
- `Meshmakers.Octo.Services.Infrastructure`: Base service infrastructure
- `Meshmakers.Octo.ConstructionKit.SourceGeneration`: Code generation from CK models

## Construction Kit (CK) Model

The `Persistence.IdentityCkModel` project uses YAML-based model definitions that are transformed into C# code at build time. Model files are in `src/Persistence.IdentityCkModel/ConstructionKit/`. The model ID is `System.Identity-3.0.0` (ckLanguage 2, first major of the 3.x line) with dependency on `System-[2.5,3.0)`. Generated types live in namespace `Persistence.IdentityCkModel.Generated.System.Identity.v3` (the suffix is the **major** of the model: 2.x was `.v2`, the registration is `AddCkModelSystemIdentityV3()`).

## Command consumers run on every replica

`CreateIdentityData` (`CreateIdentityDataCommandRequestConsumer`, queue `octo::identity::create-identity-data`) is
registered **shared** (competing consumers) in `Consumers/IdentityCommandConsumers.cs`, called from `Program.cs`:
with two or more replicas every replica consumes it and each command is processed **exactly once** by one of them.
Previously it was the classic exclusive consumer: only one replica consumed, the others waited, and a hung owner
(prod-1 2026-10-18/19, NotReady node) blocked identity provisioning.

- `CommandConsumerOptions { MigratesLegacyCommand = true }` is **required**: all senders (asset repository, bot,
  communication controller, AI, MCP, report service; `AddCommandClient`) still send to the classic address. The
  consumer uses the queue `…::shared` and serves the classic address only while no old exclusive replica is alive, so a
  rolling update (old and new build side by side) starts without errors and loses or duplicates nothing. Plain shared
  options without the flag would receive nothing from these senders. Rollback: stop the new replicas first, then start
  the old build (`octo-distributedEventHub/docs/DEVELOPER.md`, "Migrating exclusive command queues").
- Safe under competing consumers: no state between messages, one MongoDB transaction per message, existing clients
  replaced with the version read in the transaction (a conflict is retried). The exclusive endpoint had no
  concurrency limit, so one replica already ran these commands concurrently.
- The deprecation warning ("classic EXCLUSIVE topology") is no longer logged at start; a new command consumer is
  added to `IdentityCommandConsumers` with the shared options and a comment why it is safe.
- The CK method handlers (`IdentityMethodHost`) are unaffected: they already use the shared per-method queues of
  octo-common-services.
- Tests: `IdentityServices.IntegrationTests/Consumers/IdentityCommandConsumerReplicaTests` (Docker: MongoDB + RabbitMQ
  Testcontainers): two replicas with the production registration, 16 commands from a classic sender, each processed
  once, both replicas consume, each client exists once; no deprecation warning at start; rolling update old exclusive
  + new shared replica (old keeps the traffic, after it stops the new replicas take over, nothing lost or duplicated).
- Operations: queues `*::shared` and exchanges `*::send` are new names; broker policies or monitoring matching command
  queue names must include them.

## Multi-Tenancy

The service supports multi-tenancy via tenant ID in routes. The route pattern is `{tenantId:tenantId=System}/{controller=Home}/{action=Index}/{id?}`.

## API Versioning and Route Prefix

All API endpoints use a single tenant-scoped route prefix: `{tenantId:tenantId}/v{version:apiVersion}` (e.g., `octosystem/v1` for the default system tenant, `MyTenant/v1` for a specific tenant). The system tenant ID defaults to `OctoSystem` (normalized to lowercase in URLs) and is configurable via `OctoSystemConfiguration.SystemTenantId`.

Authorization policies (`src/IdentityServices/Authorization/IdentityApiAuthorizationPolicies.cs`):
every administration endpoint requires the `octo_api` scope (read: or `octo_api.read_only`) **and** a
tenant role — `UserManagement` for users/roles/groups/mappings/data permissions, `TenantManagement` or
`UserManagement` for clients/mirrors/API resources/scopes/secrets/identity providers/e-mail domain rules/
admin provisioning, the operational roles for directory reads (role names, a client's roles/actors), and
`TenantManagement` in the system tenant for the log level. Exception: `GET users/directory` (id + display
name only, for assignee pickers) needs no role but `IdentityUserDirectoryReadPolicy` — the token's `tenant_id`
must equal the route tenant, unconditionally (`IdentityApiOwnTenantRequirement`); the guard pins it. The role check probes the raw `role` claim and
`ClaimTypes.Role` (RoleClaimType trap). `OCTO_IDENTITYAPIAUTHORIZATION__ROLEENFORCEMENT=Warn`
logs instead of denying (transition); default `Enforce`. 🔴 A new controller action must use one of these
policies — `IdentityApiAuthorizationPolicyTests.EveryTenantApiEndpoint_RequiresARole_UnlessExplicitlyAllowListed`
fails otherwise. Full table: `docs/system-api.md` § Authorization Policies.

**API secret writes need `SecretManagement`.** `IdentitySecretAdministrationPolicy` (scope `octo_api` +
`SecretManagement`, shared `IdentityApiAuthorizationPolicies.SecretAdministrationRequirement`) guards every create/rotate/
delete in `ApiSecretsController`, the mirror secret rotation (`ClientMirrorController.RotateSecret`), a `clientSecret` in `POST/PUT clients` (checked in the action via
`IAuthorizationService`) and the `Client.AddSecret`/`RemoveSecret` handlers (`DecideClientSecretCaller`; the CK model's
declared roles stay `TenantManagement`/`UserManagement`). Reads keep `IdentityTenantAdministrationReadPolicy`. Staged by
`OCTO_IDENTITYAPIAUTHORIZATION__SECRETMANAGEMENTROLEENFORCEMENT` = `Warn` (**default**: the previous roles still pass,
logged `...SecretManagementRoleEnforcement=Enforce`) | `Enforce` — because the role was granted only once to
local human admins, not to `TenantOwners`, cross-tenant admins or clients. `Warn` never allows less than
before; `RoleEnforcement=Warn` relaxes it too. A refused `IdentityApiRoleRequirement` answers 403
`{"message": "...requires the role 'X'..."}` (`IdentityApiForbiddenReasonResultHandler`). Tests:
`ApiSecretsControllerTests` (role x verb x kind x mode matrix, TenantOwners member, client create/update),
`IdentityApiAuthorizationPolicyTests`. Inventory: `scripts/identity-secret-management-role-check.sh`.

## Bootstrap blueprint lines and version order

`System.Identity.Bootstrap` carries two independent lines that each bump exactly once, in a fixed order
(decision Gerald 2026-10-11): the **Files line** is 1.5.0 (FileManagement/FileViewer roles 660…61/62) and 1.6.0
(System.Files data permissions/policies 660…52–55, FileManagement for pipeline service accounts); the **SECRET
line** is **1.7.0** (SecretManagement role 660…60 and its grants) on top of it. There is no 1.4.0. The CK model
follows the same rule: 2.23.0/2.24.0 belong to the ownership markers, **2.25.0** turns the
identity-provider `ClientSecret` into the Secret value type. Whoever bumps next re-bumps above the
published maximum (`octo-ckc -c ValidateVersion` against the catalogs). The upgrade path is pinned by
`BootstrapUpgradeToSecretLineIntegrationTests` (frozen 1.5.0 / 1.6.0 seed snapshots under
`tests/IdentityServices.IntegrationTests/BootstrapSnapshots/`): nothing is lost, and from 1.6.0 the delta is exactly the
SecretManagement role (no TenantOwners edge: human administrators only) and the direct grants to existing local administrators. A new bootstrap version
that changes seeds should add its own snapshot.

## Configuration

Environment variables are prefixed with `OCTO_`. Key configuration sections:
- `Identity`: Identity service options
- `System`: System configuration

Key identity options (`OctoIdentityServicesOptions`):
- `AuthorityUrl`: Public URL of the Identity service (default: `https://localhost:5003`)
- Token signing: `KeyFilePath` / `KeyFilePassword` (static PKCS#12 certificate) — unchanged by the OpenIddict migration. The `Identity:IdentityServerLicenseKey` option was **removed** with the migration (no license required).
- `RefineryStudioUrl`: Public URL of the Data Refinery Studio SPA. When set, the `octo-data-refinery-studio` OIDC client is auto-provisioned in all tenants with correct redirect URIs, CORS origins, and front-channel logout. Example: `OCTO_IDENTITY__RefineryStudioUrl=https://studio.example.com`
- `CorsPolicyCacheSeconds` (env `OCTO_IDENTITY__CORSPOLICYCACHESECONDS`, default `60`): lifetime of the cached Identity CORS policy (`IdentityCorsPolicyProvider`). The policy is rebuilt from the client origins of all tenants after this time, so a missed `CorsClientsUpdate` (other pod, client written without event) or a removed origin heals on its own. A policy with an **empty origin list is never cached** (it is rebuilt on every request until origins exist), so a tenant provisioned after the first request is not blind to the SPA. `0` or less disables the time-based expiry (events only). Events stay the fast path: `CorsClientsUpdate` is published by `ClientsController` (every write, and the overlay endpoint **unconditionally**, also when 0 URIs were added) and by `ClientMirrorProvisioningService` (new mirror, sync, removal; one event per affected child tenant, publish failures are logged and never fail the provisioning). **Single-flight:** the requests that find the entry expired or invalidated share one load (`IdentityCorsPolicyProvider.GetEntryAsync`, `_inflight` per generation under a lock); before, every concurrent request at expiry read the clients of every tenant itself (prod-1: paired rebuilds 2-30 ms apart every minute). A new load starts only after an invalidation (new generation; the old load still never publishes) or when the shared one has finished; the slot is cleared before the task completes, so a failed load reaches its waiters and the next request retries. An empty policy is still not cached, but concurrent requests share one load meanwhile. Logging: the rebuild line at Debug, `Identity CORS origins changed: n origins (added: …; removed: …)` at Information only when the origin set differs from the previous load. Tests: `IdentityCorsPolicyProviderTests` (parallel requests at expiry, invalidation during a load, empty list, failure with waiters, log levels). The common-services `CorsPolicyProvider` (other services) is a separate follow-up.
- `ClientMirrorReconciliationInterval` (env `OCTO_IDENTITY__CLIENTMIRRORRECONCILIATIONINTERVAL`, default `300` seconds): interval of the periodic client mirror reconciliation; `0` or less switches it off. See "Periodic mirror reconciliation" above.
- `DataProtectionKeysPath`: **Legacy / seed-only.** When set and the directory contains `key-*.xml` files, those keys are imported once into MongoDB at startup (zero-logout migration from old PVC). Safe to leave unset in new deployments; DataProtection keys are now always persisted in MongoDB.
- `DynamicClientRegistration.Enabled` (env `OCTO_IDENTITY__DYNAMICCLIENTREGISTRATION__ENABLED`, default `true`): RFC 7591 Dynamic Client Registration so interactive MCP clients (Claude Code) that require DCR can self-register a public authorization-code+PKCE client via `POST /connect/register`. Enabled by default (set `false` to disable per deployment). Hard-gated (loopback redirects, PKCE, no secret, server-fixed scopes, per-IP rate limit, per-tenant cap, TTL). Registers into the system tenant + mirrors to all tenants; tenant resolved at authorize by §9 email-first discovery. Also `AllowedScopes` / `ClientTtlDays` / `MaxClientsPerTenant` / `RateLimitPermitsPerMinute`. See `docs/authentication.md` § Dynamic Client Registration and `docs/CONCEPT-MCP-DYNAMIC-CLIENT-REGISTRATION.md`.

## Password Policy (mirrored client-side — keep in sync)

User passwords are validated by ASP.NET Core Identity's default `PasswordOptions`
(minimum length 6; requires digit, lowercase, uppercase, and non-alphanumeric) — the
policy is **not** overridden in this repo. `UsersController.Post` enforces it atomically
via `UserManager.CreateAsync(rtUser, password)`: an invalid password
persists no user.

**The Refinery Studio frontend duplicates this policy** in `octo-frontend-refinery-studio`
(`src/octo-mesh-refinery-studio/src/app/shared/validators/password-policy.validator.ts`) as
a pre-submit UX check — there is no endpoint exposing the policy over the wire. The two
copies are kept in sync by hand: **if you override `PasswordOptions` here (or bump a
`Require*` / `RequiredLength`), you MUST update that frontend validator and its inline message
to match**, otherwise the client-side hint silently diverges from what
this service actually enforces.

The policy error descriptions come from `IdentityTexts` (`src/IdentityServices.Resources`, English +
German) in the **server culture**; clients must branch on `IdentityError.Code`, never on the
description. `tests/IdentityServices.UnitTests/Resources/PasswordPolicyTextsTests.cs` pins that every
German and English policy text is complete (CK v2 D7: the German `PasswordRequiresDigit` text
was truncated to "wörter müssen …").

User secrets ID: `173d8e91-b831-4e8a-a43f-672c57e6a4da`

## Data Protection Key Persistence

ASP.NET Data Protection keys are always persisted in MongoDB (system tenant, `RtDataProtectionKey` entities) via `DataProtectionKeyStore : IXmlRepository` (registered as a singleton). The application name remains `OctoIdentityServices` (set via `SetApplicationName()`), so key isolation is unchanged from the previous file-based implementation.

The `DataProtectionKeysPath` option (`OCTO_IDENTITY__DataProtectionKeysPath`) is **legacy / seed-only**: when set and the directory contains `key-*.xml` files, those keys are imported once into MongoDB on startup (zero-logout migration from the old PVC). After the import succeeds the path can be left unset in all new deployments. The Helm chart's `services.identity.dataProtection` toggle and the associated PVC have been removed; ship order is identity image first, then the updated chart.

**Encryption at rest.** Registration: `AddOctoDataProtectionKeyRing()` (`SystemStores/DataProtection/`). The secret part of every key (`masterKey`) is wrapped with the **platform key ring** `SecretEncryption` (`OCTO_SECRETENCRYPTION__KEYS__<id>` / `ACTIVEKEYID`, AES-256-GCM via the engine's `ISecretAttributeProtector`, envelope `enc:v2:<kid>:…`) — no certificate, no new secret. The stored XML is ASP.NET's own encrypted form (`<encryptedSecret decryptorType="…PlatformKeyRingXmlDecryptor, IdentityServerPersistence">`), written by `DataProtectionKeyStore` itself (not `KeyManagementOptions.XmlEncryptor`) so it can decide per write and so `decryptorType` carries no assembly version. Key id, dates and key material never change, so nobody is logged out.
- `Identity:DataProtection:EncryptExistingKeys` (`OCTO_IDENTITY__DATAPROTECTION__ENCRYPTEXISTINGKEYS`, default `false`): `false` = stored keys stay as they are, new keys are written **plain while the store holds keys** (old pods of a rolling update keep reading them) — a store without any key (fresh install) gets encrypted keys. `true` = new keys encrypted, and the startup step rewrites every plain key encrypted in place (idempotent, every pod may run it).
- `DataProtectionKeyRingStartupService` (hosted): refuses to start (`DataProtectionKeyRingException`) when the flag is on without a `SecretEncryption` key, or when a stored key is wrapped with a key id that is not configured; re-wraps keys with a non-active key id (platform key rotation — remove the old id only after the re-wrap); other failures (DB) are logged and retried next start.
- **Never rename or move `PlatformKeyRingXmlDecryptor`** — stored keys reference its type name. **Rollback** to an image without the decryptor after keys are encrypted logs every user out (old image cannot read the keys, creates new ones). Rollout/rollback: `docs/rollout-identity-dataprotection-encryption.md`.
- Tests: `PlatformKeyRingXmlEncryptionTests` (unit, real ASP.NET stack), `DataProtectionKeyEncryptionIntegrationTests` (Mongo: multi-replica, migration, rotation, raw DB dump has no key material).

## Docker

Build image using `src/IdentityServices/Dockerfile`. Requires build args:
- `OCTO_PRIVATE_NUGET_SERVICE`: Private NuGet feed URL
- `OCTO_PRIVATE_NUGET_CERTIFICATE`: Path to CA certificate
- `OCTO_VERSION`: Package version to use

## .NET runtime of the image and the Shared Framework findings

- The runtime stage uses the own base image `meshmakers/dotnet_aspnetcore-runtime-node` (build stage: `dotnet_sdk-node`), currently `1.4.0.0`
  (built from `mcr.microsoft.com/dotnet/aspnet:10.0-noble`, .NET runtime 10.0.13). Bump the tag when `dockerimages` publishes a rebuilt image.
- `System.Security.Cryptography.Pkcs` and `System.Security.Cryptography.Xml` come from the **.NET Shared Framework** (via OpenIddict and
  DataProtection), not from a package reference. A direct `PackageReference` pin in the web project fails with `NU1510` (package pruned by the
  framework), so **no package pin is possible**. `dotnet list package --vulnerable` may keep reporting them at the version of the build SDK
  while restore stays silent: that is a known, covered false positive.
- The control is the **image runtime**: since `tpl-v1.7.0` the template step `verify-dotnet-runtime.yml` (inside `build-and-push-docker.yml`) fails
  the image build when the final stage ships a .NET runtime below the minimum (10.0.13, one place: `minRuntimeVersion` in the template). Do not chase
  these findings with pins; the package-level part and the runtime check are tracked separately.
