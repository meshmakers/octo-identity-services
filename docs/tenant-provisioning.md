---
description: "Default-configuration provisioning, admin pre-provisioning, file roles and pipeline service accounts, scratch tenants"
applies_to: "**/Services/{Admin,FileRoles,ScratchTenants,RoleGrants}/**, {DefaultConfiguration*,AdminProvisioning*,PipelineServiceAccountFileRoles*}.cs"
---

# Tenant provisioning, default configuration and scratch tenants

## Default-Configuration Provisioning

The Identity CK model, default roles, identity resources, API scopes, API resources, and OIDC clients are provisioned to **all tenants** (not just the system tenant) during startup. This ensures OAuth/OIDC flows work when targeting any tenant. For child tenants, roles are written directly to the child tenant database via `EnsureRoleInChildTenantAsync()` using the same `childRepo` pattern as clients and resources. The identity service writes its data directly to child tenant databases (including the `octo-data-refinery-studio` SPA client when `RefineryStudioUrl` is configured), while other services (asset-repo, bot, etc.) send their data via the Distribution Event Hub. Cross-tenant users receive a `home_tenant_id` claim in their tokens.

**The system tenant is only bootstrapped when its database is genuinely absent — or an
infrastructure-only shell.** `SetupTenantAsync` used to call
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
because the bootstrap is the only path that creates the datasource user. For any other
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

**A failed tenant setup is retried durably.** `SetupTenantAsync` applies the
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
a retriable not-ready condition.

**Manual recovery** for a tenant that is already stuck without roles, without restarting the service:
`PUT {systemTenant}/v1/tenants/clearCache?childTenantId=<tenant>` on the asset repository publishes
`PreUpdateTenant` + `PosUpdateTenant`, which makes every service — including this one — re-run
`SetupAsync` for that tenant.

**Checking the Bootstrap seed of every tenant (read-only).** The child tenants are set up in parallel, and until the
engine gave each blueprint apply its own import command, two tenant imports that overlapped shared one import state
(a reset by one cleared the other's queues). `scripts/identity-bootstrap-seed-check.sh` shows whether a cluster was
hit: per tenant database it lists the seed entities of `System.Identity.Bootstrap` that are missing, stored more than
once or with another CK type, clients whose `provisionedByParentTenantId` names no ancestor of the tenant, and missing or
duplicated seed associations (exit 0 = clean, 2 = findings, 1 = incomplete). It runs mongosh inside the MongoDB pod with
read operations only (a write guard refuses the JavaScript otherwise; `--self-check`), reads no secret material and
passes the MongoDB password on stdin only. The guard is a deny list; where a MongoDB user with read access only exists,
pass it with `--mongo-user` and `--secret` to make the read-only promise technical. The expected entities and associations are embedded in
`scripts/identity-bootstrap-seed-check.inventory.js`; `BootstrapSeedCheckManifestTests` keeps them equal to the seed
files, so a seed change updates the list in the same change. Tests: `bash scripts/tests/identity-bootstrap-seed-check.test.sh`.
A cluster run needs kubectl access to the MongoDB namespace (shared clusters only via breakglass and with the
developer's go):

```bash
scripts/identity-bootstrap-seed-check.sh --context <kube-context> [tenant ...]
# local lane stack: --namespace octo-infra --pod mongodb-0 --container mongodb --password-file <file> --system-db <system db>
```

### Mirror roles in the tenant setup

The tenant setup provisions the mirrors of the flagged clients of the system tenant into every tenant at any depth (a scratch
tenant also those of its parent) and, right after each mirror, assigns the roles the original lists in `Client.MirrorRoleNames`
(System.Identity 3.9.0). So a new tenant, a nested tenant or a tenant after `ReRunTenantSetup` needs no manual role grant for
such a client (for example the CD's `ci-deploy-{cluster}` with its deploy role). A role that does not exist in
the tenant yet is a WARN and assigned on a later pass; a failed role write never fails the setup (ERROR in the log, the periodic
mirror reconciliation retries it). A tenant administrator who removes such a role keeps it removed (declined). Rules, deny-list
and the remaining risk of the inherited parent secret: `docs/client-mirroring.md` ("Roles mirrored by allow-list").

## Admin Provisioning (Cross-Tenant Pre-Provisioning)

The `AdminProvisioningController` allows users with the TenantManagement or UserManagement role to pre-provision cross-tenant user mappings in a **target tenant** without needing `allowed_tenants` for that tenant. The target must be the caller's own tenant or one of its registry descendants (system-tenant callers: any tenant) — `AdminProvisioningTargetScopeFilter`; before, the role was documented but not checked and any target was reachable. It is routed via the system tenant: `{tenantId}/v1/adminProvisioning/{targetTenantId}`.

**Regression tests and the route rule:** every route whose path contains `{targetTenantId}` must carry
`[TypeFilter(typeof(AdminProvisioningTargetScopeFilter))]` (class or action). `AdminProvisioningRouteCoverageTests`
derives the route set by reflection over all controllers, so a new route without the filter fails the unit tests.
`AdminProvisioningPipelineTests` runs the real routing, `AdminProvisioningController`,
`IdentityTenantAdministrationWritePolicy` and filter against a fake tenant registry: own/descendant 201;
sibling, sibling descendant, unrelated, system and unknown target 403 with an identical response; system caller
any registered tenant (unknown tenant: 404 from the action); create-then-provision; policy and filter together
(roleless caller stopped by the policy, role holder by the filter); `RoleEnforcement=Warn` (the filter only
logs, the call passes — the fix depends on `Enforce`). The rule covers every action that names a target tenant — `{targetTenantId}`/`{childTenantId}` in
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

**`provisionCurrentUser` from a shadow user:** when the calling token's subject is a cross-tenant
shadow user (`xt_…`, e.g. a session or octo-cli context scoped to an intermediate tenant A that provisions into
grandchild B), the mapping is written for the caller's **home identity** — the root of its `xt_` chain
(`ICrossTenantShadowUserChainResolver.GetSourceChainAsync`, last tier), looked up by name in the home tenant — not
for the shadow user. Before, the mapping was keyed on (A, shadow); the exchange from the home token (what MCP and
octo-cli do for every later call) never finds such a mapping (`ResolveExchangeSourceAsync` only tries the subject
and its home, `GroupRoleResolver` only the B shadow's chain), so the call answered success and the user stayed
`tenant_not_provisioned`. One home mapping serves both paths: from the home token directly, and from the A shadow
(dual-candidate rule). The exchange was deliberately **not** widened to ancestor shadow mappings. The
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
> strips the `Async` suffix from action names, so no route matched). It was fixed with a **named route**:
> `[HttpGet("{rtId}", Name = …)]` plus `CreatedAtRoute(name, new { tenantId, version, rtId }, dto)`, pinned by
> `EmailDomainGroupRulesCreateTests` (also with a trailing slash on the POST URL). **Rule for new create
> actions:** use a named route, not `CreatedAtAction` (breaks on the `Async` suffix) and not a hand-built
> `$"{Request.Path}/{id}"` (ignores `PathBase`, doubles a trailing slash). Pass `tenantId` and `version`
> from `RouteData.Values` explicitly: with `Asp.Versioning` and the `{tenantId:tenantId}/v{version:apiVersion}`
> prefix, link generation does not fill them in and answers "No route matches". The hand-built link in
> `ExternalTenantUserMappingsController.Create` predates this rule and still has those two weaknesses.

The `provisionCurrentUser` endpoint extracts `sub`, `preferred_username`, and `tenant_id` from the JWT, fetches all roles from the target tenant, and creates an `RtExternalTenantUserMapping` with all role IDs. It also adds the mapping as a member of the **TenantOwners** group (via `GroupMember` association), so the user inherits all roles through group membership. If a mapping already exists it is judged, not just returned: one that grants no effective role (no existing role in `MappedRoleIds`, none via a group) or carries a wrong `SourceUserName` (role lookup keys on the NAME, this lookup on the user id) is repaired in place; one that already grants a role is left alone. The `X-Provisioning-Outcome` response header reports `created` / `repaired` / `already-provisioned`. No login path stores a mapping any more (`FindOrCreateCrossTenantUserAsync(..., storeMappingIfMissing: false)`): the token exchange, the interactive cross-tenant login (`SignInCrossTenantUserAsync`) and the tenant switch — a bare mapping counted as explicit provisioning and bypassed `AllowSelfRegistration=false`. Only an admin action creates a mapping.

The `GET` endpoint returns `ExternalTenantUserMappingDto` with a `GroupNames` field populated by querying inbound `GroupMember` associations for each mapping entity.

The **per-tenant** `ExternalTenantUserMappingsController` (`{tenantId}/v1/externalTenantUserMappings`, used by `octo-cli GetExternalTenantUserMappings` and `IdentityServicesClient`) also resolves `GroupNames` on `GetAll`/`GetById` via `IGroupStore.GetGroupNamesForExternalUserMappingAsync` (inbound `GroupMember` walk, mirrors the AdminProvisioning resolution). Previously this controller left `GroupNames` empty, so a group-based grant looked like "no roles/groups" even though roles were inherited via the group. `IGroupStore` also exposes symmetric `AddMemberExternalUserAsync` / `RemoveMemberExternalUserAsync` (previously only user/client member add/remove existed).

## File roles, System.Files data policies and machine clients

Blueprint `System.Identity.Bootstrap` 1.6.0 seeds the roles `FileManagement` / `FileViewer`, the data permissions
`files.read` / `files.manage` (660…52/53) and the enforcing policies 660…54/55 on `System.Files/FileSystemEntity`
(FileViewer reads; FileManagement reads and writes; the asset repository carries the same rules as a built-in
baseline). Details, the one-time `FileRoleGrant` (Reporting roles → File roles), the one-time
`TenantAdministratorFileRoleGrant` (human tenant administrators → `FileManagement`, own marker so tenants with the
Reporting marker still get it) and the recurring
`PipelineServiceAccountRoleGrant` are in `docs/persistence.md`. Rules to remember:

- Pipeline service accounts (`octo-pipeline-sa-*`) always hold the baseline roles of
  `PipelineServiceAccountBaselineRoles` — `FileManagement` (tenant setup: only with System.Files) and
  `StreamDataReader` (the stream-data gate; covers legacy accounts without `AssignedRoleNames`):
  granted by `CreateIdentityDataCommandRequestConsumer` in the command that creates/touches them (kept by the
  declarative sync, additive for a `null` list) and caught up at every tenant setup (not run-once, not on the nightly
  `CacheOnly` update). Only seeded roles, only the exact prefix; a system grant, not through the role change guard.
  A new baseline role is one entry in `PipelineServiceAccountBaselineRoles`, never a second copy of the grant.
- The prefix octo-pipeline-sa- is the only trust check and it is not reserved: a client administrator may
  not grant platform roles it does not hold, but it can create a prefixed client that the setup pass then grants the
  baseline roles. Known gap.
- Customer client-credentials clients and octo-cli `LogInClientCredentials` carry no roles: 403 on the Files API
  until the client is given a File role. Reporting uses in-process system sessions and needs nothing.
- Tests: `FilesDataPermissionsSeedTests`, `PipelineServiceAccountRoleGrant*Tests`,
  `PipelineServiceAccountBaselineRolesTests`, `TenantAdministratorFileRoleGrant*Tests`,
  `PipelineServiceAccountBaselineRolesConsumerIntegrationTests` (own class: the other provisioning tests assert
  exact role sets).

## Scratch tenants: the creator becomes administrator

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
- **Roles of the creator:** the mirror inherits every role of `TenantOwners` in that child - all built-in platform roles **including
  `SecretManagement`** (intended: the agent creates clients with a secret in its scratch tenant), but no app role a
  blueprint seeds later. It counts in that child and, for the parent-administration endpoints (mirror secret rotation,
  bot-services jobs), in tenants below it - never in the parent or sibling tenants.
- The child token of the agent is the ordinary one: `client_credentials`, `acr_values=tenant:<child>`, `scope=octo_api`, with the mirror's own
  secret (`RotateMirrorSecret`) or - while per-tenant mirror secrets keep the inherited secret - the parent client's secret.
- Tests: `ScratchTenantCreatorGrantIntegrationTests` (real MongoDB: grant only for the creator, none without a marker, repeated setup, re-provisioned
  mirror, persisted revoke, foreign parent, non-mirror client, non-system parent, audit without secrets), `GroupsControllerScratchRevokeTests`.
