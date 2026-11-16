---
description: "Service-account clients over the event hub, multi-tenant client-credentials auto-provisioning, client roles and group assignment"
applies_to: "**/SystemStores/*Client*.cs, **/Services/{ClientGrants,PipelineServiceAccounts,DynamicClientRegistration}/**, *ClientMirror*.cs, ClientsController.cs"
---

# Client credentials, service accounts and client roles

## Service-Account Clients over the Distribution Event Hub

The Communication Controller provisions one `client_credentials` service account per mesh adapter, so
pipeline execution runs under a real identity. It can only reach this service **over the bus**: the
REST `ClientsController` needs an `octo_api` bearer token, i.e. the very identity being created, and
no client-credentials client with a secret is seeded anywhere. `CreateIdentityDataCommandRequestConsumer`
therefore had to learn three things it could not do before — it hard-coded `RequireClientSecret=false`,
never wrote a `ClientSecrets` entry and never touched an association:

| `DistClientDto` field (octo-common-services `Meshmakers.Octo.Services.Contracts`) | Consumer behaviour |
|---|---|
| `ClientSecret` (**plaintext**, optional) | Hashed with `OctoSecretHasher.HashSecret` (the same legacy SHA-256 convention `ClientsController` uses) and written as the single `ClientSecrets` entry. **Never** persisted or logged in the clear. |
| `RequireClientSecret` (default `false`) | Written verbatim. The default reproduces the previous hard-coded behaviour, so every producer that predates this option keeps creating public clients unchanged. |
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
fail closed. A service account lacking the tenant's business roles (e.g. Accounting) therefore makes
the feature go quiet with no error anywhere. When setting up delegation for a tenant, grant
`octo-pipeline-sa-{adapterRtId}` those roles as well —
`PUT {tenantId}/v1/clients/{clientId}/roles/{roleName}` or `octo-cli AddClientToRole`. The caller must hold
a built-in role itself to grant it to a client (403 `role-not-held` otherwise); custom roles are free, and a caller holding
`UserManagement` may also grant app roles (roles a blueprint other than `System.Identity.Bootstrap` seeds) it does not hold.

**Deployment order:** identity first, then the Communication Controller. An identity that predates
this change ignores the new fields and would create a secretless client.

Tests: `tests/IdentityServices.IntegrationTests/Persistence/ServiceAccountClientProvisioningIntegrationTests.cs`
(hashed secret + both grant types + scope + role on create; a second run with the same secret rotates
nothing and creates no duplicate client or role edge; a re-run without a secret preserves the existing
one; a client of the earlier shape stays public and secretless; an unknown role name is skipped instead
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

## Multi-Tenant Client Credentials (Auto-Provisioning)

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

**Provisioning service (done):**
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
Provisioning failures are logged but never break tenant setup.

**Several replicas, restore.** Every identity replica runs the tenant setup on `PosCreateTenant`, and a
restore sends `PreDeleteTenant` (its drop removes the tracking rows, see below), then attaches the tenant
again (`PosCreateTenant`). So several replicas provision the same (client, child) pair at once, and one of
them may still provision while another drops the rows. The tracking row is unique per pair
(`ParentClientId` + `ChildTenantId`), and the provisioning handles both races without an error:

- *Row recorded by another replica:* the insert of the tracking row hits the unique index (a
  `DuplicateKeyException`, or a bulk write error with a duplicate key behind an `OperationFailedException`;
  `IsDuplicateKey` checks the whole exception chain). The pair counts as already present. When this run had
  inserted the child mirror and both replicas inserted one, the duplicate is erased by the rule the convergence
  uses (blueprint-range record, else the lowest rtId; never the read order), so a reconciliation pass running at the same time
  keeps the same record; when the other replica replaced this run's insert, that is the one mirror and stays.
- *Row dropped by another replica:* the version-checked bump of a tracked pair finds the row gone
  (`EntityNotFoundException`). That is a debug line, and the row is not written again: the tenant is being
  deleted or restored, and the setup after the re-attach records it anew. The immediate sync and the
  reconciliation count such a pair as skipped, not as synced or repaired.

Every other failure of these writes still reaches the setup and is logged as an error. **Open
question (intentional):** parent is hard-wired to `systemContext.TenantId` —
nested customer sub-tenants are out of scope for v1, see
`octo-communication-controller-services/docs/concepts/cicd-workload-deployment.md`.

**Upkeep hooks (done):**

- `ClientStore.MutateAsync` (the only way to change a stored client) fires `SyncMirrorsForClientAsync`
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
  only drops the parent's tracking rows. `PreDeleteTenant` reaches every
  identity replica, so each replica drops the same rows; a row another
  replica dropped first is skipped with a debug line, not an error. Any
  other failure to drop a row is still logged as an error.

All three paths are best-effort: failures are logged and **do not** bubble
back to the primary operation (client update, client delete, tenant delete).
The same holds for the secret writes of `Client.AddSecret` / `Client.RemoveSecret`
and the REST secret endpoints (sync after commit, error logged).

**Periodic mirror reconciliation (Security).** Before it, only the next identity start
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
  writes the entity as given and does **not** advance `rtVersion` (engine), so the check only holds when every writer
  takes part. All child-mirror writes go through `ConvergeChildMirrorAsync` (immediate sync, start-up provisioning, backfill,
  reconciliation: read child, read parent, derive, replace with the read `rtVersion`, re-read and re-derive on
  `RtVersionConflictException`, at most `MaxMirrorWriteAttempts` = 5) or the versioned `RotateMirrorSecretAsync`. The sync re-reads
  the parent after the child (the passed snapshot is only the fallback), so a delayed sync cannot write an older parent state over
  a newer one. Result: a write after our child read makes our replace fail, a write before it is visible to the comparison while
  the parent was read after it; neither a removed secret nor a superseded own secret can come back.
- 🔴 **All other writers of a client record are versioned too.** Every writer that can touch a mirror writes with the
  `rtVersion` it read, so its write advances `rtVersion` and a reconciliation pass that read the mirror before it fails its check
  and re-reads (before, such a write left `rtVersion` unchanged and the stale pass overwrote it unnoticed):

  | Writer | How |
  |---|---|
  | REST client `PUT`, overlay URIs, overlay clean-up, `PATCH autoProvisionInChildTenants` (any tenant, mirrors included) | `IOctoClientStore.MutateAsync` (`UpdateAsync` is gone), retry on conflict, `409` after 20 attempts |
  | `octo-cli` token-exchange grant step (`OctoCliTokenExchangeGrant`) | replace with the version read in the same transaction |
  | Post-blueprint URI restore / URI family pass (`DefaultConfigurationCreatorService`) | replace with the version read in the same transaction |
  | Bus consumer `CreateIdentityDataCommandRequestConsumer` (existing client) | replace with the version read in the same transaction; a conflict fails the message, which is retried |
  | Tracking row: immediate sync, start-up provisioning, mirror secret rotation | the row is re-read right before the write (sync) and written with its version; a concurrent bump wins (the counter is informational). When the sync or the provisioning had to **insert** the mirror, the versioned row write claims the insert, exactly as the reconciliation does: a row that changed or vanished meanwhile (another writer re-created the mirror, `RemoveMirrorAsync`, the delete cleanup) withdraws the inserted client, so no duplicate and no untracked mirror (a removed mirror the sync would otherwise have re-created) stays behind |
  | **Blueprint seed upsert** (engine `ImportRt`, `ImportStrategy.Upsert`) | **not changed** (see below) |

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
  child tenant id) / `BeforeMirrorInsertForTests` / `BeforeMissingMirrorWriteForTests` (between the child read of a missing
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
  write (red with unversioned writers); a client `PUT` in the child tenant, the `octo-cli` grant step and an immediate sync
  that re-creates a missing mirror, each between the job's reads and its write (red with unversioned writers), and a transactional
  stale write that cannot bring a removed secret back; a missing mirror whose row is removed before the insert; two parallel passes
  re-creating a missing mirror; metric and log canary),
  `tests/IdentityServerPersistence.UnitTests/Services/ClientMirrorReconciliationTests.cs` (comparison incl. token fields,
  marker case, read order + version, conflict, orphan with grace pass and foreign client, unreachable child, withdrawn
  insert, row gone on the re-read),
  `tests/IdentityServices.UnitTests/Services/ClientMirrorReconciliationHostServiceTests.cs` (interval).

**Management REST endpoints (done):** all under
`{tenantId}/v1/clients/{clientId}/...`:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `mirrors` | List the sub-tenants this client has been auto-provisioned into. |
| `POST` | `mirrors/provisionInExistingTenants` | Backfill — provision into every existing sub-tenant of the caller. Requires the client to be flagged (400 otherwise). |
| `POST` | `mirrors/provisionInTenant?childTenantId=…` | One-shot provision into a specific sub-tenant. |
| `DELETE` | `mirrors/{childTenantId}` | Remove a single mirror (drops both the child-side `RtClient` and the parent's tracking row). |
| `PATCH` | `autoProvisionInChildTenants` | Flip the `AutoProvisionInChildTenants` flag on the client without rewriting the full client object. Body: `{ "enabled": true\|false }`. |

Backed by `ClientMirrorController` + `ClientAutoProvisionFlagController` in
`TenantApi/v1/Controllers/`. The `PATCH` flow piggybacks on
`ClientStore.MutateAsync` (version-checked) so the post-commit upkeep hook fires
automatically — flipping the flag from `false` → `true` does **not**
backfill existing sub-tenants; the operator must explicitly trigger
`provisionInExistingTenants` for that (or wait for the next service
startup, which runs the same provisioning loop).

**End-to-end coverage (done):**
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
hookup added with the provisioning service. `ServiceCollectionFixture` now registers
`AddMigrations(typeof(IdentityServiceConstants).Assembly)` so the same
constructor parameter that production resolves to `MigrationService` is
satisfied in tests too.

The CLI commands and the Studio UI are tracked separately.

## Client Role & Group Assignment

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
  `GroupsController` — `GET/PUT/DELETE /groups/{rtId}/members/clients[/{clientId}]`; `{clientId}` is the OAuth client id
  or the client's rtId, resolved by `GroupClientMemberResolver` (rtId first, then client id; also used by `Group.AddMember` /
  `Group.RemoveMember`), unknown → `404` with `NotFoundErrorDto` (before, a client id answered 500). `GroupDto` gained
  `MemberClientIds`; `ClientDto` gained `RtId` (read-only, identifies the client as a group member).
- **Blueprint cleanup gate:** `PreBlueprintCleanupMigration` now sweeps orphan `AssignedRole` edges for
  `RtClient` origins too (aligned with the user-side strategy). No capture/restore pass is needed for
  clients — the feature postdates the imperative seed, so no client held a random-rtId role edge at the
  one-time 17→18 cutover. Client role/group assignments are declarable in the blueprint seed via the
  generic `associations:` block.
- **Tests:** `tests/IdentityServices.IntegrationTests/Persistence/ClientRoleAssignmentIntegrationTests.cs`
  (Testcontainers MongoDB) covers direct-role assignment, group-inherited roles via client membership,
  and removal.
