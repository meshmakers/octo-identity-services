---
description: "tenant_id on client-credentials tokens, ambiguous tenant binding, per-tenant mirror secrets and which mirror matched"
applies_to: "*ClientMirror*.cs, {ClientCredentialsTenantProcessor,MirrorSecretUsageTelemetry,OctoApplicationManager}.cs"
---

# Tenant binding of client-credentials tokens and client mirroring

## `tenant_id` on Client-Credentials Tokens

Previously a `client_credentials` access token carried `client_id`, `scope` and (since client roles)
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
  tenant** — so that is what is stamped. ⚠️ **That fall-back was narrowed by the ambiguity refusal (below): it now
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

Consumers narrow the exemption behind their own staged switch — see `octo-common-services/docs/tenant-authorization.md`
§ "Tenant Authorization — the service-token exemption". This service also calls
`AddOctoTenantAuthorization(builder.Configuration)` so the switch is settable per environment
(`OCTO_TENANTAUTHORIZATION__…`); its defaults keep today's behaviour.

Tests: `tests/IdentityServices.UnitTests/Services/ClientCredentialsTokenClaimsTests.cs` (the tenant
decision, plus `ClientCredentialsClaimCompositionTests` for the destination routing) and — the
wire-level proof — `TokenShapeGoldenTests.ClientCredentials_AccessTokenShape_MatchesGoldenBaseline`,
whose recorded `client-credentials-access-token.json` now carries `tenant_id`. That is a **deliberate
golden re-record**, the third of the migration after the access-token identity claims and
the on-behalf-of grant entry; the diff is exactly that one added claim.

## Ambiguous Tenant Binding on `client_credentials`

The tenant-stamping fall-back — "no `acr_values` ⇒ the client store resolved against the system tenant, so
stamp the system tenant" — **does not survive client mirroring**. `AutoProvisionInChildTenants`
provisions the *same* `ClientId` with the *same* secret into every child tenant
(`ClientMirrorProvisioningService.CreateMirrorClient` copies `ClientSecrets` verbatim). For such a
client id, "found in the system tenant" is not evidence of "belongs to the system tenant" — the
binding is **ambiguous**, and a caller holding a child tenant's credentials could simply omit
`acr_values` and be handed a system-tenant token. Every authorization asking "is the caller in the
system tenant" — which is what the system-route hardening builds on — was therefore
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
`IIdentityAuditService`. Unambiguous ⇒ unchanged tenant-stamping behaviour, system tenant stamped.

> The Duende-era `ClientCredentialsTenantAmbiguityEvent` (category `ClientCredentials`, ID `50580`,
> expanded by `OctoEventSink`) is gone with the event sink itself. `IIdentityAuditService` is the
> OpenIddict-era replacement and takes the event name and the formatted fields directly — the same
> shape the ported delegation failures use, and the same "failures persist, successes are log-only"
> rule.

- 🔴 **The mirror lookup fails closed.** A repository error rejects the request rather than falling
  back to "system" — guessing there is exactly the escalation being closed. The blast radius is
  bounded: the probe runs *only* on the no-`acr_values` path.
- 🔴 **Ordering matters.** The processor runs **before any claim is composed**, so a refused request
  never carries a guessed `tenant_id`, and the tenant-stamping invariant (tenant stamped before the roles) is
  preserved for every accepted request.
- **Caller inventory (checked across the whole `dev` checkout, not assumed).** No production caller
  is broken: `octo-mesh-adapter` `ServiceAccountTokenService` (all 3 call sites),
  `octo-ai-services` `McpTokenIssuer` and `octo-cli` (via `AuthenticatorOptions.TenantId`, guarded
  in `LogInClientCredentialsCommand`) all send `acr_values`. The only callers that omit it are the
  `octo-sdk` sample `Sdk.GraphQlCodeGenSample` (never assigns `AuthenticatorOptions.TenantId`) and
  the `curl` recipe of an energy demo repository — both use ordinary,
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
  warning whenever a mirroring source obtains a system-tenant token, and **system-route authorization must not treat
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

## Per-Tenant Mirror Secrets — step 1 of 2, gap still open

The ambiguity refusal closed the *silent* half of the mirroring escalation. This is the start of the *explicit*
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
  credential handed out. Same trap as the service-account bus consumer's preserve branch.
- 🔴 **`CreateMirrorClient` now deep-copies `ClientSecrets`.** It previously assigned the parent's list
  *by reference*; appending an own secret to it would make `SyncMirrorsForClientAsync` hand child *N*
  the secrets of children 1..*N-1* — a cumulative credential leak between sibling tenants.
- ⚠️ **The inherited parent secret is still accepted, so the escalation is still open.** The caller
  inventory (whole `dev` + `main` checkout) found live fleet credentials that authenticate with the
  parent secret against child tenants and would break instantly: `ci-deploy` / `ci-deploy-{cluster}`
  (workload-deployment pipeline, one Vault pair per cluster — its own comments state the intent),
  `octo-ai-adapter` (`McpTokenIssuer`, one Helm/Vault pair per cluster) and `claude-agent`. None of
  them appears in any git-tracked config; all three are created with
  `octo-cli -c AddClientCredentialsClient … -apic`. **system-route authorization must keep treating
  `tenant_id == systemTenant` on a client-credentials token as unproven** until the follow-up step
  removes the inherited secret.
- The migration sequence, and the open decision between "own secrets only" and "forbid confidential
  mirroring entirely" (the counter-model being the per-tenant `octo-pipeline-sa-*` accounts of
  the service-account clients), are in `docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md`.

Tests: `ClientMirrorOwnSecretTests` (own secret ≠ parent's, public client untouched, preservation on
both rewrite paths, sibling-leak regression, no secret in the **rendered** log output via
`CapturingLogger<T>`, and an explicit assertion that the inherited secret is *still* present — that
test must be inverted when the gap closes), `ClientMirrorSecretsTests` (hash convention pinned against
published SHA-256 digests; a divergence from `OctoSecretHasher` would store rotated secrets in a
shape the token endpoint can never match), `ClientMirrorControllerTests` (endpoint branching plus
`ToString()` redaction on both secret-carrying types) and
`ClientMirrorProvisioningIntegrationTests` (the same over real MongoDB, plus rotation retiring the
superseded value).

## Client Mirroring Is Intentional — and What It Does Not Prove

Worth stating plainly, because the tenant-stamping, ambiguity-refusal and mirror-secret sections above are all about the
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
- **Roles are mirrored only by allow-list.** `CreateMirrorClient` copies `RtClient` *attributes* only,
  and never `MirrorRoleNames`. A mirror holds no role in the child tenant unless its original lists the
  role in `Client.MirrorRoleNames` (System.Identity 3.9.0, set with `Client.SetMirrorRoles-1`; empty by
  default) or somebody grants it *there* by hand (`Client.AddRole-1` in the child). Group memberships
  are never mirrored. **The roles a mirror holds in the addressed tenant are the boundary downwards**,
  and the list is the one place that widens it for every child tenant at once: see "Roles mirrored by
  allow-list" below.
- 🔴 **While the inherited secret is accepted, a `tenant_id` claim on a client-credentials token does
  not prove which tenant the caller came from** — only which tenant the token was issued *for*.
  Whoever holds a child's credentials holds the parent's. **Do not authorize on it** (this is exactly
  what blocks **system-route authorization**: `tenant_id == systemTenant` is not proof of provenance). Authorization for
  service tokens belongs on **roles assigned to the client in the addressed tenant** — those are
  per-tenant by construction, and they answer the question authorization actually asks. Whether the
  inherited secret is still in use is now measured (**mirror-secret telemetry**, below).

## Which Mirror Secret Matched — step 3 of the migration

Step 4 (drop the inherited secret) cannot be justified without knowing that nobody uses it, and before
the secrets were split there was nothing to tell apart. `MirrorSecretUsageTelemetry`
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
- **Log-only on purpose.** The ambiguity refusal next door persists an audit entry via
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

## Roles mirrored by allow-list (System.Identity 3.9.0, AB#9923)

A confidential platform client that identity mirrors into every child tenant (the `ci-deploy-{cluster}` clients of the CD,
AB#9562) needs a role in each tenant it deploys to. Instead of a grant per tenant (and again for every new tenant), the
original client carries the list of roles its mirrors get.

**Model.** `Client.MirrorRoleNames` (StringArray, optional, `TenantOwned`, default empty) on the original; the tracking row
`ClientMirror` (one per client and child tenant, in the parent tenant) records `ManagedRoleNames` (the role assignments identity
made or adopted on that mirror), `DeclinedRoleNames` (listed roles the child tenant's administrator removed) and
`ManagedMirrorRtId` (the mirror both lists refer to). Set with `Client.SetMirrorRoles-1` (`roleNames`, `dryRun`; rules and errors
in `docs/identity-methods.md`). `CreateMirrorClient` never copies the list: a mirror is never a source.

**Who may set it.** Scope `octo_api` and `TenantManagement` in the tenant of the original; the caller must hold every built-in role
it adds (role change guard) and a client cannot extend its own list. **Deny-list:** `TenantManagement`, `UserManagement`,
`SecretManagement`, `AdminPanelManagement` and `AiBudgetAdmin` are never mirrored (`MIRROR_ROLE_NOT_ALLOWED`); the reconciliation
drops them too, should a list ever reach the store another way. **Only confidential client-credentials clients**
(`RequireClientSecret` and grant `client_credentials`): a public client (Studio, octo-cli) never gets roles through its mirrors,
neither by the method (`CLIENT_NOT_CONFIDENTIAL`) nor by the reconciliation.

**Where it is applied.** After every mirror convergence, in the server's system context (`ClientMirrorRoleReconciler`,
`ClientMirrorRoles.cs`): the tenant setup (creation, restart, `ReRunTenantSetup`, also for nested tenants: the mirror source is
the system tenant for every tenant at any depth, `DefaultConfigurationCreatorService`), `Client.ProvisionMirrorInTenant-1`,
`Client.ProvisionMirrors-1`, the mirror sync after an update of the original, the periodic `ClientMirrorReconciliationJob` (the
backstop) and `Client.SetMirrorRoles-1` itself. A scratch tenant of another parent applies that parent's list. The mirror secret
rotation does not touch roles.

**Per mirror** (`MirrorRolePlan.Compute`, role names compared case-insensitively):

| Case | What identity does |
|---|---|
| Listed role, not on the mirror | assigns it, records it as managed |
| Listed role the mirror holds already (e.g. the hand grant of AB#9562) | **adopts** it: managed from now on, no second edge |
| Managed role the list no longer names (also: list cleared) | removes it |
| Role on the mirror the list does not name and identity does not manage | leaves it alone, reports it as `handSet` |
| Listed role that does not exist in the child tenant | WARN, `roleMissing`, provisioning goes on; assigned on the first pass after it exists |
| Managed listed role that is gone from the **same** mirror (rtId unchanged) | the tenant removed it: recorded as **declined**, WARN, audit event, never assigned again on that mirror |
| Declined role the tenant assigns again by hand | no longer declined, adopted |
| Mirror re-created (another rtId: deleted and inserted again by the reconciliation or a restore) | starts over: the recorded roles no longer describe it, so the listed roles are granted again and earlier declines are dropped |

**Only tracked mirrors.** A role goes only to the child's client that carries this parent's mirror marker and has a tracking row of
this parent. A client of the same id without them - a stray copy restored from another cluster's dump (AB#8533), or the child's
own client - never gets a role.

**Tenant owner (customer tenants).** No consent up front (decided by Gerald 2026-11-27: a parent administrator may already grant the
same role by hand); the tenant keeps the last word through the decline rule above. Every grant, removal, adoption and decline is an
information event in the child tenant's event log and in the system event log (`IEventRepository`, the pattern of the scratch
creator grant, AB#7192), with client id, tenant ids and role names only.

**Failures.** A failed write is logged as ERROR (client id, tenant, never a secret) and never fails a tenant setup, a provisioning
call or a reconciliation pass; the next pass retries it. The role edges are written before the tracking row, and the row with the
version it was read with: an edge whose row write failed is adopted by the next pass, a removed edge whose row write failed is
forgotten by it. Concurrent passes of two replicas: the second row write fails on the version, the next pass converges.

**Changing or clearing the list** reconciles every tracked mirror at once: added roles are assigned, removed roles are taken away
only where identity manages them (adopted hand grants count as managed), hand-set roles stay and are listed. Switching
`AutoProvisionInChildTenants` off leaves the mirrors and their roles as they are; a removed mirror or a deleted tenant takes its role
edges with it.

⚠️ **Open risk: the inherited parent secret.** A mirror still accepts the parent's secret in every child tenant ("Per-Tenant Mirror
Secrets" above, step 4 open). With a mirrored role, **one leaked secret of such a client holds that role in every tenant of the
cluster, also in tenants created later.** The deny-list, confidential clients only and a narrow deploy role (AB#9894) instead of
`CommunicationManagement` limit the blast radius; per-mirror own secrets only (`docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md`) are the
real fix. Keep lists short and specific.

**Cross-tenant.** A mirror's token carries `tenant_id` = the child and its roles are resolved there; the method gateway refuses a
token in another tenant (AB#8711). The original's system-tenant token gains nothing in a child, and a mirror's token of tenant A gains
nothing in a tenant B whose mirror does not hold the role.

Operator commands (preview, set, read) follow in octo-cli and the MCP server (AB#9926); the per-cluster adoption of the existing hand
grants with a dry-run table per cluster in AB#9927.

Tests: `ClientMirrorRolePlanTests` (rules and plan), `ClientMirrorRolesIntegrationTests` (real MongoDB: new child, nested grandchild
through the tenant setup, missing role, list change with a hand-set role, adoption and clearing, dry run, declined and re-created
mirror, stray copy, public client, failing write retried, rotation and no secret in the rendered log) and
`ClientSetMirrorRolesMethodTests` (real host: caller rule, deny-list, public client, role not held, self-grant, child administrator,
mirror as target, dry run, audit, and real client-credentials tokens per tenant through the method authorization).
