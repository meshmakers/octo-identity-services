# Per-Tenant Mirror Secrets (AB#5061)

> **Status:** step 1 (AB#5061) and the telemetry of step 3 (AB#5065) implemented.
> ⚠️ **The escalation is still open** — see
> [§6 When the gap actually closes](#6-when-the-gap-actually-closes).

## 1. The problem

`AutoProvisionInChildTenants` mirrors a parent-tenant client into every child tenant.
`ClientMirrorProvisioningService.CreateMirrorClient` copies the record verbatim, **including
`ClientSecrets`**. For a confidential client that means one `ClientId`/secret pair is valid on the
whole instance.

The consequence is an **upward** privilege escalation:

- Whoever legitimately holds a *child* tenant's mirror credentials thereby also holds the *parent's*.
- They can request a **system-tenant** token explicitly with `acr_values=tenant:{systemTenant}`.
- No check at the token endpoint can tell that caller apart from the real parent, because it is
  byte-for-byte the same credential.

AB#5058 closed the *silent* variant — omitting `acr_values` and being handed a system-tenant token
for free — by refusing to guess when a client id is mirrored. It could not close the *explicit*
variant. That is why **a `tenant_id == systemTenant` claim on a client-credentials token is not proof
of provenance**, and why the system-route hardening (AB#5055) is blocked.

## 2. Caller inventory

Checked across the whole `dev` and `main` checkout, not assumed.

### 2.1 Mirrored clients that ship with the product — all public

`System.Identity.Bootstrap/seed-data/entities.yaml` is the **only** file in either checkout that sets
the flag declaratively. All six clients are `RequireClientSecret: false` with `Secrets: []`:

| ClientId | Grant |
|---|---|
| `octo-data-refinery-studio` | `authorization_code` + PKCE |
| `octo-cli` | `device_code` |
| `octo-idenityServices-swagger` | `authorization_code` + PKCE |
| `octo-mcpServices-swagger` | `authorization_code` + PKCE |
| `octo-mcpServices-device` | `device_code` + token-exchange |
| `octo-platformServices-swagger` | `authorization_code` + PKCE |

Dynamically registered clients (`octo-dcr-*`) are flagged too and are public by hard gate. **None of
these can obtain a `client_credentials` token at all**, so none of them is affected by this work item
— which is also why the fix must not simply forbid mirroring.

### 2.2 Confidential mirrored clients — created imperatively, live in Vault

These exist in **no** git-tracked configuration. They are created with
`octo-cli -c AddClientCredentialsClient … -apic` and their secrets live in Vault or local files:

| ClientId | Who uses it | Secret source | Sends `acr_values`? |
|---|---|---|---|
| `ci-deploy` / `ci-deploy-{cluster}` | workload-deployment pipeline (`octo-mesh-deployment/pipelines/templates/deploy-workload.yml`) | Vault `secret/meshmakers/{cluster}/octomesh` → `ci_deploy_client_id` / `ci_deploy_client_secret`, **one pair per cluster** | yes, per child tenant |
| `octo-ai-adapter` | `octo-ai-services` `McpTokenIssuer` | Vault → Helm secret `{release}-backend`, **one pair per cluster** | yes, per session tenant |
| `claude-agent` | agent automation against temporary tenants | `~/.octo-cli/claude-agent.secret` | yes, per tenant |

🔴 **All three deliberately use parent (`octosystem`) credentials against child tenants.** The deploy
pipeline says so in its own comments: *"log in fresh (mirrored client from Epic 3054 Phase 1 means
same ClientId/Secret works in every sub-tenant)"*. These are exactly the callers a naive fix breaks,
and they are load-bearing: every workload rollout on every cluster goes through `ci-deploy`.

> Note: the documented registration command for `octo-ai-adapter` (`base/values-ai.yaml`,
> `setup-vault-octomesh-secrets.yml`) does **not** carry `-apic`, yet the issuer addresses arbitrary
> tenants — so the client was either flagged manually or the documentation is incomplete. **This must
> be confirmed per cluster before step 2.**

### 2.3 The counter-model that already works

`PipelineServiceAccountProvisioningService` (octo-communication-controller-services) provisions
`octo-pipeline-sa-{adapterRtId}` — **one client per tenant and adapter, each with its own generated
secret**, delivered over the bus and stored in that tenant's own
`RtServiceAccountConfiguration.ClientSecret`. That is the shape a machine identity should have, and
it is the migration target for §2.2.

## 3. Why "just don't mirror confidential clients" was rejected

It is the cleanest rule and it closes the hole completely — but it breaks all three callers in §2.2
on the next service start, i.e. every workload deployment on every cluster. Rejected as a step-1
change; it remains the plausible **end state** once §2.2 has migrated (see §6, option B).

## 4. Why "generate a per-mirror secret" needs a distribution answer first

Secrets are stored **SHA-256 hashed and are unrecoverable**. Mirrors are materialized by a background
provisioning loop at tenant-creation and on every service start — there is no one present to hand a
plaintext to. An auto-generated secret that is never revealed is a credential nobody can use.

So the generation half is trivial and the **distribution half is the whole design question**. Two
options were considered:

| Option | Verdict |
|---|---|
| Store the plaintext recoverably (DataProtection-encrypted) and expose a read endpoint | Rejected for now. It introduces a new class of *reversible* stored credential into Identity. `RtServiceAccountConfiguration.ClientSecret` sets a precedent, but replicating it here needs an explicit decision, and it also needs a CK schema bump on `System.Identity` — which cascades a version bump through every dependent construction kit. |
| **Issue on demand, return once, never store the plaintext** | **Chosen.** No recoverable storage, no schema change, and rotation and issuance are the same operation. |

The direction of the resulting trust relationship is the point: the value is handed to a caller who
**already holds parent-tenant management rights**. Parent → child is legitimate delegation; the
escalation being removed is the opposite direction, child → parent.

## 5. What is implemented (step 1)

Additive and non-breaking by construction.

1. **Every mirror of a confidential parent gets its own generated secret**, tagged
   `Description = "octo:mirror-own-secret"` (`ClientMirrorSecrets.OwnSecretDescription`). Possession
   of it proves exactly one tenant. Public parents are untouched — they keep no secret at all.
2. **The own secret is preserved** across re-provisioning and across parent-side secret rotation.
   🔴 Load-bearing: both paths rewrite the mirror from the *parent's* state, so without preservation
   every service restart would silently invalidate every per-tenant credential issued so far. This is
   the same trap already documented for the AB#5027 bus consumer.
3. **`POST {parentTenant}/v1/clients/{clientId}/mirrors/{childTenantId}/secret`** issues a fresh
   secret for one mirror and returns it **once**. Calling it again rotates and retires the previous
   one. Requires `IdentityApiFullAccess` in the parent tenant. Both the response DTO and the service
   result override `ToString()` so the value cannot leak through interpolation.
4. **The inherited parent secret is still accepted**, unchanged, so §2.2 keeps working.
5. A **defensive copy** of the parent's secret list was added on the way. Previously the mirror shared
   the parent's list *by reference*; appending an own secret to it would have made the sync loop hand
   child *N* the secrets of children 1..*N-1* — a cumulative credential leak between sibling tenants.
   Pinned by `SyncAcrossTwoChildren_DoesNotLeakOneChildsOwnSecretIntoTheOther`.

Secret material is never logged; `Provisioning_NeverWritesSecretMaterialToTheLog` asserts that against
the *rendered* log output rather than against format strings.

## 6. When the gap actually closes

⚠️ **Not yet.** As long as a mirror accepts the inherited parent secret, a child credential is still
a parent credential, and **AB#5055 must continue to treat `tenant_id == systemTenant` on a
client-credentials token as unproven**. Step 1 makes the fix *possible* and *adoptable*; it does not
make it *effective*.

The gap closes at the moment the inherited secret is removed from mirrors. Sequence:

| # | Step | Owner | Done when |
|---|---|---|---|
| 1 | Ship step 1. Confirm per cluster which confidential clients are actually flagged — in particular whether `octo-ai-adapter` is (§2.2 note). | identity | inventory per cluster written down |
| 2 | For each caller in §2.2, obtain a per-tenant secret via the rotation endpoint and store it per tenant: CI/CD in Vault (or rotate-and-use inside the pipeline run, which needs no Vault change), `octo-ai-adapter` per tenant, `claude-agent` locally. Needs an `octo-cli` command wrapping the endpoint and a change in `octo-mesh-deployment/pipelines/templates/deploy-workload.yml`. | deployment / AI / CLI | every caller authenticates with a mirror-own secret |
| 3 | Verify no caller uses the inherited secret any more. **Telemetry shipped (AB#5065):** `MirrorSecretUsageTelemetryValidator` decorates Duende's `ISecretsListValidator` and records `secretKind=own` / `secretKind=inherited` with `clientId` and `tenantId` on every successful shared-secret authentication of a mirror. Query per environment: `{namespace="octo", container="identity"} \|= "MirrorSecretUsage" \|= "secretKind=inherited"`. ⚠️ It infers mirror-ness from the *presence* of an own secret, so **row 1's per-cluster inventory is a hard precondition** — a mirror without an own secret produces no record, and a zero count would then mean "not measured", not "not used". | identity | one full release with zero inherited-secret matches, **after** every confidential mirror is confirmed to hold an own secret |
| 4 | **Drop the inherited secret from every mirror.** `InheritedParentSecret_IsStillCopied_SoTheGapIsDocumentedNotClosed` must be inverted — its failure is the signal the gap closed. | identity | mirrors carry only their own secret |
| 5 | Unblock AB#5055. | identity | system-route authorization may trust the system-tenant claim |

**Open decision — the end state.** Two variants, to be chosen before step 4:

- **A. Keep mirroring for confidential clients, with own secrets only.** The mirror stays a
  convenience; the credential becomes tenant-scoped.
- **B. Forbid mirroring confidential clients entirely** and move §2.2 onto per-tenant service
  accounts (§2.3). Structurally simpler — the insecure state becomes unrepresentable — and it makes
  the rotation endpoint of §5.3 unnecessary. Costs more migration work in the deployment pipeline.

B is the stronger end state; A is reachable sooner. This is the decision the work item leaves open.

## 7. Related

- `docs/authentication.md` § *Ambiguous Tenant Binding on `client_credentials`* — AB#5058, the silent
  half of this escalation.
- `CLAUDE.md` § *Service-Account Clients over the Distribution Event Hub (AB#5027)* — the per-tenant
  secret provisioning that already works, and the "preserve the existing secret" trap that recurs here.
- `docs/authentication.md` § *Which Mirror Secret Was Used? (AB#5065)* — the step-3 telemetry, its
  Loki query and its blind spot.
- `docs/authentication.md` § *Client Mirroring — What It Is For, and What a Mirrored Credential
  Proves* — why mirroring is intentional, why roles are the real boundary downwards, and why the
  tenant claim on a service token must not be authorized on until step 4 lands.
