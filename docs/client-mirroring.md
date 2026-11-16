---
description: tenant_id on client-credentials tokens, ambiguous tenant binding, per-tenant mirror secrets and which mirror matched
applies_to: ClientMirror*.cs, src/IdentityServices/Services/**
---

# Tenant binding of client-credentials tokens and client mirroring

## `tenant_id` on Client-Credentials Tokens (AB#5032)

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

## Ambiguous Tenant Binding on `client_credentials` (AB#5058)

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

## Per-Tenant Mirror Secrets (AB#5061) — step 1 of 2, gap still open

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

## Client Mirroring Is Intentional — and What It Does Not Prove

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

## Which Mirror Secret Matched (AB#5065) — step 3 of the migration

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
