---
description: Cross-tenant sign-in, shadow users, token exchange, sibling grants, delegation, tenant probe guard
applies_to: *CrossTenant*.cs, **/{CrossTenantAudit,SourceTenantGrants,ShadowUserCleanup}/**, {TenantProbeGuard*,AllowedTenants*,*IdentityResolver,*Processor}.cs
---

# Cross-tenant authentication and delegation

## Cross-Tenant Authentication

The service supports hierarchical cross-tenant authentication where parent-tenant users can log in to child tenants:

- **`RtOctoTenantIdentityProvider`**: CK type linking a child tenant to a parent tenant for auth delegation
- **`RtExternalTenantUserMapping`**: CK type mapping a parent-tenant user to roles in the child tenant
- **`CrossTenantAuthenticationService`**: Walks the tenant hierarchy to validate credentials against parent tenant databases
- **`ExternalTenantUserMappingStore`**: Persistence for cross-tenant user role mappings. A mapping is unique per (`SourceTenantId`, `SourceUserId`) in a tenant, but the database does not enforce it (no unique index on runtime entities). `FindBySourceUserAsync` (login, `IsExplicitlyProvisionedAsync`, token exchange) therefore never throws on duplicates: it returns the oldest mapping (smallest `RtId`) and logs a WARN naming all ids (`ExternalTenantUserMappingLookup`). The store is scoped and holds a `DuplicateWarningGate`: the several lookups of one login or exchange log the WARN once per duplicate set (repeats at Debug). The effective roles (`GroupRoleResolver`, via `FindBySourceUserNamesAsync`) are the union over all matching mappings, not only the oldest. Both create paths (`POST adminProvisioning/{targetTenantId}`, `POST ExternalTenantUserMappings`) answer `409 application/problem+json` with `code: ExternalTenantUserMappingAlreadyExists` and `existingMappingId` when the pair exists; to change roles, update the existing mapping (`PUT ExternalTenantUserMappings/{id}`). `provisionCurrentUser` stays idempotent. Existing duplicates are not migrated; delete the extra rows (`DeleteAdminProvisioningMapping`).
- **`ExternalTenantUserMappingsController`**: System API CRUD for managing mappings (per-tenant, requires `allowed_tenants`)
- **Source user lookup**: `POST ExternalTenantUserMappings/sourceUserLookup` finds one user of another tenant by
  exact user name / e-mail for a grant (`docs/CONCEPT-SIBLING-TENANT-GRANTS.md`). Code in
  `IdentityServerPersistence/Services/SourceTenantGrants/`: `SourceUserLookupService` (registry ancestry via
  `ICrossTenantAncestryGuard`, never `SearchUsersInTenantAsync`), `ISourceTenantGrantPolicy` (default
  `DenyNonAncestorsSourceTenantGrantPolicy` earlier), `ISourceUserLookupAuditSink` (no-op earlier),
  `SourceUserLookupRateLimiter` (`Identity:SourceUserLookupRateLimit`). 🔴 Every negative case returns the one constant
  `404 SourceUserNotFound` and runs the same queries (no early return, decoy query in T when S is unknown); never add a
  reason to the answer and never log the identifier. The HTTP test host replaces the policy with
  `Helpers/TestSourceTenantGrantPolicy` (permits only the pairs a test arranges, default otherwise); tests
  `SourceUserLookupTests`, `SourceUserLookupServiceIntegrationTests`. The sign-in block rule lives in
  `SourceUserSignInBlock` and is shared with `CrossTenantAuthenticationService`.
- **`AdminProvisioningController`**: Cross-tenant provisioning via system tenant (see below)

**Cross-tenant auto-login** (token-based, no credential re-entry):
- `POST /{parentTenantId}/api/auth/cross-tenant-token` — Generates a DataProtection-encrypted token (60s expiry) for the authenticated parent-tenant user
- `POST /{childTenantId}/api/auth/cross-tenant-login` — Exchanges the token for a session in the child tenant
- The Angular login component automatically attempts token-based auto-login when clicking "LOGIN VIA {parent}". If no parent session exists, it redirects to the parent tenant's login page (where all auth methods are available); after authentication there, it redirects back with a `crossTenantAutoLogin` query param to auto-complete the token exchange

**Cross-tenant role sync**: When a cross-tenant user logs in (via `FindOrCreateCrossTenantUserAsync`), `SyncMappedRolesAsync` resolves mapped role IDs to role names by querying the tenant repository directly (via `IMultiTenancyResolverService.GetTenantRepository()`), then calls `UserManager.AddToRoleAsync` with the role **name** (not ID). This runs on every login, ensuring existing users get role updates. Important: `RoleManager<RtRole>` must NOT be used for this — it may resolve to the wrong tenant context during cross-tenant login. The tenant repository approach reads from `HttpContext.Items["tenantRepository"]` which is correctly set by the inline middleware.

**Second factor across tenant boundaries:** every cross-tenant entry point (password login
fallback, cross-tenant-token/-login, tenant-switch, token exchange; the device approval no longer crosses tenants) refuses a source user
with 2FA (own or anywhere in its `xt_` chain: `CrossTenantAuthResult.SourceUserRequiresSecondFactor`) unless the proof
carries `amr=mfa` (`SecondFactorEvidence`). The password login answers `requiresTwoFactor` and completes through the
normal `login-2fa`/`login-2fa-email`/`login-recovery` endpoints against the SOURCE user (`ICrossTenantSecondFactorVerifier`,
source lockout counts). Sessions/tokens issued on evidence carry `amr=mfa` on (exchange: `["token_exchange","mfa"]`);
device tokens now keep the session's `amr` instead of a forced `pwd`. `tenant-switch` derives the source identity from
the caller's own chain (never the request body). Details: `docs/authentication.md` § Second Factor Across
Tenant Boundaries; tests `CrossTenantSecondFactorTests` (HTTP, real child tenant). The repository has no CHANGELOG file;
this paragraph and that section are the change record (Security). The security-stamp revalidation (every 30 min) used to drop
`amr=mfa` from the session; `SessionClaimPreservation` (`OnRefreshingPrincipal`) keeps `amr`/`idp`/`sid`. The refresh
grant already kept `amr`. 🔴 Tests that need the revalidation advance `CustomWebApplicationFactory.SecurityStampClock`
(reset it in `finally`); tests: `SecondFactorEvidenceRefreshTests`.

**Sign-in attempts are counted atomically and rate-limited:** `OctoUserManager` (the registered
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

**Cross-tenant hardening:** the challenge cookie is single-use (nonce + `ICrossTenantChallengeReplayGuard`,
voided on completion, logout and local sign-in), gaps in the `xt_` chain require the second factor, and stored `amr` user
claims are never returned by `OctoUserStore.GetClaimsAsync`. The unreachable cross-tenant provisioning branch of
`DeviceVerificationController` is gone — a session whose subject is not a user of the device code's tenant gets
`access_denied`; the session's `amr` is still passed on to the device token.

**Locked-out or disabled source users:** `ValidateCrossTenantAccessAsync` (every crossing) also refuses a
locked-out source user and one the `IdentityOptions.SignIn` rules refuse ("disabled"; no separate flag on `RtUser`),
including every tier of its `xt_` chain.

**Cross-tenant token exchange (RFC 8693)** — the non-interactive
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
  security linchpin as before (dual-candidate source selection is
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
- **octo-cli exchanges too (blueprint 1.8.0):** `octo-cli` (660…31, public, secretless)
  carries the token-exchange grant next to device_code, so an operator's root-tenant token can be
  exchanged for a child-tenant token (`acr_values=tenant:X`) instead of being sent to a foreign
  tenant route. The client reaches the child tenant twice: the blueprint seeds `octo-cli` in every
  tenant, and the `AutoProvisionInChildTenants` mirror copies the parent's `AllowedGrantTypes`
  (`CreateMirrorClient`), converging on every identity start (for tenants that already had the client see
  *Rollout* below: the seed cannot change a tenant-owned value). Pinned by
  `OctoCliClientTokenExchangeSeedTests`.
- **Ancestry is not authority (decision Gerald 2026-10-17).** The exchange only checks that
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
  `unauthorized_client`. A refused exchange leaves nothing in B: no mapping, no shadow
  user; an empty mapping that already exists grants nothing (`Exchange_RepeatedAfterEmptyMapping…`).
  Exchanged tokens never carry a refresh token. Tests: `TenantExchangeIntegrationTests`
  (`Exchange_AncestorUserWithoutProvisioning…`, `…ProvisionedOperator…`, `…DirectRoleGrant…`,
  `…NonAncestor…`).
- **Rollout (existing tenants):** the blueprint bump alone does NOT reach a tenant that already
  has the client. `Client.AllowedGrantTypes` is `TenantOwned`, so the seed import (Upsert) keeps the
  stored value; the apply logs `mode=Initial added=N updated=0` regardless (Upsert is counted as "added").
  Verified on test-2 (octo-cli r3.5.27: exchange refused with `unauthorized_client`). Hence
  `OctoCliTokenExchangeGrant` (`Services/ClientGrants`): a one-time, additive step in
  `DefaultConfigurationCreatorService.SetupTenantAsync` (every identity start, tenant create/update) that
  appends the token-exchange URN to `AllowedGrantTypes` of every client with `ClientId == "octo-cli"` and
  touches nothing else. It runs AFTER the blueprint apply and AFTER the child-tenant mirror provisioning,
  because that mirror copies the parent's grants over a mirrored `octo-cli` — in a child whose parent is not
  fixed yet this step must have the last word. One log line per tenant: `… octo-cli token-exchange
  grant: tenant=… result=Added|AlreadyPresent|ClientMissing|AlreadyDone clientsUpdated=n` (no secrets).
  Run-once marker (tenant configuration key `OctoCliTokenExchangeGrant`, written only when an `octo-cli`
  client was found): a grant an administrator removes later is not re-added by this step (a mirror copy from
  the parent still can). Tenants without the client are retried on each setup. No blueprint bump and no
  manual database edit needed; after deploying the identity image, check the start-up log lines per tenant
  (counts show which tenants were touched) and verify with `octo-cli -c GetClient -id octo-cli`.
  Before the CLI relies on the exchange, operators must be provisioned in each child tenant they
  operate (`ProvisionCurrentUser -ttid`). Tests: `OctoCliTokenExchangeGrantIntegrationTests` (real MongoDB),
  `OctoCliClientTokenExchangeSeedTests`.
- **Only access tokens are subject tokens:** `TenantExchangeProcessor` and `OnBehalfOfProcessor` validate the
  `subject_token` with `SubjectTokenValidation.ForAccessToken` (`typ` must be `at+jwt`), so an id_token with user claims
  is refused. OpenIddict already refuses it for the RFC 8693 grant; on-behalf-of (custom flow) relies on this check alone.
  Test tokens minted with `JsonWebTokenHandler` need `TokenType = "at+jwt"`.
- **v1 issues no exchanged refresh token** (short-lived B tokens, re-exchanged from
  the still-valid A token). See `docs/CONCEPT-CROSS-TENANT-TOKEN-EXCHANGE.md` and
  `docs/authentication.md` § Cross-Tenant Token Exchange. Coverage:
  `tests/IdentityServices.IntegrationTests/Persistence/TenantExchangeIntegrationTests.cs`
  (privilege-escalation regression: resolved roles == B subset, not A's full set).

## Delegation / On-Behalf-Of Grant

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
  Distribution Event Hub" in `docs/client-credentials.md`.

# One broken tenant database must not slow every token request

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

**A RUNNING tenant heals itself (round 2).** When a probe fails with an authentication error (MongoDB 18/13, also
the pooled-connection case) or times out, the guard asks `TenantDatabaseUserHealer` (octo-common-services,
rate-limited to once a minute per tenant) to re-create the tenant's MongoDB user **in the background** and closes the
circuit as soon as the user was missing and is back, so no restart is needed. The healer needs the admin MongoDB
connection; a service without it just logs a warning. A token request that hits an unreachable tenant database is no
longer an unhandled 500: `TokenEndpointDatabaseFailureMiddleware` (before `UseOidcTenantResolution`, so the tenant lookup is covered; `/connect/token`
only) answers `503 temporarily_unavailable` with `error_description` naming the tenant and the cause, and octo-sdk maps it
to `TenantTokenDenialCause.TenantUnavailable`, so octo-cli shows the reason instead of "could not be reached". Tests:
`TenantProbeGuardTests` (healing), `TokenEndpointDatabaseFailureMiddlewareTests`.

**A wrong secret during the healing is 401 or 503, never 500.**
`ClientMirrorReconciliationTests.WrongSecret_WhileTheChildDatabaseUserIsHealed_IsNever500_AndEndsAs401` drops the user of a
child tenant's database, drops the token host's cached clients and asks for a token with a wrong secret until it is 401:
`503 temporarily_unavailable` while the database cannot be read, then 401, then the right secret works again. The 500s of
identity build 65204 (r3.5.61) were not this path: the integration test process ran out of memory because no MongoDB
repository client was ever released (every test host left its clusters, monitor threads and sockets behind; fixed in
octo-construction-kit-engine-mongodb, see its CLAUDE.md "Repository clients are released, not only dropped"). A 5xx answer
in that class prints the response body to the test output.
