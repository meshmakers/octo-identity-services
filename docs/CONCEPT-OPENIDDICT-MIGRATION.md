# Concept: Migrating from Duende IdentityServer to OpenIddict

**Status:** Implemented on feature branch (2026-09-01) — phases 1–6 complete, cutover (AB#4998) pending · **Epic:** AB#4989 · **Related:** AB#4988 (license renewal), work items AB#4990–AB#4998

## 1. Motivation

Our Duende IdentityServer license expired on 2026-08-30 (AB#4988) and renewal is uncertain. The
June 2026 Duende license agreement grants no perpetual use right: after termination we must cease
use (§10.C), with audit rights surviving 18 months. The tier we would need (Standard: server-side
sessions + device flow, plus redistribution rights for customer deployments) starts at $12,500/yr.
Duende v8 keeps running on an expired license (log warnings only, no hard stop), which gives us a
bridge window — but it is a bridge, not a destination.

**Decision:** migrate `octo-identity-services` from Duende IdentityServer 8.0.6 to
**OpenIddict 7.x** (Apache 2.0). The wire protocol (OAuth2/OIDC) is identical, so *all consumers —
SPAs, backend services, adapters, octo-cli, MCP clients — keep working unchanged* as long as we
preserve the discovery document, endpoint paths, token shape, and claims.

Why OpenIddict and not the alternatives: Keycloak (JVM sidecar, no in-process embedding, Java SPIs
for our tenant model), Zitadel (AGPL since 2025 — unacceptable for redistribution), Authentik
(Python SSO portal, wrong shape), Ory Hydra (headless token engine, extra service, no MongoDB).
Only OpenIddict preserves our model: same ASP.NET Core host, same MongoDB/CK persistence, same
ASP.NET Identity user store, per-tenant issuer resolution in our own middleware, no client-ID
metering, no redistribution addendum. Since 7.0, token exchange (RFC 8693) — today our custom
extension grant — is a first-class flow.

## 2. Do we need a migration? (Summary)

**No data migration is required.** A one-time **additive CK schema extension** (new entity types
for OpenIddict's authorization/token model) and an **operational cutover with a bounded re-login
window** are sufficient. In detail:

| Data | Storage today | Action | Rationale |
|---|---|---|---|
| Clients (`RtClient`), API resources/scopes, identity resources | CK/MongoDB, per tenant | **None** — keep as-is | Duende types are only in-memory AutoMapper projections. The new OpenIddict application/scope stores project the *same* Rt* entities; the grant-type→permissions transform happens in the mapping layer at read time, not in the data. |
| Users, passwords, roles, groups, external mappings | ASP.NET Identity over CK | **None** | Not Duende-coupled at all. |
| DataProtection key ring (`RtDataProtectionKey`) | System tenant DB | **None** — keep application name `OctoIdentityServices` | Cross-tenant tokens, cookie encryption, and the QR/e-mail flows keep working across the cutover. |
| Signing key (PKCS#12 via `SigningCredentialService`) | File/secret | **None** — register the same certificate with OpenIddict | JWKS stays identical ⇒ **outstanding access tokens remain valid** across the cutover; resource services need no change and no restart. |
| Published CK model (`System.Identity-2.x`) | Catalogs | Additive model bump | New types added; existing attributes untouched (Duende-derived attribute descriptions cleaned up editorially in the same rev). |
| Persisted grants (`RtPersistedGrant`): refresh tokens, device codes, authorization codes, consents | System tenant DB, Duende-proprietary serialized `Data` blob | **Not migrated — deliberately abandoned at cutover** | The blobs are Duende's internal serialization format; no converter exists and writing one would mean reimplementing Duende internals for a one-shot gain. See impact analysis below. |
| Server-side sessions (`RtServerSideSession`) | Per-tenant DB, Duende-serialized ticket | **Not migrated — sessions end at cutover** | Ticket format is Duende's session serializer. Users re-authenticate once. |

### Cutover impact analysis (what the abandoned grants actually cost)

- **Access tokens (JWT):** unaffected. All clients use `AccessTokenType = Jwt` (verified: seeds,
  DCR, `ClientsController`, mirror provisioning — no reference tokens anywhere). Same signing
  cert + issuer ⇒ tokens validate before and after.
- **`client_credentials` service accounts (adapters, CI/CD, mirrors):** unaffected. No persisted
  state; the next token request just succeeds against OpenIddict.
- **Refresh tokens (`offline_access`, 4 seeded clients + DCR clients):** invalidated. Interactive
  users re-authenticate once; background consumers holding refresh tokens re-run their login flow.
- **Server-side sessions / cookies:** invalidated (the ticket store changes). Browser users
  re-log-in once. Combined with refresh-token loss this is **one** re-login event, not two.
- **Consents:** lost, but irrelevant — all first-party clients have `RequireConsent = false`
  (seeds + DCR force it); only genuinely third-party clients would re-consent.
- **Device codes / authorization codes:** ephemeral (minutes); a deploy already invalidates
  in-flight ones today. No impact beyond the deployment moment.
- **Cross-tenant token exchange:** stateless (v1 issues no exchanged refresh tokens); unaffected.

**Conclusion:** the cutover costs one announced re-login for interactive users per cluster.
Attempting to convert grant blobs would cost far more than it saves.

## 3. Current state (inventory)

Duende is confined to this repository (octo-mcp-service and one CK-engine test reference it in
comments only). Coupling surface:

- **Packages:** `Duende.IdentityServer` 8.0.6 (`IdentityServerPersistence`),
  `Duende.IdentityServer.AspNetIdentity` 8.0.6 (`Authentication` — transitive carrier only, no
  code usage).
- **Stores (Duende interfaces over CK/MongoDB):** `ClientStore` (`IClientStore`), `ResourceStore`
  (`IResourceStore`), `PersistentGrantStore` (`IPersistedGrantStore`, centralized in the system
  tenant, tenant id in `Description`), `ServerSideSessionStore` (`IServerSideSessionStore`).
- **Services:** `UserProfileService` (`IProfileService`: `tenant_id`, `home_tenant_id`,
  `allowed_tenants`), `ClientCredentialsRoleTokenValidator` (`ICustomTokenRequestValidator`:
  effective client roles), `TenantExchangeGrantValidator` (`IExtensionGrantValidator`, RFC 8693),
  `CorsPolicyService` (`ICorsPolicyService`), `OctoEventSink` (`IEventSink`),
  `SigningCredentialService` (`ISigningCredentialStore` + `IValidationKeysStore`, static PKCS#12),
  `TokenExchangeEvents` (Duende `Event` subclasses).
- **Interaction layer:** `AuthApiController`, `ConsentApiController`, `DeviceApiController`,
  `GrantsApiController` use `IIdentityServerInteractionService` / `IDeviceFlowInteractionService`
  / `IEventService` / `IdentityServerConstants` cookie scheme names.
- **Middleware coupled to Duende response shapes:** `OidcTenantResolutionMiddleware` (~800 lines:
  authorize 302/303 + form_post capture, PAR JSON body capture, device-authorization body,
  code→tenant and refresh-token→tenant mapping), `TenantLoginRedirectMiddleware`.
- **Already Duende-independent (no gap):** Dynamic Client Registration (custom
  `/connect/register`), dynamic external providers (`DynamicAuthSchemeService`), token cleanup
  (`TokenCleanupHostService`), DataProtection persistence, CORS provider logic, all TenantApi CRUD
  data (CK entities).
- **Duende features we do NOT use:** CIBA, DPoP, mTLS, resource isolation, Duende dynamic
  providers, Duende automatic key management, Duende DCR/Configuration API, reference tokens,
  `ISessionManagementService`.

## 4. Target architecture

### 4.1 Concept mapping

| Duende concept | OpenIddict counterpart |
|---|---|
| `AddIdentityServer()` + options | `AddOpenIddict().AddServer()` + `AddCore()` + `AddValidation()` |
| `IClientStore` / `Client` | `IOpenIddictApplicationStore<RtClient>` (custom store, no `OpenIddict.MongoDb` needed — we project our own entities) |
| `IResourceStore` / `ApiScope`, `ApiResource`, `IdentityResource` | `IOpenIddictScopeStore<RtApiScope>`; audiences/resources resolved in a claims/handler step from `RtApiResource` |
| `IPersistedGrantStore` | `IOpenIddictAuthorizationStore` + `IOpenIddictTokenStore` (new CK types, see 4.2) |
| `IServerSideSessionStore` + `AddServerSideSessions` | Custom `ITicketStore` on the ASP.NET Identity application cookie, persisting to `RtServerSideSession`-successor type (see 4.5) |
| `IProfileService` | Claims handler on `HandleAuthorizationRequestContext`/token generation + **claim destinations** (`SetDestinations`) |
| `IExtensionGrantValidator` (token exchange) | Native: `AllowTokenExchangeFlow()` + custom event handler for the cross-tenant gate |
| `ICustomTokenRequestValidator` | Event handler on the token response generation for `client_credentials` |
| `ICorsPolicyService` | Standard ASP.NET CORS with `IdentityCorsPolicyProvider` (already ours) applied to OpenIddict endpoints |
| `IEventSink` / `IEventService` | Direct calls to our audit log at the interaction sites (we only persist error/failure events today) |
| `ISigningCredentialStore` | `AddSigningCertificate(x509)` with the same PKCS#12; `AddEncryptionCertificate` for a stable key; **`DisableAccessTokenEncryption()`** (mandatory — our APIs validate plain signed JWTs) |
| `IIdentityServerInteractionService` | `HttpContext.GetOpenIddictServerRequest()` + our own return-URL/authorize-context helpers (thin `IOctoInteractionService` façade, see 4.6) |
| `IDeviceFlowInteractionService` | OpenIddict device flow: verification handled by our endpoint accepting the user code and completing the flow |
| `IdentityServerConstants.*CookieAuthenticationScheme` | Our own scheme-name constants (`OctoAuthSchemes`), values chosen to keep `TenantCookieManager` naming stable |

### 4.2 CK schema: new types (additive model bump, e.g. `System.Identity-2.12.0`)

- **`RtOAuthAuthorization`** — subject, client rtId, type (permanent/ad-hoc), status, scopes,
  creation date, **`TenantId` (first-class)**. Replaces the consent/authorization role of
  `RtPersistedGrant`.
- **`RtOAuthToken`** — authorization ref, type (refresh_token/device_code/user_code/…), reference
  id (hashed lookup key), subject, client rtId, status, payload, creation/expiration/redemption
  dates, **`TenantId`**. Indexes on reference id (unique), subject, expiration.
- The `TenantId` attribute replaces today's tenant-in-`Description` workaround in
  `PersistentGrantStore` — the refresh-token→tenant lookup in `OidcTenantResolutionMiddleware`
  becomes a first-class query.
- Storage location stays the **system tenant DB** (same reasoning as today: `/connect/token` has
  no tenant route; keys are globally unique).
- `RtPersistedGrant` and `RtServerSideSession` are kept in the model during the transition
  (readable for diagnostics) and removed in a later major model rev. `TokenCleanupHostService`
  sweeps both old and new types during the transition.

### 4.3 Stores and client-model transform

Custom `IOpenIddictApplicationStore<RtClient>` projects `RtClient` directly:

- `AllowedGrantTypes`/`AllowedScopes`/`RedirectUris`/… → OpenIddict **permissions** set
  (`Permissions.Endpoints.*`, `GrantTypes.*`, `ResponseTypes.*`, `Scopes.*`) computed at read
  time. **No stored data changes**; the transform is one pure function, unit-tested against every
  seeded client shape.
- `RequirePkce` → `Requirements.Features.ProofKeyForCodeExchange`.
- Secret validation: keep our stored hash format (Duende `Secret` = SHA-256/SHA-512 of the
  secret); implement the comparison in the store so **existing client secrets keep working
  unchanged** (OpenIddict lets the store own secret validation; do not adopt its default ASP.NET
  Identity hasher for existing secrets — only optionally for newly created ones).
- Client-mirror upkeep hooks (`SyncMirrorsForClientAsync` etc.) stay in the store exactly as
  today.
- Per-tenant resolution: unchanged — the store reads the tenant repository from
  `HttpContext.Items` (wired by `OidcTenantResolutionMiddleware`).

### 4.4 Flows

- **Authorization code + PKCE, client credentials, refresh tokens:** standard configuration.
  Claims parity is the critical part: reproduce `UserProfileService` (`tenant_id`,
  `home_tenant_id`, `allowed_tenants`, roles) and `ClientCredentialsRoleTokenValidator`
  (unprefixed role claims on `client_credentials` tokens) as claims handlers, and set
  **claim destinations** explicitly (OpenIddict defaults to `sub`-only). `aud` must match today's
  tokens (from `RtApiResource`) — token-diff harness verifies (see §6).
- **Token exchange (RFC 8693):** `AllowTokenExchangeFlow()`. The cross-tenant logic from
  `TenantExchangeGrantValidator` moves into a `HandleTokenRequestContext` handler: validate
  subject token, resolve target tenant B from `acr_values`, fail closed on wiring mismatch,
  `ValidateCrossTenantAccessAsync`, `FindOrCreateCrossTenantUserAsync`, principal with B-shadow
  `sub`. Security property preserved: **the exchanged token is minted on the B-shadow subject**,
  so tenant-B roles resolve automatically and A's roles never leak. v1 semantics kept: no
  exchanged refresh token.
- **Device flow:** `AllowDeviceAuthorizationFlow()`. `DeviceApiController` re-implemented against
  OpenIddict (accept user code, bind to authenticated user, complete/deny). Verification URI
  options keep pointing to the Angular SPA (`/{tenantId}/device`).
- **DCR:** unchanged (`DynamicClientRegistrationService` + `MapPost("/connect/register")`).
  Re-attach the `registration_endpoint` via OpenIddict's discovery customization handler.
  `DcrDefaultScopeMiddleware` is pure ASP.NET middleware and keeps working.
- **PAR:** enabled (OpenIddict 6.1+). Required — .NET 9+ backend OIDC clients auto-use it. The
  PAR capture stage in `OidcTenantResolutionMiddleware` must be re-verified against OpenIddict's
  response JSON (§4.7).
- **Logout/end-session:** standard endpoint; `GetLogoutContextAsync` replaced by reading the
  end-session request (`id_token_hint`, `post_logout_redirect_uri`) via OpenIddict request
  accessors; session revocation via the new ticket store.

### 4.5 Server-side sessions (rebuild)

Duende's `AddServerSideSessions` is replaced by a **cookie `ITicketStore`** — this is
functionally what Duende does under the hood (the cookie carries a key; the encrypted ticket
lives server-side):

- `OctoTicketStore : ITicketStore` persists the DataProtection-protected ASP.NET
  `AuthenticationTicket` into a per-tenant `RtServerSideSession`-successor (same shape: unique
  `SessionKey`, `SubjectId`, `SessionId`, `ExpirationDateTime` indexes; keep the
  `MongoWriteRetry` behavior for concurrent renewals).
- Wired via `ConfigureApplicationCookie(o => o.SessionStore = ...)`; cookie stays hundreds of
  bytes (the original cookie-bloat fix is preserved).
- Expiry sweep: extend `TokenCleanupHostService` (system + all child tenants), replacing Duende's
  built-in 10-minute sweep.
- Session enumeration/revocation used by logout stays on the store's query API.
- **Cookie scheme names:** replace `IdentityServerConstants.DefaultCookieAuthenticationScheme` /
  `ExternalCookieAuthenticationScheme` with our own `OctoAuthSchemes` constants. The
  `TenantCookieManager` `{name}.{tenantId}` convention is unchanged; cookie *names* may change at
  cutover (sessions end anyway — see §2), but must be stable from then on.

### 4.6 Interaction layer

Introduce a thin **`IOctoInteractionService`** façade that the four SPA API controllers consume,
so controller code stops referencing any OIDC-server library directly:

- `GetAuthorizationContextAsync(returnUrl)` → parse/validate the stored authorize request
  (OpenIddict request accessor + client lookup).
- `IsValidReturnUrl`, `GetErrorContextAsync`, `GetLogoutContextAsync` → own implementations
  (return-URL validation = local URL or registered redirect; error context via our error id
  round-trip, cf. AB#4950).
- Consent: `GrantConsentAsync`/`DenyAuthorizationAsync` → create/deny an `RtOAuthAuthorization`
  and resume the authorize flow.
- Grants page: `GetAllUserGrantsAsync`/`RevokeUserConsentAsync` → authorization/token store
  queries.
- Audit events (login success/failure/logout, token exchange) → direct `OctoEventSink`-equivalent
  calls (we only ever persisted error/failure).

### 4.7 `OidcTenantResolutionMiddleware` re-verification

The middleware's contract is HTTP-level, so it survives — but every capture stage must be
re-pinned against OpenIddict's actual responses: authorize redirect status codes and `Location`
shape, `form_post` HTML, PAR response JSON (`request_uri` field), device-authorization response
body, token response (refresh-token capture). The `acr_values`-through-PAR workaround must be
re-tested (OpenIddict preserves request parameters through `request_uri` resolution — verify,
then possibly simplify). The refresh-token→tenant persistent lookup switches to the first-class
`TenantId` attribute (§4.2). Each stage gets an integration test pinning the OpenIddict response
shape so future OpenIddict upgrades fail loudly here instead of silently.

## 5. Implementation plan (maps to AB#4990–4998)

| Phase | WI | Content | Depends on |
|---|---|---|---|
| 1 | 4990 | OpenIddict skeleton: server/core/validation wiring, signing cert, `DisableAccessTokenEncryption`, claims destinations, discovery diff doc, remove license-key boot gate | — |
| 2 | 4991 | Application/scope stores over `RtClient`/`RtApiScope`/`RtApiResource`, permissions transform, secret compatibility; CK model bump with `RtOAuthAuthorization`/`RtOAuthToken` + token store | 1 |
| 3 | 4992 | Token exchange handler (cross-tenant gate, B-shadow sub, audit events) | 1, 2 |
| 3 | 4993 | Device flow + DCR rewire + discovery `registration_endpoint` | 1, 2 |
| 4 | 4994 | `OctoTicketStore` sessions, `OctoAuthSchemes`, cleanup sweep | 1 |
| 4 | 4995 | `IOctoInteractionService` + four SPA API controllers + audit | 1, 2 |
| 5 | 4996 | `OidcTenantResolutionMiddleware`/`TenantLoginRedirectMiddleware` re-verification with pinned integration tests | 1–4 |
| 6 | 4997 | Conformance + E2E: full test-suite port, token-diff harness, cross-tenant E2E, MCP/octo-cli/adapters | 1–5 |
| 7 | 4998 | Cutover: staging-1 → test-2 → prod-1/prod-2, Duende package removal, comment/CK-description cleanup, license-secret removal | 6 |

Phases 3 and 4 parallelize across two developers. Estimate: **4–8 developer-weeks** to parity
plus stabilization; the protocol endpoints are the small part — claims parity, session rebuild,
and middleware re-pinning dominate.

## 6. Verification strategy

- **Token-diff harness:** capture Duende vs. OpenIddict tokens (header, claims, `aud`, `scope`,
  lifetimes) for every flow × client shape; diff must be empty except `jti`-class claims.
  This is the primary regression gate — resource services must not notice the swap.
- **Discovery-diff:** automated diff of `/.well-known/openid-configuration` old vs. new;
  every difference documented and consumer-checked (MCP protected-resource metadata included).
- Port existing suites: `PersistentGrantStoreTests` → token store, `ServerSideSessionStore*` →
  ticket store, `TenantExchangeIntegrationTests` (privilege-escalation regression!),
  `CrossTenantLoginTests`, `DeviceApiControllerTests`, `VirginSystemDatabaseBootstrap*`.
- E2E per cluster before/after: SPA login all tenants, cross-tenant hand-off + exchange, device
  flow, `client_credentials` (adapters, mirrors), DCR + MCP end-to-end, refresh lifecycle,
  logout. Optionally the OpenID Foundation conformance suite (basic + device profiles).

## 7. Cutover & rollback

1. Feature branch builds a fully OpenIddict-backed service; Duende path remains on `main` until
   cutover (no dual-stack in one process — the swap is per deployment).
2. Order: staging-1 (soak ≥ 3 days) → test-2 → prod-1/prod-2, each with an announced re-login
   window. `client_credentials` consumers need no announcement.
3. Monitoring: auth error rates, token issuance counts per flow, `LicenseExpired` errors gone,
   Dash0 identity dashboards.
4. **Rollback:** redeploy the previous image. Old grants/sessions were already invalidated at
   cutover, so rolling back costs a second re-login but nothing else; config data was never
   transformed, so it is bidirectionally compatible. New `RtOAuthToken` rows are simply orphaned
   (swept later). Rollback window closes once the transition CK types are removed (final cleanup
   rev) — keep that rev at least one train behind the cutover.
5. Until cutover: stay on Duende 8.0.6 (runs with warnings). Clarify the contractual position of
   the actually-signed order (pre-June-2026 terms may be milder) — tracked in AB#4998.

## 8. Risks & open questions

| Risk | Mitigation |
|---|---|
| Claims/`aud` drift breaks resource services silently | Token-diff harness as merge gate (§6) |
| `OidcTenantResolutionMiddleware` capture stages subtly mismatch OpenIddict response shapes | Pinned integration tests per stage (§4.7); budgeted explicitly in WI 4996 |
| OpenIddict has no packaged session management | `ITicketStore` rebuild is standard ASP.NET machinery; ~equivalent to today's `ServerSideSessionStore` scope |
| Secret-hash incompatibility locks out existing clients | Store-owned secret validation keeping today's hash format (§4.3), covered by integration tests with seeded secrets |
| Single-maintainer risk (OpenIddict) | Apache 2.0 (fork-able worst case); optional sponsorship tier ($1k/mo) buys private support + 24-month back-support; RSK commercial components exist |
| PAR behavior differences (`acr_values` visibility) | Verify early in Phase 1 spike; the workaround may even become removable |
| Angular SPA API contracts change | None expected — the four controllers keep their routes/DTOs; only their internals change |

**Open questions:** (a) keep grants centralized in the system tenant DB vs. move per-tenant now
that `TenantId` is first-class — proposal: keep centralized, revisit separately; (b) adopt
OpenIddict's encryption certificate for id-token/`request_uri` protection — yes, new stable cert
in the same secret chain; (c) timing relative to Data-Permissions Epic 4969 rollout — sequence to
avoid overlapping identity-service trains.

## Implementation notes (2026-09-01)

Phases 1–6 (AB#4990–AB#4996) are implemented on the feature branch; the operational cutover
(AB#4998) is pending. Deviations from / decisions beyond the concept above:

- **Grant storage went per-tenant** (open question (a) resolved the other way): the OpenIddict
  authorization/token stores persist in new per-tenant CK types `RtOAuthAuthorization`/`RtOAuthToken`
  (System.Identity-2.12.0, migration 21→22), not in the system-tenant `RtPersistedGrant`. The
  refresh-token→tenant resolution in `OidcTenantResolutionMiddleware` is in-memory only, preferring
  `acr_values` sent by clients (no persistent SHA-256 hash fallback).
- **No separate encryption certificate** (open question (b)): the static PKCS#12 signing certificate
  doubles as the encryption credential for OpenIddict-internal token payloads;
  `DisableAccessTokenEncryption` keeps access tokens as plain signed JWTs and the JWKS unchanged.
- **`DisableEntityCaching` is mandatory**: the stores are per-tenant, so OpenIddict's process-wide
  entity cache would leak entities across tenants. Never re-enable it.
- **Principals are built in passthrough protocol controllers** (`Controllers/Protocol/`:
  `TokenEndpointController`, `AuthorizeController`, `EndSessionController`,
  `DeviceVerificationController` at `/connect/deviceverification`) rather than event handlers.
  `TenantLoginRedirectMiddleware` and the Duende `ServerSideSessionStore` were deleted;
  `DeviceApiController` now only holds the DTOs, and the SPA's `ConsentApiService` device methods
  post form-encoded to `/connect/deviceverification` (only SPA contract change).
- **Interaction state is fully self-contained**: `errorId`, `logoutId` and the one-time
  `octo_consent` parameter are data-protected payloads (multi-pod safe, no message store),
  exposed through the `IOctoInteractionService` facade. Remembered consent is a permanent
  `RtOAuthAuthorization`; the grants page merges permanent authorizations with clients holding
  live refresh tokens.
- **Wire-format parity is enforced by code**: `OctoAccessTokenShapeHandler` keeps the Duende token
  shape (one `scope` claim per value, no `sub` on `client_credentials`, no `oi_*` claims, `nbf`
  present, no `azp` on id tokens, access tokens get no DB entry), verified byte-identical by the
  golden baseline tests (`tests/IdentityServices.IntegrationTests/Api/Protocol/TokenShapeGoldenTests.cs`
  + `GoldenFiles/`, recorded from Duende — all 5 green).
- **Secret compatibility as planned**: `OctoApplicationManager` + `OctoSecretHasher` validate the
  stored Duende hash format (Base64 SHA-256/512) — no secret rotation needed.
- **Public clients may still send a secret**: deployed consumers (octo-cli, adapters) send a
  `client_secret` even for clients with `RequireClientSecret = false`; Duende ignored it, OpenIddict
  rejects it (`invalid_client`, ID2053). `OctoPublicClientSecretHandler` drops the secret for
  public clients before `ValidateClientType`; confidential clients still authenticate strictly
  (pinned by `PublicClientSecretToleranceTests`).
- **`AlwaysIncludeUserClaimsInIdToken` parity**: for clients with this flag (e.g. Refinery Studio)
  the user claims (`role`, `tenant_id`, `allowed_tenants`, `home_tenant_id`, `name`,
  `preferred_username`, `email`, `family_name`, `given_name`) are stamped with an id-token
  destination via `OctoClaimsDestinations.ForClient(bool)`; profile claims are populated in
  `OctoTokenClaimsService.PopulateUserClaimsAsync`. Without this, SPAs that read user identity
  from the id token (angular-oauth2-oidc) fall into a login redirect loop.
- **Accepted behavioral differences**: `client_credentials` without a `scope` parameter now yields
  no scopes (Duende granted all allowed); token responses may report `expires_in` as remaining
  seconds; introspection now authenticates clients (ApiSecrets-based resource introspection not
  wired — unused).
- **Config**: `Identity:IdentityServerLicenseKey` removed; signing via `KeyFilePath`/`KeyFilePassword`
  unchanged. Remaining discovery-document differences: `docs/openiddict-discovery-diff.md`.
