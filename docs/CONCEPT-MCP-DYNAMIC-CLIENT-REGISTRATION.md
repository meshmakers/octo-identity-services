# Concept — MCP Dynamic Client Registration (RFC 7591), AB#4338 Option A

Status: PROPOSED implementation plan. Enables spec-compliant interactive MCP clients (Claude Code
2.1.x) to authenticate against the AB#4315-gated MCP transport, which requires RFC 7591 Dynamic
Client Registration (DCR) — verified live: Claude Code fails with "Incompatible auth server: does not
support dynamic client registration" because our Duende exposes no `registration_endpoint`.

## Decisions (resolved)

1. **Do NOT use the `Duende.IdentityServer.Configuration` package.** It is a separate host built on the
   EF-oriented `IClientConfigurationStore`; our client persistence is all-custom CK/Mongo
   (`ClientStore : IOctoClientStore`), and it does not solve tenant resolution. Separate license tier.
   → Hand-roll a small `POST /connect/register` endpoint reusing the existing `RtClient` build path.

2. **Tenant model: reuse the EXISTING tenant-specific auth (no new tenant machinery).** Single fixed
   issuer (`IssuerUri=AuthorityUrl`); tenant carried via `acr_values=tenant:{id}`. Per
   `docs/CONCEPT-TENANT-SPECIFIC-OAUTH.md`, a client that does NOT send `acr_values` is already handled
   by **Email-First Tenant-Discovery (§9, shipped)** — the same path Grafana uses. MCP metadata
   correctly advertises the root authority (verified both `/mcp` and `/{tenantId}/mcp`). So:
   - DCR registers the client in the **system tenant** with `AutoProvisionInChildTenants=true` and
     mirrors it to child tenants — identical to how the seeded `octo-mcpServices-*` clients already
     live and propagate (`ClientMirrorProvisioningService`).
   - Tenant is resolved at **authorize** by §9 email-first tenant-discovery (`/tenant-discovery`):
     Claude Code sends authorize with no acr → user enters email → `acr_values=tenant:X` appended →
     tenant-specific token. Transparent to Claude Code (it waits for the loopback callback).
   - Because §6 provisions the client into every tenant, it is found in whatever tenant §9 resolves.
   - **No octo-mcp-service change, no per-tenant issuer, no ClientStore fallback hack** — this is the
     platform's normal per-tenant client model, not a special case.

3. **Registration is OPEN but hard-constrained.** Claude Code performs DCR with NO initial access token
   (zero-config). An initial-access-token gate would be incompatible. Security instead via: enabled by
   default (opt-OUT per deployment — acceptable: loopback-only redirects give no phishing vector and a
   registration alone yields no token), loopback-only redirect URIs, PKCE required, public client (no secret),
   grant fixed to authorization_code(+refresh), server-fixed scope allow-list + the mcp resource,
   per-IP rate limit, per-tenant client cap, bounded TTL, dedupe.

4. ~~**Keep the seeded `octo-mcpServices-interactive` client** as a fallback for non-DCR clients.~~
   **REVISED (blueprint 1.1.5):** the client was removed again. Nothing ever consumed it — Claude Code
   registers via DCR (`octo-dcr-*`, random loopback ports; the static client's fixed `:8976`
   redirects never matched), the MCP server itself uses the device client for device flow, refresh and
   token exchange, and the Swagger UI has its own client. A deployment that disables DCR and needs a
   pre-registered interactive client can re-create one explicitly.

## End-to-end flow (M2)
1. Claude Code → `GET /.well-known/oauth-protected-resource/mcp` (octo-mcp-service) → `resource=https://mcp/`,
   `authorization_servers=[https://identity/]` (root — unchanged).
2. → `GET https://identity/.well-known/openid-configuration` → now includes `registration_endpoint`.
3. → `POST https://identity/connect/register` (system-tenant context) → gate validates → creates
   `RtClient` in system tenant (`DynamicRegistration=true`, `AutoProvisionInChildTenants=true`,
   loopback redirects, PKCE, fixed scopes, TTL) → mirror to existing child tenants → 201 with
   `client_id`, `token_endpoint_auth_method=none`.
4. → `GET https://identity/connect/authorize?client_id=…&resource=https://mcp/&code_challenge=…`
   (no acr) → `OidcTenantResolutionMiddleware` → `/tenant-discovery` → user email → tenant X (+acr) →
   login → consent (client sends `prompt=consent` → relies on the consent-flow fixes in PR #107) →
   code → loopback callback.
5. → `POST /connect/token` (PKCE) → access token (allowed_tenants; aud carries the mcp resource) +
   refresh token.
6. Claude Code sends `Authorization: Bearer` to `https://mcp/mcp` → AB#4315 validates → connected;
   per-tool `tenantId` selects the tenant to operate on (within allowed_tenants).

## Tenant switching (CORRECTED 2026-07-11 — one token = one operating tenant)

IMPORTANT correction: switching tenants is NOT free. The shared `TenantAuthorizationMiddleware`
(octo-common-services) authorizes the route tenant **strictly against the token's `tenant_id` claim**;
its own comment states `allowed_tenants` is used ONLY for tenant selection (the picker UI), NOT for
authorization. A token with `tenant_id=energyiq` gets **403** at voestalpine's API even if voestalpine ∈
`allowed_tenants`. Two tenant concepts:
- **Login / operating tenant** — the one the user authenticated against; `tenant_id` in the token; the
  ONLY tenant that token can act on.
- **`allowed_tenants`** — which tenants the user MAY authenticate against (the picker), NOT tenants the
  current token can access.

Consequences (verified live 2026-07-11):
- The MCP server reuses ONE session token for every tool call (`McpSessionContext` +
  `Create*Client(tenantId, token)`). For a `tenantId` ≠ the token's `tenant_id`, the backend 403s.
  So **operating on another tenant requires a NEW token with that tenant's `tenant_id`** — i.e. a fresh
  authentication against it. In-band, the MCP server does this via the device-code `authenticate` tool
  (the tools cannot re-drive Claude Code's browser OAuth), hence the device-flow fallback on switch.
- The tenantless `/mcp` endpoint + interactive DCR login is still correct for the INITIAL connection;
  the DCR client stays tenant-agnostic. But per-switch re-auth is unavoidable under the current
  `tenant_id`-based authorization model.

Options for SEAMLESS switching (future, beyond AB#4338):
- **REJECTED — naive token re-scope** (swap `tenant_id` on the existing token): INSECURE. The token
  carries tenant-specific ROLES resolved in the login tenant; reusing them under another `tenant_id`
  would grant the user the wrong tenant's rights (privilege leak). A valid token for tenant Y MUST
  carry Y-roles, which can only be resolved in Y. This is exactly why the backend's strict `tenant_id`
  check is correct.
1. **Silent cross-tenant token issuance with role re-resolution** (the only secure seamless path).
   Reuse the existing cross-tenant auto-login machinery (`/{parent}/api/auth/cross-tenant-token` →
   `/{child}/api/auth/cross-tenant-login`, which re-resolves roles in the target via
   `SyncMappedRolesAsync` / `ExternalTenantUserMapping` — no credential prompt, no role leak) and
   extend it to mint a target-tenant **bearer access token** (today it yields a browser session).
   Real, security-sensitive feature; its own work item.
2. **Authorize on `allowed_tenants`** instead of strict `tenant_id` — REJECTED: would leak roles across
   tenants (same reason as the naive re-scope). The strict check is deliberate.
3. **Status quo**: re-auth (device or a fresh interactive login with `acr_values=tenant:<target>`) per
   switch — the token is correctly minted against the target with target-tenant roles. Safe; works today.

## Phased implementation

### Phase 0 — spike confirmations — ✅ DONE 2026-07-11 (all green, verified on the running local stack)
Results:
- **Discovery advertisement — better than expected.** Duende 8.0.1 has `Discovery.CustomEntries`
  (verified) AND a NATIVE DCR discovery option: `IdentityServerOptions.Discovery.DynamicClientRegistration`
  with `RegistrationEndpointMode` + `StaticRegistrationEndpoint` (verified in the 8.0.1 DLL). → advertise
  our hand-rolled endpoint via `StaticRegistrationEndpoint = {authority}/connect/register` +
  `RegistrationEndpointMode = <use-static>` (exact enum name to confirm at impl time). The DCR endpoint
  HANDLER is NOT in the base package (confirmed) → we still hand-roll it (plan unchanged).
- **Tenant path — confirmed.** authorize WITHOUT acr → `302 /tenant-discovery?returnUrl=…` (the §9 path,
  returnUrl preserves resource+PKCE). authorize WITH `acr_values=tenant:energyiq` + the seeded
  interactive client (mirrored into energyiq) → `303 /energyiq/login` → client found in the child tenant,
  flow proceeds. Client-placement = standard mirror pattern, CONFIRMED (no ClientStore hack).
- **Resource indicator (RFC 8707) — confirmed validated.** `resource=https://localhost:5017/` (mcpApi)
  → proceeds to login (accepted). `resource=https://bogus.example/` → `303 /energyiq/error` (invalid_target,
  rejected). So a public authz-code client can request the mcp resource; a wrong resource is refused.

→ **Green-light Phase 1.** No blockers found; the tenant + resource + discovery mechanics all work with
existing machinery.

### Phase 0 (original checklist, for reference) (0.5–1 d)
- Duende 8.0.1: add `registration_endpoint` to the root discovery via
  `IdentityServerOptions.Discovery.CustomEntries` without breaking discovery caching. Verify.
- Prove the end-to-end tenant path (reuses shipped machinery): a client registered in the system
  tenant with `AutoProvisionInChildTenants=true` + mirrored is found at authorize AFTER §9 email-first
  tenant-discovery resolves a child tenant, and the token carries that tenant. (Placement is DECIDED:
  standard per-tenant provisioning/mirror, same as the built-in clients — not the ClientStore-fallback
  hack.)
- Confirm a public authz-code client can request `resource=${octo.mcp.publicUrl}/` (mcpApi) through
  the token pipeline (scope+resource association).

### Phase 1 — schema + store (1–2 d)
- CK: add `DynamicRegistration` (bool, default false) + `DynamicRegistrationExpiresAt` (DateTime?)
  in `ConstructionKit/attributes/identity-attributes.yaml`; reference (isOptional) in
  `ConstructionKit/types/ck-client.yaml`. Bump `System.Identity` model version + `IdentitySchemaVersionValue`;
  add index-refresh migration copied from `ClientProvisionedByParentMigration.cs` (additive → no data migration).
- `ClientUriSources.cs`: add `Dynamic` source constant.

### Phase 2 — registration endpoint + discovery — ✅ DONE 2026-07-11 (build + suite green)
Implemented: `DynamicClientRegistrationOptions` on `OctoIdentityServicesOptions` (Enabled default false,
AllowedScopes, ClientTtlDays=90, MaxClientsPerTenant=100, RateLimitPermitsPerMinute=5); RFC 7591
request/response/error DTOs; `IDynamicClientRegistrationService` + `DynamicClientRegistrationService`
(validate gate → build RtClient in system tenant, DynamicRegistration=true + AutoProvisionInChildTenants=true
+ loopback redirects Source=dynamic + fixed scopes + TTL → InsertOneRtEntityAsync → ProvisionForAllChildTenantsAsync
mirror → dedupe by redirect-uri set → per-tenant cap); `POST /connect/register` minimal-API endpoint
(anonymous, rate-limited "dcr", 201/200/400/403/404 mapping); native-ish discovery via
`Discovery.CustomEntries["registration_endpoint"]` gated on Enabled. NOTE: used CustomEntries (definitely
works) instead of the `Discovery.DynamicClientRegistration.StaticRegistrationEndpoint` native option to
avoid enum-name uncertainty — revisit if desired. Security gate is basic-but-real here (loopback/PKCE/
public/fixed-scopes); Phase 3 adds the config polish. Original Phase 2 detail below.

### Phase 2 (original checklist) (2 d)
- `POST /connect/register` (system-tenant context — root path, no tenant prefix). RFC 7591 subset
  request/response DTOs (redirect_uris, grant_types, token_endpoint_auth_method, scope, client_name).
- `DynamicClientRegistrationService` (`IdentityServerPersistence/Services/`): validate (Phase 3 gate);
  build `RtClient` reusing the `CreateClientIfNotExistAsync`/`ApplyToClient` field-mapping; set system
  tenant, `AutoProvisionInChildTenants=true`, `DynamicRegistration=true`, TTL; persist via
  `IOctoClientStore.CreateAsync`; then `ClientMirrorProvisioningService` provision into existing
  children; dedupe by (redirect-uri set) → re-issue existing non-expired client.
- `ConfigureIdentityServerOptions.cs`: advertise via the NATIVE option (Phase 0 finding)
  `Discovery.DynamicClientRegistration.StaticRegistrationEndpoint = {authority}/connect/register` +
  `RegistrationEndpointMode = <use-static>` (fallback: `Discovery.CustomEntries["registration_endpoint"]`).
- `Program.cs`: register service + endpoint; add `/connect/register` to CORS + a per-IP sliding-window
  rate limiter (reuse the `tenant-discovery` limiter pattern).

### Phase 3 — security gate (1–2 d)
- `OctoIdentityServicesOptions.DynamicClientRegistration { Enabled=false, AllowedScopes, ClientTtlDays=90,
  MaxClientsPerTenant, RateLimit }`.
- Enforce: loopback-only redirects (127.0.0.1 / [::1] / localhost, http); PKCE required; no secret /
  auth_method=none; grant authorization_code(+refresh) only; scopes = fixed allow-list
  {openid,profile,email,role,octo_api,offline_access} + mcp resource — NOT client-chosen; reject
  otherwise with RFC 7591 error codes. Open registration (no initial-access-token) — gated by the above
  + rate limit + cap + opt-in.

### Phase 4 — lifecycle — ✅ DONE 2026-07-11 (build green; suite pending in this commit)
Implemented: (1) **Immediate expiry enforcement** — `ClientStore.FindClientByIdAsync` returns null for a
`DynamicRegistration=true` client past `DynamicRegistrationExpiresAt`, so Duende rejects it
(`unauthorized_client`) regardless of sweep timing. (2) **TTL sweep** in `TokenCleanupHostService`
(`RemoveExpiredDynamicClientsAsync`, runs each cleanup interval alongside grant cleanup): queries the
system tenant for expired dynamic clients, `RemoveMirrorsForClientAsync` (drops child mirrors + tracking
rows) then erases the system-tenant client. (3) **PreBlueprintCleanupMigration** defensive early-continue
on `entity is RtClient { DynamicRegistration: true }` (already preserved via random ClientId; documents
intent). Dedupe + per-tenant cap already landed in Phase 2. Original Phase 4 detail below.

### Phase 4 (original checklist) (1 d)
- TTL sweep: extend `TokenCleanupHostService` (iterates system + child tenants) to erase expired
  `DynamicRegistration=true` clients + their mirrors (`RemoveMirrorsForClientAsync`).
- Per-tenant cap enforced at registration.
- `PreBlueprintCleanupMigration`: defensive early-continue on `DynamicRegistration=true` for `RtClient`
  (already safe via random ClientId ∉ whitelist; makes intent explicit).

### Phase 5 — tests + docs ✅ DONE 2026-07-11 (live e2e still pending)
- **DCR integration tests** (`DynamicClientRegistrationIntegrationTests`, Testcontainers, 8 tests, all
  green): valid loopback → system-tenant client (DynamicRegistration + AutoProvision + PKCE + offline)
  + mirrored into child; non-loopback / no-redirect / confidential-auth / bad-grant rejected; disabled →
  Disabled; identical redirect set deduped → existing re-issued; per-tenant cap → CapExceeded.
- **Docs**: `docs/authentication.md` § Dynamic Client Registration; `CLAUDE.md` config option.
- **STILL PENDING: live Claude Code e2e** — needs the local identity restarted with
  `OCTO_IDENTITY__DYNAMICCLIENTREGISTRATION__ENABLED=true`, then `claude mcp login` against
  `https://localhost:5017/mcp` (email-first tenant-discovery in the browser).

### Phase 5 (original checklist) (2–3 d)
- Integration tests (Testcontainers Mongo, reuse `IdentityServicesFixture`): valid loopback register →
  RtClient in system tenant, random rtId, DynamicRegistration=true, mirrored; reject non-loopback /
  secret / bad-grant / bad-scope; dedupe re-issues; TTL sweep erases + demirrors; PreBlueprintCleanup
  preserves; authz-code+PKCE with the mcp resource succeeds.
- Live: Claude Code 2.1.x `octomesh` server → Authenticate → browser (email-first tenant-discovery) →
  connected; whoami/list_tenants.
- Docs: `docs/authentication.md`, `CLAUDE.md`.

## Files
Create: `DynamicClientRegistrationService`(+iface), registration endpoint + DTOs, index migration,
integration tests.
Modify: `identity-attributes.yaml`, `ck-client.yaml`, `IdentityServiceConstants` (schema version),
`ClientUriSources`, `ConfigureIdentityServerOptions` (discovery entry), `OctoIdentityServicesOptions`
(DCR opts), `Program.cs` (service/endpoint/CORS/rate-limit/discovery), `TokenCleanupHostService` (TTL
sweep), `PreBlueprintCleanupMigration` (defensive skip), docs.

## Risks
1. **Mirror fan-out** (dynamic clients × tenants) — same behavior as the built-in mirrored clients, so
   normal platform load; bounded further by dedupe + TTL. Monitor count; not a blocker.
2. **Open registration abuse** — accepted, mitigated by loopback+PKCE+fixed-scope+rate-limit+cap+opt-in.
3. **Consent UX** — Claude Code sends `prompt=consent`; depends on the consent-flow fixes (PR #107).
4. **Duende discovery customization** per Duende 8.0.1 — confirm in Phase 0.
5. **Resource indicator** requestable by a dynamic public client — confirm in Phase 0.

## Effort ≈ 6.5–10.5 dev-days (Phase 0 gates the rest).
