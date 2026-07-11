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
   (zero-config). An initial-access-token gate would be incompatible. Security instead via: opt-in per
   deployment (default OFF), loopback-only redirect URIs, PKCE required, public client (no secret),
   grant fixed to authorization_code(+refresh), server-fixed scope allow-list + the mcp resource,
   per-IP rate limit, per-tenant client cap, bounded TTL, dedupe.

4. **Keep the seeded `octo-mcpServices-interactive` client** as a fallback for non-DCR clients.

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

## Tenant switching (already solved — do NOT scope the connection to a tenant)

Switching tenants is NOT done by re-connecting or by scoping the OAuth flow to one tenant. There are
two distinct tenant concepts:
- **Login tenant** — where the user authenticates (via §9 email-first discovery); becomes `tenant_id`
  in the token. One-time (short-cut on repeat visits by the `octo_last_tenant` cookie).
- **Operating tenant(s)** — which tenant's data a tool call acts on; the per-tool `tenantId` parameter,
  bounded by the token's `allowed_tenants`.

The MCP server already reuses ONE session token across tenants: `McpSessionContext.TryGetAccessToken`
pulls the session access token and the `*ClientContext` helpers feed it to
`Create*Client(tenantId, accessToken)` per call; the backend service enforces `allowed_tenants`
(`TenantAuthorizationMiddleware`). So a single token (with `allowed_tenants` resolved by
`AllowedTenantsResolver`) lets Claude Code operate across ALL the user's tenants without re-auth.

Consequences for this design:
- **Use the tenantless `/mcp` endpoint** (current config `https://localhost:5017/mcp`) — one
  connection, one login, switch via the `tenantId` tool parameter.
- **The DCR client is tenant-agnostic** — it is just the app identity; tenant rights come from the
  USER (`allowed_tenants`), not the client. This is why registering it once (system + mirror) is
  sufficient; it does not bind the session to a tenant.
- **Reject M1 / tenant-scoped MCP URLs** — they would pin the connection to one tenant and BREAK
  switching. Tenantless is strictly better here.
- **Optional hardening (separate small task, octo-mcp-service):** the tenantless `/mcp` path does not
  itself check that the per-tool `tenantId` ∈ `allowed_tenants` (today only the backend 403s). Add an
  early `allowed_tenants` membership check in the MCP server so cross-tenant misuse fails fast with a
  clear error instead of a downstream 403.
- **Caveat:** this assumes the user's tenants are reachable via cross-tenant mappings / the tenant
  hierarchy (so one login yields `allowed_tenants` covering them). Users holding SEPARATE, unlinked
  accounts in different tenants would need a per-account login — out of scope; flag if it arises.

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

### Phase 2 — registration endpoint + discovery (2 d)
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

### Phase 4 — lifecycle (1 d)
- TTL sweep: extend `TokenCleanupHostService` (iterates system + child tenants) to erase expired
  `DynamicRegistration=true` clients + their mirrors (`RemoveMirrorsForClientAsync`).
- Per-tenant cap enforced at registration.
- `PreBlueprintCleanupMigration`: defensive early-continue on `DynamicRegistration=true` for `RtClient`
  (already safe via random ClientId ∉ whitelist; makes intent explicit).

### Phase 5 — tests + live validation + docs (2–3 d)
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
