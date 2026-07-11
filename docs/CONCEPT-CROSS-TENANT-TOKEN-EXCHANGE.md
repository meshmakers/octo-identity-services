# Concept — Seamless MCP tenant switching via cross-tenant token exchange (AB#4338)

Follow-up to the DCR work. Lets the MCP server obtain a **target-tenant (B) bearer access token** for an
already-authenticated user (proof = their current A access token) WITHOUT a browser/credential prompt,
with roles **re-resolved in B** — no privilege leak. Solves the device-flow-on-switch friction.

## Why the naive approach is rejected
`TenantAuthorizationMiddleware` authorizes the route tenant strictly against `tenant_id` (allowed_tenants
is only the picker). A token carries tenant-specific ROLES resolved in the login tenant. Swapping
`tenant_id` on the existing token would leak the login tenant's roles into B → privilege escalation.
REJECTED. A valid B token MUST carry B-roles, resolvable only in B.

## The mechanism: RFC 8693 Token Exchange as a Duende IExtensionGrantValidator

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token` = the caller's A access
token, `acr_values=tenant:B` carries the target. Duende 8.0.1 supports this via
`.AddExtensionGrantValidator<T>()` (no built-in TE validator; behavior fully ours).

**The linchpin (security-correct role resolution — reuses everything):**
`OidcTenantResolutionMiddleware` already wires the B tenant repo into `HttpContext.Items` from
`acr_values=tenant:B` on `/connect/token`. The validator returns a `GrantValidationResult` whose
**`sub` is the B-shadow user (`xt_A_user`)**, NOT the A user. That forces
`UserProfileService.GetProfileDataAsync` + `OctoUserStore.GetRolesAsync` to stamp `tenant_id=B`,
B's `allowed_tenants`, and **B-resolved roles** automatically — the exact same claim path as a normal
login. No re-scope, no leak. Only the validator's authorize+resolve logic is new.

**Validator sequence (fail-closed at each step):**
1. Validate `subject_token` **context-free** (`JsonWebTokenHandler.ValidateTokenAsync` against
   `IValidationKeysStore` keys, `ValidateAudience=false`; NOT Duende
   `ITokenValidator.ValidateAccessTokenAsync`, which runs in the B request-context and wrongly rejects
   with `invalid_token` because the A user does not exist in B). Extract A `sub`, `tenant_id=A`,
   `home_tenant_id`, `preferred_username`. Reject if invalid/expired.
1a. **Effective-source resolution (sibling-tenant fix):** the caller is usually itself a cross-tenant
   shadow user `xt_{home}_{orig}`, so `tenant_id=A` is a *sibling* of B (both children of the home
   tenant), not an ancestor — the ancestry gate below would wrongly deny it. The shadow user name is
   read from the SOURCE tenant database (`FindUserNameByIdInTenantAsync(A, subA)`) — authoritative;
   token claims like `home_tenant_id`/`preferred_username` are subject to API-resource claim
   filtering and are typically ABSENT from access tokens, so they must not be relied on. If the name
   matches `xt_{home}_{orig}` (same `Split('_', 3)` convention as `UserProfileService`), resolve the
   home `sub` via `FindUserIdByNameInTenantAsync(home, orig)` and use (home, homeSub) as the
   effective source for the gate. A direct user (no `xt_` prefix) keeps (A, subA). Unresolvable home
   identity → `UnauthorizedClient`.
2. **B-authorization gate:** `CrossTenantAuthenticationService.ValidateCrossTenantAccessAsync(B, source, subSource)` (walks hierarchy: source must be ancestor of B; source user exists). null → `UnauthorizedClient`. (Defense-in-depth: assert B ∈ `AllowedTenantsResolver.ResolveAsync(source,userSource)`.)
3. **Re-resolve roles in B:** assert `HttpContext.Items[TenantId] == B`; `FindOrCreateCrossTenantUserAsync(result, B)` → B-shadow user with B roles (`SyncMappedRolesAsync` via `RtExternalTenantUserMapping`). Return principal with the B-shadow `sub`.
4. **Audit** via `OctoEventSink`: {subjectA, tenantA, tenantB, shadowRtId, grantedRoles}, success + failure.

**Refresh tokens — v1 decision: NONE.** Issue short-lived B access tokens; re-exchange on expiry from the
still-valid A token. Sidesteps cross-tenant refresh-token binding; A remains the single long-lived
credential (root of trust). Add exchanged refresh tokens only if re-exchange latency becomes a problem.

## MCP-service side
- `ITenantTokenExchanger`/`TenantTokenExchanger` (sibling of `SessionTokenRefresher`): POST `/connect/token`
  with the exchange grant + A token + `acr_values=tenant:B` + `client_id=octo-mcpServices-device` → B token.
- `IMcpSessionTokenStore`: per-tenant token cache keyed by `(sessionId, tenantId)`; the existing single
  token stays as the home/root (A) token.
- `switch_tenant(server, tenantId)` tool `[McpRisk(Low)]` (grants no new authority — B-auth enforced
  server-side): exchange + cache + return {IsSuccess, TenantId, Roles}. On failure recommend `authenticate`.
- `McpSessionContext.TryGetAccessTokenAsync(server, tenantId)` overload: home tenant → existing path; else
  per-tenant cache → transparently token-exchange from the home A token (tools work even without an explicit
  switch). The 6 `*ClientContext.TryBuildAsync` helpers thread the resolved tenantId into the token lookup.
- Device-flow `authenticate` stays as the fallback (initial/home auth + B where cross-tenant authz fails).

## Files
Identity — ADD: `IdentityServices/Services/TenantExchangeGrantValidator.cs`. MODIFY: `Program.cs`
(`.AddExtensionGrantValidator<>`), `OidcTenantResolutionMiddleware.cs` (token-exchange acr branch in
`ResolveTenantFromTokenRequestAsync`), seed `entities.yaml` (grant on the device client 660…34; the
interim interactive client 660…35 was removed again in blueprint 1.1.5 — DCR covers interactive logins),
`DynamicClientRegistrationService.cs` (allow-list the grant for DCR clients — decide). DO NOT touch
`TenantAuthorizationMiddleware`/`PersistentGrantStore`/`UserProfileService`/`OctoUserStore`/
`CrossTenant*`/`AllowedTenantsResolver` (the strict tenant_id check is CORRECT; the exchanged token
satisfies it for B).
mcp-service — ADD: `ITenantTokenExchanger`/impl, `Tools/TenantSwitchTools.cs`. MODIFY: `McpSessionTokenStore`
(per-tenant cache), `McpSessionContext` (per-tenant acquisition), the 6 `*ClientContext` helpers, `Program.cs`.

## Tests
Identity integration (Testcontainers, IdentityServicesFixture): A(parent, roles) + B(child w/
RtOctoTenantIdentityProvider(parent=A) + RtExternalTenantUserMapping granting a SUBSET of roles); exchange
end-to-end → token has tenant_id=B + B-resolved roles (**privilege-escalation regression: roles == B subset,
NOT A's**); B-not-ancestor → 400; invalid subject_token → 400; exchanged token passes B-route auth, 403s on C.
mcp-service (ToolTestBase): switch_tenant happy/unauth/missing-arg/exchange-fail; transparent acquisition;
exchanger wire-format.

## Risks
1. **Privilege escalation (highest)** — must issue for the B-shadow sub, never re-scope A. Pinned by the
   B-role-equality integration test.
2. **B repo not wired** — validator must assert resolved tenant == requested B, fail closed.
3. **Refresh-token cross-tenant** — v1 avoids by issuing no exchanged refresh token.
4. DCR clients need the grant allow-listed if Claude Code uses one.
5. First `switch_tenant` creates a persistent `xt_A_user` in B (idempotent; audit it).

## Effort ≈ 5-6 dev-days. Phases: 1) identity grant validator + middleware + seed + tests (2-3d);
2) mcp-service exchanger + cache + switch_tenant + transparent acquisition + tests (2d); 3) DCR grant
allow-list + docs + audit/telemetry (1d). All under AB#4338.
