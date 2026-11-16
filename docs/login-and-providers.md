---
description: Self-registration, AD group sync, identity provider REST API, tenant discovery and topology, OTP delivery, channel preference
applies_to: src/Authentication/**, **/Services/Login/**, {TenantDiscovery*,TenantTopology*,*IdentityProvider*,*EmailDomainGroupRule*,*Channel*}.cs
---

# Login configuration, identity providers and tenant discovery

## Per-User Outbound Channel Preference

`RtUser.PreferredChannelBindingId` (optional String, CK 2.18.0) stores the **rtId of the
`VerifiedExternalIdentifier`** the user chose as the target for **system-initiated** messages. The
channel KIND is never stored — it is DERIVED from the referenced binding (PhoneNumber ⇒ `"SIGNAL"`,
EntraIdObjectId ⇒ `"TEAMS"`, extensible in `PreferredChannelService.KindToChannel`), so a user with
several phone numbers picks the concrete number. The attribute name `PreferredChannelBindingId` is
a cross-repo contract: the mesh adapter reads it from the user entity and derives kind + target
itself. Synchronous replies keep using the channel the message came in on.
`IPreferredChannelService` / `PreferredChannelService`
(`IdentityServerPersistence/Services/SelfService/`): `GetOptionsAsync` lists every VALID own
binding of a channel-mapped kind, `SetPreferredChannelAsync` only accepts one of those (anything
else — malformed id, foreign/unknown binding, expired, unmapped kind ⇒
`Status=BindingNotEligible`, deliberately not distinguishing "not yours" from "does not exist");
clearing (null) is always allowed; `ClearIfReferencedAsync` is invoked by
`SelfServiceIdentifierService.RemoveAsync` so deleting the preferred binding clears the preference
in the same operation (a reference gone dangling via other paths reads as "no preference" without
a write). Persistence via `UserManager.UpdateAsync`. Self-service API on
`MyIdentifiersApiController`: `GET`/`PUT {tenantId}/api/manage/identifiers/preferredChannel`
(cookie + bearer schemes, current user only) — GET returns `{bindingId, channel, identifierValue,
options[]}`, PUT takes `{bindingId|null}` and answers `Success=false`/`Status=BindingNotEligible`
on refusal (no 400 path anymore). UI: radio group of CONCRETE targets ("Microsoft Teams",
"Signal (+43 …)" per bound number, "no preference") on the ClientApp my-identities page, options
served by GET. Tests:
`tests/IdentityServerPersistence.UnitTests/Services/SelfService/PreferredChannelServiceTests.cs`.

## Signal OTP Delivery — Per-Tenant Sender Resolution

The self-service phone OTP is delivered over the `signal-cli-rest-api` bridge by
`SignalRestOtpDeliveryChannel` (`IdentityServerPersistence/Services/SelfService/`). Since per-tenant sender resolution
the **sender number is tenant state, not deployment state**: the channel resolves its sender PER
TENANT at send time (the tenant id travels in `OtpDeliveryContext` — the channel is a singleton
with no HTTP-scoped tenant), with this fallback chain:

1. **The tenant's Studio-activated `System.Communication/SignalChannel`** (
   rtWellKnownName `signal-channel`) in the `Registered` state (2) → its `Number` + `ApiUrl` win.
   Read by `TenantSignalChannelResolver` via `ISystemContext.TryFindTenantRepositoryAsync` — the
   same explicit-tenant access `ClientMirrorProvisioningService` uses (`ISystemContext` is a
   singleton, so the chain is singleton-safe). The entity belongs to the Communication Controller's
   CK model, so the read is a **generic `RtEntity` query by CK type id** (no generated type here)
   and strictly **read-only**. Guards mirror the controller's own projection
   (`AddSignalChannelConfigurationAsync`): a read failure — e.g. a tenant whose
   System.Communication model predates 3.34.0 — degrades to the next step with a warning, never
   breaks OTP delivery; a hand-crafted multi-channel tie is broken by lowest rtId with a warning
   (singleton is service-enforced in the controller).
2. **The env-bound `SignalBridgeOptions`** (`OCTO_SIGNALBRIDGE__APIURL` / `__NUMBER`) — unchanged
   semantics (including the THROW when `ApiUrl` is set but `Number` empty). This is the
   **local-dev fallback** where no Studio activation exists; in cluster deployments the env vars
   are now fully optional.
3. **Neither** → the `LoggingOtpDeliveryChannel` dev stub path (its loud warning, code in the
   log), exactly the previous unconfigured behavior. The stub is no longer registered as an
   `IOtpDeliveryChannel` itself — `SignalRestOtpDeliveryChannel` is always the Signal channel and
   delegates to the injected stub.

The chosen source is logged at Debug ("tenant SignalChannel" vs "SignalBridgeOptions fallback").
Tests: `SignalRestOtpDeliveryChannelTests` (chain behavior at the channel) and
`TenantSignalChannelResolverTests` (entity read: Registered-only, lowest-rtId tie-break,
read-failure degradation, read-only) in
`tests/IdentityServerPersistence.UnitTests/Services/SelfService/`.

## Login Configuration (Self-Registration & Auto-Group Assignment)

Identity providers support login-time configuration via two attributes on the abstract `IdentityProvider` base type:

- **`AllowSelfRegistration`** (bool, default true): When false, new users cannot self-register via this provider — only existing users can authenticate. Applies to all provider types (Google, Azure, OctoTenant, LDAP, etc.)
- **`DefaultGroupRtId`** (string, optional): RtId of a group to which new users are automatically added on first login via this provider

Additionally, **`EmailDomainGroupRule`** entities map email domain patterns to groups:
- **`EmailDomainPattern`**: Domain to match (e.g., "meshmakers.com"), case-insensitive
- **`TargetGroupRtId`**: Group to add matching users to
- Unique index on `EmailDomainPattern`

Key components:
- **`ILoginGroupAssignmentService`** / **`LoginGroupAssignmentService`** (`IdentityServerPersistence/Services/Login/`): Orchestrates group assignment from provider defaults + email domain rules + external identity group claim sync
- **`IEmailDomainGroupRuleStore`** / **`EmailDomainGroupRuleStore`** (`IdentityServerPersistence/SystemStores/`): CRUD for email domain rules
- **`EmailDomainGroupRulesController`** (`TenantApi/v1/Controllers/`): REST API at `{tenantId}/v1/emailDomainGroupRules`
- **`AuthApiController`**: Self-registration gate + group assignment in external login callback, LDAP login, cross-tenant password login, and cross-tenant token login

## AD Group-to-OctoMesh Group Synchronization

When a user logs in via Microsoft AD (LDAP), their AD group memberships are automatically synchronized with OctoMesh groups on **every login** (not just first login). This enables role inheritance from AD groups.

**How it works:**
1. `MicrosoftAdAuthentication` reads the `memberOf` attribute directly from the LDAP user entry and extracts group CN names (e.g., `CN=FdaUsers,CN=Users,DC=...` → `FdaUsers`)
2. Group names are added as `JwtClaimTypes.Role` claims on the external identity
3. `LoginGroupAssignmentService.SyncExternalGroupClaimsAsync` (called on every login, for both new and existing users) matches each role claim against OctoMesh groups by normalized name (`FindByNameAsync`)
4. If a matching OctoMesh group exists, the user is added as a `GroupMember` (if not already a member)
5. The user then inherits all roles assigned to that group via `GroupRoleResolver`, which appear in the JWT token

**Prerequisites for AD group mapping:**
- An OctoMesh **Group** must exist in the tenant with the **same name** as the AD group (e.g., `FdaUsers`)
- That OctoMesh group must have **Roles** assigned via `AssignedRole` associations
- The AD user must be a member of the AD group (`memberOf` attribute)

**Error handling:** Group sync failures are logged but never block the login flow. Individual group assignment failures do not prevent other groups from being assigned.

The **Refinery Studio identity management UI** (Users, Roles, Clients) is available for **all tenants**, not just the system tenant. The `IdentityService` in `@meshmakers/octo-services` resolves the current tenant via `TENANT_ID_PROVIDER` and routes API calls to `{tenantId}/v1/...`.

- **Tenant-scoped login/consent redirects**: `AuthorizeController` (`Controllers/Protocol/`) issues login and consent redirects directly with the correct tenant prefix (resolved from `acr_values=tenant:{tenantId}` / `OidcTenantResolutionMiddleware`), so the former `TenantLoginRedirectMiddleware` — which rewrote Duende's hard-coded 302 redirects — was **deleted** in the OpenIddict migration. Logout redirects carry a self-contained data-protected `logoutId` handled by `EndSessionController`.
- **Auto-creation of `RtOctoTenantIdentityProvider`**: When a tenant has `ParentTenantId` set, the provider is auto-created during `SetupTenantAsync` (new tenants) and via `OctoTenantIdentityProviderMigration` (existing tenants, migration 8→9).

## Tenant Discovery (Email-First Flow)

When an OAuth client sends `/connect/authorize` **without** `acr_values=tenant:{tenantId}`, the `OidcTenantResolutionMiddleware` redirects to `/tenant-discovery` instead of defaulting to the System-Tenant. The user enters their email/username, the server discovers which tenants they belong to, and redirects back to the authorize URL with `acr_values` appended.

Key components:
- **`TenantDiscoveryService`** (`IdentityServerPersistence/Services/`): Searches all tenant databases for a user by email or username. Excludes cross-tenant shadow users (`xt_` prefix). Uses `ISystemContext` to iterate tenants in parallel.
- **`TenantDiscoveryApiController`** (`Controllers/Api/`): Rate-limited endpoint at `POST /api/tenant-discovery/lookup` (no `{tenantId}` prefix). Returns only the user's own tenants, never the full tenant list. Enforces 500ms minimum response time to prevent timing attacks.
- **Discovery scope.** An app host that serves one tenant subtree (for example an accounting app on its own host, root tenant `accounting`) passes it as a second, space-separated `acr_values` entry: `acr_values=tenant_scope:accounting`. `OidcTenantResolutionMiddleware.ParseScopeFromAcrValues` reads it (the `tenant:` parser ignores unknown prefixes, so older clients and the existing `tenant:` entry are unaffected), forwards it as `?scopeTenantId=` on the `/tenant-discovery` redirect (`BuildDiscoveryUrl`), and the SPA sends it with the lookup. `TenantDiscoveryService.FindTenantsForUserAsync(identifier, scopeTenantId)` resolves the user exactly as before — the home search is deliberately **not** restricted to the subtree, an administrator's home is usually above it — and then intersects the result with the descendants of the scope (`GetScopeDescendantsAsync`: a breadth-first walk through each tenant's own context, `ISystemContext.TryFindTenantContextAsync` → `ITenantContext.GetChildTenantsAsync`, direct and indirect, the scope itself excluded, a child without a resolvable context treated as a leaf, cycle-safe). 🔴 It is deliberately **not** built on `ISystemContext.GetAllTenantsAsync`: that enumeration constructs `OctoTenant` without the parent id (engine-mongodb `SystemContext.GetAllTenantsAsync`), so every tenant looks like a direct child of the system tenant and a scope below it has no descendants — the first cut shipped that way in 3.4.126 and returned "not found" for every scoped lookup on prod-1, while the unit tests, fed with hand-built parents, stayed green. A scope test must therefore go through the same API the service uses, not through a registry fixture. The scope only narrows: it never adds a tenant the user is not in, so the anti-enumeration properties of the lookup are unchanged; an unknown scope answers "not found", not the unscoped list. The single-session shortcut is gated the same way — a session cookie for a tenant outside the scope no longer skips the discovery. Once a tenant is chosen the SPA appends `tenant:{id}` next to the scope entry, so the authorize request carries both. **PAR (RFC 9126):** a scope-only `/connect/par` names no tenant, so nothing used to be captured and the follow-up `/connect/authorize?request_uri=…` ran an unscoped discovery. The middleware now reads the scope from the PAR form as well, captures the issued `request_uri` for it (`TokenToTenantMap[ScopeMapKey(request_uri)]`, same lifetime as the tenant entries, keyed apart so the two can never be confused) and restores it on the authorize call (`ExtractScopeFromRequestUri`) before the shortcut and the discovery redirect.
- **`TenantDiscoveryComponent`** (`ClientApp/src/app/features/tenant-discovery/`): Angular SPA page with email input, tenant selection (when multiple), and redirect logic.
- **`octo_last_tenant` cookie**: Shortcuts the discovery flow on repeat visits by redirecting directly with the last-used tenant's `acr_values`.
- **Interceptor exclusion**: The Angular `tenantInterceptor` skips `/api/tenant-discovery/` paths since this endpoint has no tenant context.

See `docs/CONCEPT-TENANT-SPECIFIC-OAUTH.md` § 9 for the full flow diagram and API specification.

## Tenant topology endpoint `GET /api/tenant-topology?scope={rootTenantId}`

Tells an app acting for a signed-in user which of the user's allowed tenants lie below the app's root tenant and whether each has children — **without** any call to a tenant other than the token's tenant, which the user-token tenant gate (`TenantAuthorizationMiddleware`) rejects under `Enforce`.

- **Contract** (the `@meshmakers/shared-auth` client depends on exactly this): `200 { "scope", "scopeHasChildren", "tenants": [ { "tenantId", "depth", "hasChildren" } ] }`; `depth` 1 = direct child of the scope, `hasChildren` = the tenant itself has children (never listed, not even their ids). Nothing else is ever returned: no scope entry, no tenant outside the claim or the subtree, no parent ids, no tenant data (pinned by `ResponseCarriesNoOtherFieldThanTheContract`).
- **Entitlement:** `tenants` = (the `allowed_tenants` claim of the validated user token) ∩ (strict descendants of `scope`). The claim is a *selection hint*, not an API authorization; here it only limits which topology facts are revealed (a boolean and a depth about tenants the user can already log into). `scopeHasChildren` is truthful only when the scope is in the claim or `tenants` is non-empty, otherwise `false` (no oracle for unrelated scopes). An unknown scope, a malformed scope (not a well-formed tenant id), a scope without entitled descendants and a foreign scope all answer the **same** `200` with an empty list and `scopeHasChildren=false`.
- **Status codes:** 401 no/invalid token; 403 client-credentials token (no `sub`) or a user token without the `octo_api` read scope (`IdentityApiReadOnlyPolicy`, no role needed); 400 missing `scope`; 429 rate limit (`Retry-After: 60`); **503** with a problem body when the hierarchy cannot be read completely (failing registry read, more than `TenantTopology:MaxNodes` tenants) — fail closed, never a partial list. A cycle in a hand-edited registry terminates (visited guard). Older identity builds answer 200 `text/html` (SPA fallback) for unknown /api paths; clients must treat a non-JSON 2xx like 404 (topology unknown).
- **No new exemption:** the route has **no** `{tenantId}` segment, and `TenantAuthorizationMiddleware` skips routes without a tenant segment — so nothing changes in octo-common-services and `IAllowParentTenantAdministration` is not used. `TenantGateInEnforceMode_AllowsTheTenantLessRoute_AndStillRefusesAForeignTenantRoute` (real pipeline, `X-Test-RealBearerPrincipal` so the gate actually sees a "Bearer" principal) and `Route_HasNoTenantSegment_…` fail if someone adds a tenant segment or an exemption marker.
- **Code:** `TenantTopologyApiController` (`Controllers/Api/`), `ITenantTopologyService`/`TenantTopologyService` (`IdentityServerPersistence/Services/`), `TenantSubtreeWalker` (the BFS walk, **extracted unchanged in behaviour** from `TenantDiscoveryService.GetScopeDescendantsAsync`, which now delegates to it and keeps its "unreadable ⇒ null" contract; the walk still goes through each tenant's own `ITenantContext.GetChildTenantsAsync`, see the discovery section for why not `GetAllTenantsAsync`), `TenantTopologyRateLimiter` (`Services/`).
- **Caching:** the subtree snapshot (tenantId, depth, hasChildren of the whole subtree) is cached per scope in the shared `IMemoryCache` for 45 s (`TenantRegistry.CacheTtl`) with single flight **per scope key** (in-flight table, entries live only while a read runs; a slow scope or unknown-scope spam never blocks the first request of another scope, `ASlowScope_DoesNotBlockOtherScopes_NorUnknownOnes`); the per-request cost is the intersection with the claim, no database access on a hit (`HundredRequests_ReadTheRegistryOnce`, `ConcurrentFirstRequests_ShareOneRead`). Only **registered** scopes are cached — an arbitrary `scope` value never grows memory — and a failed read is never cached.
- **Rate limit:** per **subject** (`sub`), sliding window of `TenantTopology:RateLimitPermitsPerMinute` (default 60; env `OCTO_IDENTITY__TENANTTOPOLOGY__RATELIMITPERMITSPERMINUTE`). The ASP.NET rate-limiter middleware runs *before* authentication in this host and cannot see the subject, so the controller asks `ITenantTopologyRateLimiter` after the token was validated; an invalid token is answered 401 first and never allocates a partition.
- **CORS:** the identity CORS policy is global and built from the `AllowedCorsOrigins` of every client of every tenant (`IdentityCorsPolicyProvider`, any header, any method), so a browser app whose client lists its origin (meshmakers-app `${scheme}://${tenantId}-accounting.${domain}`, energy-community `${scheme}://energy-community.${domain}`) can preflight and call this route with its bearer header; pinned by `AppOriginOfASeedClient_CanPreflightAndCallTheRouteFromTheBrowser`. No change was needed.
- **Logs:** counts and the scope id only — never claims or token content.
- **Tests:** `TenantTopologyServiceTests` (intersection, depth, hasChildren, legacy case, every fail-closed branch, cache), `TenantTopologyApiControllerTests`, `TenantTopologyRateLimiterTests`, `TenantTopologyEndpointTests` (real Mongo hierarchy, wiring, CORS). Documentation for app developers is a separate story (octo-documentation). The repository has no CHANGELOG file; this section is the change record.

## Identity Provider REST API (IdentityProvidersController)

The `IdentityProvidersController` exposes CRUD endpoints for identity provider configurations at `{tenantId}/v1/identityProviders`. All provider types are serialized/deserialized via JSON polymorphism on `IdentityProviderDto`:

| Provider Type | DTO | Enum Value |
|--------------|-----|------------|
| Google | `GoogleIdentityProviderDto` | 0 |
| Microsoft | `MicrosoftIdentityProviderDto` | 1 |
| Azure Entra ID | `AzureEntraIdProviderDto` | 2 |
| Microsoft AD | `MicrosoftAdProviderDto` | 3 |
| OpenLDAP | `OpenLdapProviderDto` | 4 |
| Facebook | `FacebookIdentityProviderDto` | 5 |
| Octo Tenant | `OctoTenantIdentityProviderDto` | 6 |

`OctoTenantIdentityProviderDto` has a `ParentTenantId` property identifying the parent tenant for cross-tenant authentication. `IdentityProviderDtoMapper` / `IdentityProviderEntityMapping` (`src/IdentityServices/Mapping/`) map between `RtOctoTenantIdentityProvider` and `OctoTenantIdentityProviderDto`.
