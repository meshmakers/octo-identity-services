---
description: OpenIddict endpoints and handlers, token shape, sessions, tenant resolution at authorize/token/PAR, cookie scoping, token validation
applies_to: src/IdentityServices/{OpenIddict,Cookies}/**, src/IdentityServices/Controllers/Protocol/**, OpenIddictConfiguration.cs, **/SystemStores/OpenIddict/**
---

# OpenIddict protocol stack and tenant resolution

## OpenIddict Protocol Stack (Epic AB#4989)

The OAuth2/OIDC server is **OpenIddict 7.6.0**, configured in
`src/IdentityServices/Configuration/OpenIddictConfiguration.cs`:

- **Endpoint URIs are pinned to the previous Duende paths** (`/connect/authorize`, `/connect/token`,
  `/connect/endsession`, `/connect/deviceauthorization`, `/connect/deviceverification`,
  `/connect/par`, userinfo, introspection, revocation) and JWKS stays at
  `/.well-known/openid-configuration/jwks` — no consumer needs reconfiguration. Remaining discovery
  differences: `docs/openiddict-discovery-diff.md`.
- **Flows:** authorization code + PKCE, `client_credentials`, refresh token, device flow (RFC 8628),
  and RFC 8693 token exchange (now a first-class OpenIddict flow).
- **`DisableAccessTokenEncryption`** keeps access tokens as plain signed JWTs (Duende-compatible).
- **`DisableEntityCaching` is CRITICAL:** the stores are per-tenant; OpenIddict's process-wide entity
  cache would leak entities across tenants. Never re-enable it.
- **Signing:** the same static PKCS#12 certificate as before (`KeyFilePath`/`KeyFilePassword`) →
  the JWKS is unchanged and outstanding access tokens stayed valid across the cutover. The signing
  cert doubles as the encryption credential for OpenIddict-internal token payloads.

**Custom OpenIddict stores** (`src/IdentityServerPersistence/SystemStores/OpenIddict/`) project the
existing CK entities — no data migration:

- `OpenIddictApplicationStore`: read-only projection of `RtClient` (application id = `client_id`;
  honors the enabled flag and the DCR TTL gate).
- `ClientPermissionsMapper`: pure function mapping `AllowedGrantTypes`/scopes/flags to OpenIddict
  permissions; unit-tested against all seed client shapes.
- `OpenIddictScopeStore`: projects `RtApiScope` + `RtIdentityResource` as requestable scopes;
  scope→audience resolution via `RtApiResource`.
- `OpenIddictAuthorizationStore` / `OpenIddictTokenStore`: over the new **per-tenant** CK types
  `RtOAuthAuthorization` / `RtOAuthToken` (System.Identity-2.12.0, migration 21→22).

**Client secrets:** `OctoApplicationManager` + `OctoSecretHasher` (`src/IdentityServices/OpenIddict/`)
validate client secrets against the stored Duende hash format (Base64 SHA-256/512) — no secret
rotation was needed at cutover.

**Principals are built by passthrough controllers** in `src/IdentityServices/Controllers/Protocol/`:

- `TokenEndpointController`: `client_credentials` (stamps effective client roles via
  `IClientRoleStore`), RFC 8693 token exchange (delegates to `TenantExchangeProcessor`), and
  code/refresh/device redemption (re-validates the user and re-resolves roles on every redemption).
- `AuthorizeController`: cookie authentication and tenant-scoped login/consent redirects (replaces
  Duende's UserInteraction plus the deleted `TenantLoginRedirectMiddleware`).
- `EndSessionController`: logout; `logoutId` is a self-contained data-protected payload;
  `/connect/endsession/callback` renders front-channel logout iframes for all registered
  front-channel clients.
- `DeviceVerificationController` at `/connect/deviceverification`: OpenIddict end-user verification
  endpoint; the Angular device page posts form-encoded to it (`DeviceApiController` now only holds
  the DTOs).

**Resource indicators (RFC 8707, AB#5193):** the `resource` parameter is validated against the
requesting tenant's API resources, not against OpenIddict's static `RegisterResources(...)`
allow-list — that list has no per-tenant form and was never filled, so **every** indicator was
rejected with `invalid_target` and no interactive MCP client could log in (Duende validated against
the API resource store). `OctoResourceValidationHandlers` (`IdentityServices/OpenIddict/`) replaces
all three built-in `ValidateResources` handlers (authorize, PAR, token/refresh) and resolves through
`IOpenIddictResourceStore<RtApiResource>` → `OpenIddictResourceStore`
(`IdentityServerPersistence/SystemStores/OpenIddict/`) — the same store shape OpenIddict 8.x
introduces upstream, so the upgrade is a `ReplaceResourceStore<...>()` plus deleting the handlers.
Accepted: statically registered, or an **enabled** `RtApiResource` of that tenant carrying at least
one **requested** scope (a request without `scope` — the refresh renewal — is judged on registration
alone). A trailing slash is insignificant (`ResourceIdentifiers`); nothing else is normalized.
🔴 The companion `ValidateResourcePermissions` handlers (ID2192) are removed too — they look for a
per-client `rsrc:{resource}` permission that `RtClient` cannot express, so they could only ever
reject; removed one by one rather than via `IgnoreResourcePermissions()`. The indicator does **not**
shape the token (audiences stay scope-derived); if that ever changes, the per-client allow-list
becomes load-bearing again. No cache, no invalidation event — entity caching is off anyway. See
`docs/CONCEPT-RESOURCE-INDICATORS.md`.

**Claims parity layer** (`src/IdentityServices/OpenIddict/`):

- `OctoTokenClaimsService`: stamps `tenant_id`, `allowed_tenants`, `home_tenant_id`, roles, and
  `aud` (replaces `UserProfileService`).
- `OctoClaimsDestinations`: claim→token mapping; profile claims are NOT embedded in tokens —
  userinfo serves them.
- `OctoTenantGenerationClaimHandler` (AB#8997, security item AB#8970): `tenant_gen` on **every** access token =
  `TenantLifecycleRecord.CreatedUtc` of the tenant in `tenant_id` (`ITenantLifecycleStore`, read directly at issuance)
  as Unix milliseconds, decimal string, UTC-normalised and truncated like `CkMethodTenantLifecycleGeneration`. Three
  OpenIddict `ProcessSignInContext` handlers: `Lookup` (token endpoint, before `RedeemTokenEntry`, so a failed read
  refuses with `server_error` without burning the code / refresh token), `StampAccessToken` (after
  `PrepareAccessTokenPrincipal`) and `StampIssuedToken` (after `PrepareIssuedTokenPrincipal`: 🔴 OpenIddict 7.6 issues
  the RFC 8693 exchanged access token as the "issued token" with `GenerateAccessToken=false` — a handler on the
  access-token principal alone misses every exchange). Covers every grant incl. refresh (re-read, never copied)
  without touching `TokenEndpointController`. Access token only (not id token, not userinfo). No record / no
  `CreatedUtc` → no claim. Resource services check it from AB#8999 on. The HTTP test host layers
  `Helpers/TestTenantLifecycleStore` over the real store (`CustomWebApplicationFactory.TenantLifecycleStore`) to arrange
  generations; the test system tenant has no record, so the golden token shapes are unchanged. Details:
  `docs/authentication.md` § Tenant Generation.
- **Grants of an earlier tenant (AB#9017, Security):** token exchange and on-behalf-of check the `tenant_gen` of the
  `subject_token`, `TokenEndpointController` checks the private claim `octo_grant_tenant_gen` that refresh tokens,
  authorization codes and device codes store at issuance (`StampAuthorizationCode` / `StampRefreshToken` /
  `StampDeviceCode` in `OctoTenantGenerationClaimHandler`, no destination), each against the current generation of the
  token's `tenant_id`, through `IGrantTenantGenerationGuard` over the AB#8999 `ITenantGenerationCheck`
  (`AddOctoTenantGenerationCheck()` in `Program.cs`). Same option as the resource services,
  `TenantAuthorization:TenantGenerationEnforcement` (default `LogOnly`); `Enforce` maps Deny to `invalid_grant` and
  Unavailable to `server_error`. The check runs before the shadow user / role resolution and before OpenIddict redeems a
  grant (a refused refresh token is not rotated). 🔴 In `LogOnly` a mismatched refresh token is let through, but the
  rotated token keeps the old value (transaction property `CarriedGrantGenerationPropertyName`), never the current one.
  Metric `transport=grant` + `grant_type`. Issuing a code now costs one lifecycle read (the #304 read-count assertions in
  `TenantGenerationClaimHttpTests` changed accordingly). The HTTP tests (`GrantTenantGenerationHttpTests`) use derived
  hosts whose check is built with another `SystemTenantId`, because the test host signs in to its system tenant, which is
  never checked. Details: `docs/authentication.md` § Grants of an earlier tenant.
- **Bearer label (AB#9017):** `ConfigureJwtBearerOptions` sets `TokenValidationParameters.AuthenticationType = "Bearer"`,
  otherwise `TenantAuthorizationMiddleware` skips every bearer request to identity's API. Identity keeps the library
  defaults (`UserTokenEnforcement` / `ServiceTokenEnforcement` = `Enforce`); `OCTO_TENANTAUTHORIZATION__*=LogOnly` is the
  per-environment fallback. The test host forwards
  `Bearer` to `TestAuthHandler` and does not run `ConfigureJwtBearerOptions`; the label is pinned by a unit test.
- `OctoAccessTokenShapeHandler`: enforces the Duende-compatible wire format — `scope` as one claim
  per value (platform-wide `RequireClaim(scope, …)` policies compare full values), **no `sub` on
  `client_credentials` tokens** (`TenantAuthorizationMiddleware` identifies service tokens by its
  absence), no `oi_*` claims, `nbf` present, no `azp` on id tokens; access tokens get no DB entry.

**Interaction facade** `IOctoInteractionService` (`src/IdentityServices/OpenIddict/Interaction/`):
consumed by `AuthApiController`/`ConsentApiController`/`GrantsApiController`. Error/logout/one-time
consent round-trip state travels as self-contained data-protected payloads (`errorId`, `logoutId`,
`octo_consent` query parameter) — no server-side message store, multi-pod safe. Remembered consent
is a permanent `RtOAuthAuthorization`; the grants page lists permanent authorizations plus clients
with live refresh tokens.

**Audit:** `IIdentityAuditService` persists failure events to the runtime event log (replaces
Duende's `IEventService`/`OctoEventSink`; success events are log-only — behavior unchanged).

**Regression gate:** golden baseline tests in
`tests/IdentityServices.IntegrationTests/Api/Protocol/TokenShapeGoldenTests.cs` + `GoldenFiles/` —
token shapes were recorded from Duende and are verified **byte-identical** against OpenIddict
(all 5 green). Any change to token shape must keep these tests green or consciously re-record.

**Behavioral differences vs. Duende** (accepted): `client_credentials` WITHOUT a `scope` parameter
now yields no scopes (Duende granted all allowed scopes); token responses may report `expires_in`
as remaining seconds; introspection now authenticates clients (Duende's ApiSecrets-based resource
introspection is not wired — it was unused).

## Server-Side Sessions (cookie-bloat fix)

Full per-tenant ASP.NET auth tickets (~3 KB each, sent with every request and on OAuth loopback-callback redirects) were overflowing small loopback servers and bloating all browser traffic. Sessions are stored server-side via **`OctoTicketStore : ITicketStore`** (`src/IdentityServices/OpenIddict/`), standard ASP.NET Core machinery (the former Duende `ServerSideSessionStore` was deleted in the OpenIddict migration).

**How it works:**
- The per-tenant `.AspNetCore.Identity.Application.{tenantId}` cookie carries **only a short session key** (hundreds of bytes) instead of the full encrypted ticket. The ticket itself lives in MongoDB per-tenant via the CK runtime.
- `OctoTicketStore` persists data-protected tickets in the per-tenant `RtServerSideSession` entities (same CK type as before, new serialization — old Duende-serialized tickets were invalidated at cutover, one re-login).
- The `sid` claim is stamped at session creation.
- `TenantCookieManager` naming convention (`{name}.{tenantId}`) is **unchanged**.
- `ConfigureApplicationCookie` sets `ExpireTimeSpan = 7 days` sliding; this bounds both the cookie lifetime and the session record lifetime.

**CK types:**
- `RtServerSideSession`: stores the encrypted ticket with a **Unique** `SessionKey` index and ascending indexes on `SubjectId`, `SessionId`, and `ExpirationDateTime`.
- `RtDataProtectionKey`: stores the DataProtection key ring (see Data Protection Key Persistence section).

**Cleanup:** expired-but-not-yet-cleaned records are treated as missing on lookup. `TokenCleanupHostService` sweeps expired sessions, expired `RtOAuthToken`/`RtOAuthAuthorization` entries, and legacy grants for the system tenant plus all child tenants.

**Write-conflict retry:** Concurrent session renewals (two browser tabs refreshing simultaneously) can trigger a transient MongoDB write conflict (`MongoCommandException` with a 'Write conflict' message). The store shares the `MongoWriteRetry` helper to retry transient write conflicts transparently.

## `allowed_tenants` Identity Resource

The `allowed_tenants` claim is registered as an `IdentityResource` in `DefaultConfigurationCreatorService.CreateIdentityResources()`. This makes it available in **ID tokens** (not just access tokens) when the `allowed_tenants` scope is requested. Used by Grafana's `org_attribute_path` for automatic organization mapping.

## Multi-Tenant Auth Scheme Isolation

External identity provider schemes (Google, Microsoft, Azure Entra ID, Facebook, OpenLDAP, Microsoft AD) are registered in the singleton `IAuthenticationSchemeProvider` with tenant-prefixed names: `{tenantId}:{providerName}`. This ensures all tenants' schemes coexist without conflicts.

- **`DynamicAuthSchemeService`**: Uses `ISystemContext.FindTenantRepositoryAsync(tenantId)` to load providers directly from any tenant's database (bypassing the HTTP-scoped `IOctoIdentityProviderStore`). Only removes/adds schemes for the specified tenant prefix.
- **`DynamicAuthSchemeServiceInitializer`**: At startup, registers schemes for the system tenant and all child tenants (same pattern as `DefaultConfigurationInitializationService`).
- **`AuthApiController`**: Filters schemes by tenant prefix (`{tenantId}:`) in `GetLoginContext` and `GetExternalProviders` endpoints. The full prefixed scheme name is passed to the frontend and back for challenge/login calls.
- **`IdentityProviderUpdateConsumer`**: Runtime reconfiguration only affects the specific tenant's schemes.

## OAuth Grant Storage (per tenant)

OAuth grants (authorization codes, refresh tokens, device codes, remembered consents) are stored **per tenant** in the new CK types `RtOAuthAuthorization`/`RtOAuthToken` via `OpenIddictAuthorizationStore`/`OpenIddictTokenStore` (System.Identity-2.12.0, migration 21→22). Grants are NOT centralized — the old "Centralized Grant Storage" design (system-tenant `RtPersistedGrant` with tenant id in `Description` and a SHA-256 hash fallback) was already stale since AB#1586 and is fully gone with the OpenIddict migration.

Because grants live per tenant, the `/connect/token` request must be wired to the right tenant before the store is consulted — that is `OidcTenantResolutionMiddleware`'s job (see Token Endpoint Tenant Resolution below). Access tokens are plain JWTs and get **no DB entry**. `TokenCleanupHostService` sweeps expired sessions, OAuth token entries, and legacy grants for the system tenant plus all child tenants.

## Pushed Authorization Request (PAR) Tenant Resolution

When backend OIDC clients (built on `Microsoft.AspNetCore.Authentication.OpenIdConnect` .NET 9+) authenticate, they automatically use **PAR (RFC 9126)** if the IdP advertises a `pushed_authorization_request_endpoint` — which OpenIddict does (as Duende did before). This means the authorization parameters (including `acr_values=tenant:{tenantId}`) are POSTed to `/connect/par`, and the subsequent browser redirect to `/connect/authorize` contains only `request_uri=urn:ietf:params:oauth:request_uri:...` — no `acr_values` on the URL.

`OidcTenantResolutionMiddleware` handles this in two stages (AB#7892, no process-local state):
1. On `POST /connect/par`, it reads `acr_values` from the form body and marks the issued `request_uri` in the JSON response with the tenant (`urn:ietf:params:oauth:request_uri:{tenantId}:{reference}`; a scope-only PAR carries `tenant_scope.{scopeTenantId}` instead, AB#5311)
2. On `GET /connect/authorize?request_uri=...`, it reads the tenant from the marker and removes the marker from the query before OpenIddict sees it; fallback query-string `acr_values`

Without this, every PAR-using client would land on `/tenant-discovery` because the URL no longer carries `acr_values`.

## Token Endpoint Tenant Resolution

The `/connect/token` endpoint has no `{tenantId}` route segment. To ensure `OctoUserStore`, `ClientStore`, and other per-tenant stores use the correct tenant database, `OidcTenantResolutionMiddleware` resolves the tenant per grant type. All capture stages work against OpenIddict responses (golden-verified):

**No process-local state — safe with several replicas and across restarts (AB#7891, AB#7892).** Every value a later
request sends back carries its tenant (`OidcTenantMarker`, `{tenantId}:{value}`): the middleware marks it on the response
that hands it out and strips the marker from the request before OpenIddict reads the form. The marker is not signed on
purpose — it only selects the tenant token store; a changed marker points to a store without the value (`invalid_grant`).
Nothing extra is stored, so no mapping outlives its token. Rationale per entry type: code comment at the top of
`OidcTenantResolutionMiddleware` and `docs/authentication.md` ("OIDC Endpoint Tenant Resolution").

**Authorization codes:** marked on the `/connect/authorize` response — `Location` query or fragment
(`response_mode=query`/`fragment`) or the hidden form field (`response_mode=form_post`, e.g. the Asset Repository GraphQL
Playground); on `/connect/token` with `grant_type=authorization_code` the tenant comes from the marker. An unmarked code
(issued before AB#7892) uses the system tenant — before AB#7892 a missing map entry on a second replica made the client
lookup run in the system tenant: `401 invalid_client` and a login loop for sub-tenant clients (test-2, 2026-11-12).

**Refresh tokens:** marked in every `/connect/token` response that carries one (rotated tokens too). On refresh the marker
wins over `acr_values` (it names the store the token lives in); an unmarked token falls back to `acr_values`, else the
system tenant. `/connect/revocation` and `/connect/introspect` strip the marker of the `token` field and use its tenant.

**Device flow (AB#7891):** the `device_code` carries the tenant marker; `/connect/deviceverification` gets the tenant hint
from the device page (`acr_values=tenant:{tenantId}`). The `verification_uri` in device authorization responses is
rewritten to the SPA page `/{tenant}/device` with `?userCode=`.

**`client_credentials` and token exchange:** `acr_values=tenant:{tenantId}` from the form body — required.

## Per-Tenant Cookie Scoping

Auth cookies are scoped per tenant via `TenantCookieManager` (`src/IdentityServices/Cookies/TenantCookieManager.cs`). This prevents cross-tenant session leakage by appending `.{tenantId}` to cookie names (e.g., `.AspNetCore.Identity.Application.sbeg`).

Key components:
- **`OctoAuthSchemes`** (`src/Authentication/`): the cookie schemes — `Identity.Application` (tenant-scoped by `TenantCookieManager`) and `Identity.External`. The Duende `idsrv` / `idsrv.session` / `idsrv.external` cookies no longer exist.
- **`TenantCookieManager`**: Custom `ICookieManager` that scopes the `Identity.Application` cookie per tenant
- **`OidcTenantResolutionMiddleware`**: Resolves tenant for `/connect/*` OIDC endpoints from `acr_values`, `id_token_hint`, or the tenant marker of codes, refresh tokens and PAR `request_uri`s (`OidcTenantMarker`, no process-local state, AB#7892)
- **`OctoTokenClaimsService`**: Adds `tenant_id` and `allowed_tenants` claims to tokens (used by endsession for cookie resolution and by backend middleware for tenant authorization)

See `docs/authentication.md` for detailed architecture and edge cases.

## Multi-Tenant Token Validation

Access tokens include `allowed_tenants` claims listing all tenants a user may access. Backend middleware validates the route tenant against these claims.

Key components:
- **`IAllowedTenantsResolver`** / **`AllowedTenantsResolver`** (`IdentityServerPersistence/Services/`): Resolves allowed tenants at token issuance time: the login tenant, the home tenants a shadow user's `xt_{home}_{name}` chain unwinds to, and every descendant reachable through cross-tenant user mappings (BFS that follows the xt_ chain tier by tier). It does **not** add ancestors by walking the `OctoTenantIdentityProvider` graph (AB#5170): a provider says where a tenant delegates authentication to, not that its users exist up there, and the blanket walk offered a locally created operating-tenant user the management tenant and the platform root — in `allowed_tenants`, the Studio switcher and the email-first tenant discovery — where no account of theirs exists and the switch gate refuses them. Pinned by `tests/IdentityServices.IntegrationTests/Persistence/AllowedTenantsResolverIntegrationTests.cs`
- **`ITenantRegistry`** / **`TenantRegistry`** (`IdentityServerPersistence/Services/`, AB#6393): cached tenant registry (id → `OctoTenant`, 45 s `IMemoryCache`, one re-read at most every 5 s on an unknown id) that opens tenant repositories without I/O via `ISystemContext.GetRegisteredTenantRepository` — no existence probe, admin session or CK auto-import. Used by `AllowedTenantsResolver` and `CrossTenantAuthenticationService`. 🔴 An id that is not in the registry yields `null` (fail closed); never fall back to `FindTenantRepositoryAsync` for hot paths. The system tenant is not a registry entry and is handled separately.
- **`OctoTokenClaimsService`** (`IdentityServices/OpenIddict/`): Adds `allowed_tenants` claims to all issued tokens (replaces the former `UserProfileService`)
- **`TenantAuthorizationMiddleware`** (`octo-common-services`): Validates route tenant against `allowed_tenants` claims; registered after `UseAuthorization()` in all backend services

The resolver algorithm: (1) always includes the login tenant; (2) for cross-tenant users (xt_), includes the home tenant; (3) walks up the ancestor chain from the login tenant via `RtOctoTenantIdentityProvider.ParentTenantId`; (4) BFS down through descendant tenants, checking `ExternalTenantUserMapping` by `SourceTenantId` + `SourceUserName` and following the `xt_{parentTenantId}_{parentUsername}` naming chain through each tier. This ensures cascading tenants (e.g., `octosystem → meshtest → subtenant1`) include both ancestors and descendants in `allowed_tenants`.

See `docs/authentication.md` § "Multi-Tenant Token Validation" for full architecture details.
