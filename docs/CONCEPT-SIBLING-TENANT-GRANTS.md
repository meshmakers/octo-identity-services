# Concept — Sibling-tenant user lookup and grants (AB#8313)

Contract fixed by AB#8340 (first story of Feature AB#8313). Studio (AB#8314), octo-cli and the MCP server build against
it before the backend stories are finished. Changes to this contract after merge go through a comment on AB#8340 and on
AB#8314.

## 1. Goal and boundaries

An administrator of a **target tenant T** gives one user of a **source tenant S** access to T with chosen T groups,
where S is **not** a registry ancestor of T (typically a sibling under the same parent, e.g. a `meshmakers` user into a
customer tenant). T's administrator never sees S's user directory:

- one user is found by **exact** user name or **exact** e-mail — no listing, no prefix, substring or wildcard search;
- only when **S permits T** (allow-list kept in S, §6);
- every lookup and grant is audited in **both** tenants (§7).

Out of scope and unchanged:

- The ancestor flows under `adminProvisioning/{targetTenantId}` (`sourceUsers`, `withGroups`, `provisionCurrentUser`)
  stay as they are. Ancestry is decided by the tenant registry through `ICrossTenantAncestryGuard` (AB#8339, AB#8367,
  switch `IdentityApiAuthorization:CrossTenantAncestry` = `Warn`/`Enforce`).
- A sibling grant creates **no** `RtOctoTenantIdentityProvider` in T: T's login page does not offer "Login via S". The
  sibling user reaches T by tenant switch / token exchange from an S session (AB#8343).
- CK model: no change (`RtExternalTenantUserMapping` and the GroupMember association exist).

## 2. Routes

All routes of the grant are tenant-scoped in the **target tenant T** — `/{T}/identity/api/v1/…` — so Studio can offer
the action on T's own Users page. Route segments are case-insensitive; the SDK uses camelCase.

| Method and route (in T) | Purpose | Policy | Story |
|-------------------------|---------|--------|-------|
| `POST ExternalTenantUserMappings/sourceUserLookup` | find exactly one user of S | `IdentityUserAdministrationWritePolicy` | AB#8341 |
| `POST ExternalTenantUserMappings` | create the mapping, now with optional `groupIds` | `IdentityUserAdministrationWritePolicy` | AB#8343 |
| `GET ExternalTenantUserMappings` | list T's mappings (unchanged) | `IdentityUserAdministrationReadPolicy` | — |
| `GET ExternalTenantUserMappings/{rtId}` | one mapping (unchanged) | `IdentityUserAdministrationReadPolicy` | — |
| `PUT ExternalTenantUserMappings/{rtId}` | change the mapping's roles (unchanged) | `IdentityUserAdministrationWritePolicy` | — |
| `DELETE ExternalTenantUserMappings/{rtId}` | remove the grant (unchanged route; revocation §8) | `IdentityUserAdministrationWritePolicy` | AB#8344 |

Permission routes in the **source tenant S** (owned by AB#8345, §6):

| Method and route (in S) | Purpose | Policy |
|-------------------------|---------|--------|
| `GET CrossTenantGrantPermissions` | the target tenants S permits | S administrators only (`IdentityUserAdministrationWritePolicy` + `TenantManagement`) |
| `PUT CrossTenantGrantPermissions` | replace that list | S administrators only (same) |

**No endpoint lists the tenants that permit grants, and none lists the users of a non-ancestor tenant.** The
administrator of T types the source tenant id.

### 2.1 `POST ExternalTenantUserMappings/sourceUserLookup`

POST, not GET, so the identifier (often an e-mail address) never lands in access logs or proxy logs.

Request — `SourceUserLookupRequestDto`:

```json
{ "sourceTenantId": "meshmakers", "identifier": "alice@meshmakers.io" }
```

| Field | Type | Rule |
|-------|------|------|
| `sourceTenantId` | string | registry ancestor of T, or a tenant whose allow-list contains T |
| `identifier` | string | exact user name or exact e-mail of the user in S; compared case-insensitively against `NormalizedUserName` and `NormalizedEmail`, nothing else |

Answers:

| Status | Body | When |
|--------|------|------|
| `200` | `SourceUserLookupResultDto` | exactly one active user of S matches |
| `404` | problem, code `SourceUserNotFound` | **every** negative case (uniform-404 rule, §3) |
| `429` | problem, code `SourceUserLookupRateLimited`, body field `retryAfterSeconds`, header `Retry-After` | lookup limit exceeded (§4) |
| `400` | validation problem | body missing or not JSON. An empty, whitespace or missing `sourceTenantId`/`identifier` is a negative case and answers `404` (the DTO has no `[Required]` on purpose) |
| `401` / `403` | — | no token / caller lacks `IdentityUserAdministrationWritePolicy` in T |

Response — `SourceUserLookupResultDto` (no e-mail address, no phone number):

```json
{ "sourceTenantId": "meshmakers", "userId": "686a6215fd3e5972ff5693fd", "userName": "alice", "displayName": "Alice A." }
```

| Field | Type | Note |
|-------|------|------|
| `sourceTenantId` | string | echo of the request |
| `userId` | string | → `sourceUserId` of the mapping |
| `userName` | string | → `sourceUserName` of the mapping |
| `displayName` | string, nullable | for the dialog only |

A registry-ancestor user can be looked up through the same route, so the dialog needs one route for every source.

### 2.2 `POST ExternalTenantUserMappings` (extended)

Request — `CreateExternalTenantUserMappingDto` (existing fields unchanged, `groupIds` new and optional):

```json
{
  "sourceTenantId": "meshmakers",
  "sourceUserId": "686a6215fd3e5972ff5693fd",
  "sourceUserName": "alice",
  "roleIds": null,
  "groupIds": ["6a1b2c3d4e5f60718293a4b5"]
}
```

| Field | Type | Rule |
|-------|------|------|
| `sourceTenantId`, `sourceUserId`, `sourceUserName` | string, required | as today; take them from the lookup result |
| `roleIds` | string[], optional | as today (direct roles, role-change guard AB#7927) |
| `groupIds` | string[], optional | ids of **T** groups; the mapping becomes their member. `null`/absent = behaviour as before. The SDK does not send the field when it is `null`. |

Answers:

| Status | Body | When |
|--------|------|------|
| `201` | `ExternalTenantUserMappingDto` (`groupNames` filled) | stored |
| `400` | problem, code `UnknownGroup`, extension `unknownGroupIds` | a `groupIds` entry is no group of T; **nothing** is stored (no silent skip as in `adminProvisioning/{t}/withGroups`) |
| `403` | problem, code `SourceTenantNotPermitted` | S is no registry ancestor of T and S does not permit T, **or** the user does not exist / is blocked in S — one answer for all of these |
| `403` | problem from the role-change guard | the groups' or direct roles exceed what the caller may grant (AB#7927) |
| `409` | problem, code `ExternalTenantUserMappingAlreadyExists`, extension `existingMappingId` | a mapping for (S, user) exists (AB#6975, unchanged) |

For a registry-ancestor source the create behaves as today; `groupIds` works for ancestors too.

`GET`, `PUT` and `DELETE` keep their shape. `ExternalTenantUserMappingDto` already returns `sourceTenantId`,
`sourceUserName` and `groupNames`, which is what the granted-users list of AB#8314 shows.

## 3. Uniform-404 rule

The lookup answers **one** `404 SourceUserNotFound` with an identical body for every negative case:

- S does not exist;
- S exists but does not permit T (default for every tenant, §6);
- no user with that exact user name or e-mail;
- more than one user with that e-mail (never a list);
- the user is an `xt_` shadow user;
- the user is locked out or blocked by the sign-in rules (same check as AB#7855);
- the identifier is empty or whitespace;
- the identifier is not the complete user name or e-mail of a user: there is no prefix, substring, wildcard, regular
  expression or Mongo operator semantics. `ali` finds a user whose user name (or e-mail) is exactly `ali`, never
  `alice`; `alice*`, `.*` or `{"$ne": null}` are compared as plain text and match only a user with exactly that name.

Body (`application/problem+json`):

```json
{ "status": 404, "title": "Source user not found",
  "detail": "No user of the source tenant can be granted access with this identifier.",
  "code": "SourceUserNotFound" }
```

Implementation rules (AB#8341): no early return before the user query (the policy and tenant checks do not shorten the
path, so timing does not tell the cases apart); tests assert the identical body for each case; the existing
`SearchUsersInTenantAsync` (substring, empty search = first users) is **not** used for non-ancestors.

As built (AB#8341, `src/IdentityServerPersistence/Services/SourceTenantGrants/`):

- `SourceUserLookupService` reads the registry ancestors of T (`ICrossTenantAncestryGuard.GetRegistryAncestorsAsync` —
  the registry alone; the `Warn` mode of AB#8339 does **not** widen this route), asks `ISourceTenantGrantPolicy`, then
  always runs the same two equality queries (`NormalizedUserName == X`, `NormalizedEmail == X`, X = trimmed,
  upper-cased identifier, passed as a value, never as an operator). When S is unknown or empty the queries run against
  T's database and the result is discarded, so "tenant absent" costs the same database round trips as "user absent".
  Only then is the decision taken. Remaining, small differences: an unknown S may trigger the registry's throttled miss
  refresh (at most every 5 s per pod), and a found user costs the in-memory sign-in check.
- The default policy `DenyNonAncestorsSourceTenantGrantPolicy` answers `false` for every pair; registry ancestors are
  admitted before the policy is asked. AB#8345 replaces the registration (`TryAddScoped`).
- A policy that throws counts as "not permitted"; a read error of S counts as "no user"; both answer the uniform `404`.
- Logs carry caller, T, S, the internal outcome and a 12-character SHA-256 prefix of the normalized identifier — never
  the identifier itself. The outcome is never part of the answer.
- Audit hook for AB#8342: `ISourceUserLookupAuditSink.RecordAsync(SourceUserLookupAuditEvent)` is called once per
  lookup (T, S, caller, hit/miss, whether S exists, user id and name of a hit; no identifier). Registered as
  `NoOpSourceUserLookupAuditSink` until AB#8342 replaces it; a failing sink is logged and never breaks the request.

Create (`403 SourceTenantNotPermitted`) follows the same idea: one answer for "S unknown", "S does not permit T" and
"user absent or blocked in S".

## 4. Rate limit

Lookups are limited **per caller and target tenant** (key: the caller's subject, or the client id of a service token,
+ T), default **20 lookups per 10 minutes**, sliding window, configurable: `Identity:SourceUserLookupRateLimit` with
`Enabled`, `PermitLimit` and `Window` (documented in `configuration.md`). The limit is checked after authorization and
before the lookup; `retryAfterSeconds` is the exact time until the oldest counted lookup leaves the window (at least 1). Over the limit: `429` with problem code
`SourceUserLookupRateLimited`, the wait time in seconds both as the `Retry-After` header and as the integer body field
`retryAfterSeconds` (same value). The body field exists because Studio calls the identity API cross-origin and the CORS
policy exposes no response headers, so a browser cannot read `Retry-After`; clients read `retryAfterSeconds`.

```json
{ "status": 429, "title": "Too many lookups",
  "detail": "Too many source user lookups. Try again later.",
  "code": "SourceUserLookupRateLimited", "retryAfterSeconds": 240 }
```

Hits and misses count alike. The limit is kept in memory per pod, like the sign-in
limits.

## 5. Problem codes

All error answers are RFC 9457 `application/problem+json`. Clients branch on the `code` extension — language-neutral
and stable; title and detail are English text for humans. The codes are PascalCase like the existing ones of this API
(`ExternalTenantUserMappingAlreadyExists`, `CrossTenantSourceNotAncestor`); the SDK carries them as constants in
`Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors.CrossTenantGrantProblemCodes`.

| Code | Status | Route | Extensions |
|------|--------|-------|------------|
| `SourceUserNotFound` | 404 | lookup | — |
| `SourceUserLookupRateLimited` | 429 | lookup | `retryAfterSeconds` (integer, same value as the `Retry-After` header) |
| `SourceTenantNotPermitted` | 403 | create | — |
| `UnknownGroup` | 400 | create | `unknownGroupIds` |
| `ExternalTenantUserMappingAlreadyExists` | 409 | create (existing, AB#6975) | `existingMappingId` |
| `CrossTenantSourceNotAncestor` | 403 | `adminProvisioning` writes only (existing, AB#8339) | — |

## 6. Source-tenant permission (AB#8345)

Decided by Gerald on 2026-11-06 (option A): **S keeps an allow-list of target tenants.** Per-grant consent is not
built.

- `GET/PUT /{S}/identity/api/v1/CrossTenantGrantPermissions`, body `{ "targetTenantIds": ["customer-a", "customer-b"] }`
  (DTO and storage fixed by AB#8345; additive only if a CK change is needed).
- Default: empty list = no tenant may look up or grant S's users. Existing tenants are unchanged by the upgrade.
- Only S administrators read or change the list; T administrators get `403`. No endpoint reveals which tenants S
  permits — a non-permitted T sees the same `404`/`403` as for a non-existent tenant.
- Every change is audited in S (§7).
- The backend stories build against `ISourceTenantGrantPolicy.IsPermittedAsync(sourceTenantId, targetTenantId)`. Until
  AB#8345 ships, the default implementation **denies every non-ancestor**: lookups of sibling users answer `404`,
  sibling creates `403`. Tests use a permitting test policy.
- S removes T from the list: lookups and new grants from T stop at once; existing grants are refused at the next token
  exchange (§8).

As built (AB#8345, `src/IdentityServerPersistence/Services/SourceTenantGrants/`):

- Storage: no CK change. The list is the tenant configuration row `CrossTenantGrantPermissions` (a
  `System/TenantConfiguration` entity, the storage of `ITenantContext.Get/SetConfigurationAsync`) in **S's own
  database**, value `{ "targetTenantIds": [...], "changedAtUtc": ..., "changedBy": ... }`. A tenant without the row —
  every tenant before the upgrade — has an empty list. `CrossTenantGrantPermissionStore` reads and writes it.
- `AllowListSourceTenantGrantPolicy` (registered `TryAddScoped`, replaces `DenyNonAncestorsSourceTenantGrantPolicy`)
  answers `true` exactly when T is on S's list (case-insensitive). Read on every call, no cache, so a removal acts with
  the next request. Fails closed without throwing: unknown S, unreadable registry or unreadable row → `false`. For an
  unknown S the same row read runs against T's database and is discarded, so "S absent" costs the same round trip as
  "S does not permit T". Directional: T on S's list never lets S look up T's users. A tenant on its own list does not
  count.
- Routes: `GET/PUT {S}/v1/CrossTenantGrantPermissions`, policy `IdentityCrossTenantGrantPermissionsPolicy` — scope
  `octo_api`, roles `UserManagement` **and** `TenantManagement`, and a token issued for S (the own-tenant check is
  unconditional, also under `RoleEnforcement=Warn`, so neither a T administrator nor a parent administrator with a
  parent-tenant token reads the list; a parent administrator switches into S first). `PUT` replaces the whole list;
  validation (`400`, nothing written): list required, no empty entry, valid tenant id format (≤ 64 ASCII letters,
  digits, `-`, `_`), at most 200 entries, not S itself. Entries are **not** checked for existence, so the route is no
  tenant directory. Each change is logged (`added`, `removed`, caller); every change (added or removed entries) is also written into S's event log as `Identity.CrossTenantGrantPermissionsChanged` (§7); a `PUT` that leaves the list unchanged writes no event.
- The lookup route (AB#8341) uses the policy now; mapping create (`403 SourceTenantNotPermitted`, AB#8343) and the
  exchange gate and revocation (AB#8343, AB#8344) ask the same `ISourceTenantGrantPolicy`.

## 7. Audit events (AB#8342)

Written through `IIdentityAuditService` into the runtime event log of the tenant(s) named (source
`RtEventSourcesEnum.IdentityService`). Fields: event name, actor (caller tenant + user name), source tenant, target
tenant, mapping id, group names. Never the looked-up identifier of a miss in clear, never tokens or passwords.

| Event (= event category) | Written to |
|-------|-----------|
| `Identity.CrossTenantLookup` (hit / miss) | T and S; a miss for a non-existent S only in T |
| `Identity.CrossTenantGrantCreated` | T; S only when S is a registry ancestor of T or permits T (AB#8436) |
| `Identity.CrossTenantGrantChanged` (roles / groups) | T; S only when S is a registry ancestor of T or permits T (AB#8436) |
| `Identity.CrossTenantGrantRemoved` | T; S only when S is a registry ancestor of T or permits T (AB#8436) |
| `Identity.CrossTenantFirstExchange` (shadow user created with roles) | T and S |
| `Identity.CrossTenantExchangeRefused` (exchange refused for a sibling source) | T and S |
| `Identity.CrossTenantGrantPermissionsChanged` (permission list changed, AB#8345) | S |

Grant events name S and the source user exactly as the administrator of T sent them. So that no tenant can place (or
flood) events in a foreign tenant's log, `RecordGrantAsync` writes into S only when S is a registry ancestor of T or
`ISourceTenantGrantPolicy` says S permits T; otherwise the event is recorded in T only (a failed decision counts as "not
permitted", AB#8436).

An audit write never breaks the request; a failure is logged. `docs/authentication.md` (section "Cross-Tenant Grant
Audit Events") lists the events and how an administrator reads them.

As built (AB#8342): the event name is the event **category** (dotted, platform convention); `LIKE
"Identity.CrossTenant*"` reads them all. The refused exchange has level Warning and is written only for a sibling source.
`Identity.CrossTenantGrantChanged` is written by the role `PUT`; the group route of AB#8343 calls the same recorder
(`ICrossTenantGrantAuditRecorder.RecordGrantAsync`). AB#8345 writes the permission-list event (constant
`CrossTenantGrantAuditEvents.GrantPermissionsChanged`) by calling `IIdentityAuditService.StoreInfoAsync(sourceTenantId, eventName, message, details)`. Grant events are
written for every mapping write through `ExternalTenantUserMappings` (also for an ancestor source); the ancestor flows under
`adminProvisioning` stay without them (§1). The first exchange is recorded for every source tenant.

## 8. Token exchange and revocation (AB#8343, AB#8344)

- Exchange gate (`CrossTenantAuthenticationService.ValidateCrossTenantAccessAsync`, used by `TenantExchangeProcessor`):
  when S is no registry ancestor of T, admit only if a mapping for (S, user) exists in T **and** the policy permits
  (S, T) **at exchange time**. AB#7855 (sign-in block), AB#8304 (decide, then create the `xt_` user) and "no refresh
  token on exchanged tokens" are unchanged.
- First exchange: the `xt_` shadow user gets exactly the roles of the mapping's groups plus its direct roles — nothing
  from S, nothing else in T.
- **Revocation**: the next exchange into T is refused with `access_denied` when the mapping is deleted, when S
  withdraws T from its allow-list, or when the mapping has **no effective role left** — its direct `roleIds` and the
  roles of all its groups taken together (removing one group or emptying one group's roles revokes only if nothing else
  still grants a role). A token already issued stays valid until its
  `exp` (exchanged tokens are short-lived and carry no refresh token; AB#8344 documents the lifetime in
  `docs/authentication.md`). No GroupMember / AssignedRole edge of a deleted mapping stays behind; re-granting the same
  user works without `409` and yields the new groups' roles only. The role-less `xt_` user left behind is removed by the
  cleanup of AB#8305.

## 9. Client flow (Studio AB#8314, octo-cli, MCP)

1. The administrator, signed in to T, enters the source tenant id and the exact user name or e-mail.
2. `POST ExternalTenantUserMappings/sourceUserLookup` → `200` shows `userName` / `displayName`; `404` shows one neutral
   message ("No user found that can be granted access"), never a reason; `429` shows "Too many lookups, try again
   in N minutes" from `retryAfterSeconds`.
3. The administrator chooses T groups → `POST ExternalTenantUserMappings` with `groupIds`.
4. The list of granted users is `GET ExternalTenantUserMappings` (source tenant, user, groups); removal is `DELETE`.

SDK (octo-sdk, `IIdentityServicesClient`, client's tenant = T):

| Method | Route |
|--------|-------|
| `Task<SourceUserLookupResultDto?> LookupSourceUser(SourceUserLookupRequestDto request)` | lookup; returns `null` for `404 SourceUserNotFound`, throws `ServiceClientResultException` otherwise (`429`, `403`, …) |
| `Task CreateExternalTenantUserMapping(CreateExternalTenantUserMappingDto mapping)` | create, `GroupIds` optional |
| `GetExternalTenantUserMappings`, `GetExternalTenantUserMapping`, `DeleteExternalTenantUserMapping` | unchanged |

Compatibility: an identity service without AB#8343 ignores `groupIds` (the mapping is stored without groups) and has no
lookup route (`404` without code — the SDK throws, it does not answer `null`). Clients send `groupIds` and call the
lookup only against identity services that contain AB#8341/AB#8343.

## 10. Stories

| Story | Part |
|-------|------|
| AB#8340 | this contract, SDK DTOs and client signatures |
| AB#8341 | lookup route, uniform 404, rate limit |
| AB#8342 | audit events in both tenants |
| AB#8343 | create with `groupIds`, exchange gate for sibling sources |
| AB#8344 | revocation at the next exchange |
| AB#8345 | allow-list in S, production `ISourceTenantGrantPolicy`, permission routes |
| AB#8314 | Studio dialog (Feature of Studio & UX) |
