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
| `429` | problem, code `SourceUserLookupRateLimited`, header `Retry-After` | lookup limit exceeded (§4) |
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
- the identifier is empty, whitespace, a fragment (`ali`), a wildcard (`alice*`), a regular expression (`.*`) or a
  Mongo operator string — none of these has search semantics, they simply match nothing.

Body (`application/problem+json`):

```json
{ "status": 404, "title": "Source user not found",
  "detail": "No user of the source tenant can be granted access with this identifier.",
  "code": "SourceUserNotFound" }
```

Implementation rules (AB#8341): no early return before the user query (the policy and tenant checks do not shorten the
path, so timing does not tell the cases apart); tests assert the identical body for each case; the existing
`SearchUsersInTenantAsync` (substring, empty search = first users) is **not** used for non-ancestors.

Create (`403 SourceTenantNotPermitted`) follows the same idea: one answer for "S unknown", "S does not permit T" and
"user absent or blocked in S".

## 4. Rate limit

Lookups are limited **per caller and target tenant** (key: the caller's subject + T), default **20 lookups per 10
minutes**, sliding window, configurable (AB#8341 defines the option, e.g. `Identity:SourceUserLookupRateLimit` with
`PermitLimit` and `Window`, documented in `configuration.md`). Over the limit: `429`, `Retry-After` in seconds, problem
code `SourceUserLookupRateLimited`. Hits and misses count alike. The limit is kept in memory per pod, like the sign-in
limits.

## 5. Problem codes

All error answers are RFC 9457 `application/problem+json`. Clients branch on the `code` extension — language-neutral
and stable; title and detail are English text for humans. The codes are PascalCase like the existing ones of this API
(`ExternalTenantUserMappingAlreadyExists`, `CrossTenantSourceNotAncestor`); the SDK carries them as constants in
`Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors.CrossTenantGrantProblemCodes`.

| Code | Status | Route |
|------|--------|-------|
| `SourceUserNotFound` | 404 | lookup |
| `SourceUserLookupRateLimited` | 429 | lookup |
| `SourceTenantNotPermitted` | 403 | create |
| `UnknownGroup` | 400 | create |
| `ExternalTenantUserMappingAlreadyExists` | 409 | create (existing, AB#6975) |
| `CrossTenantSourceNotAncestor` | 403 | `adminProvisioning` writes only (existing, AB#8339) |

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

## 7. Audit events (AB#8342)

Written through `IIdentityAuditService` into the runtime event log of the tenant(s) named (source
`RtEventSourcesEnum.IdentityService`). Fields: event name, actor (caller tenant + user name), source tenant, target
tenant, mapping id, group names. Never the looked-up identifier of a miss in clear, never tokens or passwords.

| Event | Written to |
|-------|-----------|
| `CrossTenantLookup` (hit / miss) | T and S; a miss for a non-existent S only in T |
| `CrossTenantGrantCreated` | T and S |
| `CrossTenantGrantChanged` (groups) | T and S |
| `CrossTenantGrantRemoved` | T and S |
| `CrossTenantFirstExchange` (shadow user created with roles) | T and S |
| exchange refused for a sibling source | T and S |
| permission list changed (AB#8345) | S |

An audit write never breaks the request; a failure is logged. `docs/authentication.md` lists the events and how an
administrator reads them once AB#8342 is merged.

## 8. Token exchange and revocation (AB#8343, AB#8344)

- Exchange gate (`CrossTenantAuthenticationService.ValidateCrossTenantAccessAsync`, used by `TenantExchangeProcessor`):
  when S is no registry ancestor of T, admit only if a mapping for (S, user) exists in T **and** the policy permits
  (S, T) **at exchange time**. AB#7855 (sign-in block), AB#8304 (decide, then create the `xt_` user) and "no refresh
  token on exchanged tokens" are unchanged.
- First exchange: the `xt_` shadow user gets exactly the roles of the mapping's groups plus its direct roles — nothing
  from S, nothing else in T.
- **Revocation**: deleting the mapping, removing its last group, emptying the group's roles, or S withdrawing T from
  its allow-list refuses the next exchange into T with `access_denied`. A token already issued stays valid until its
  `exp` (exchanged tokens are short-lived and carry no refresh token; AB#8344 documents the lifetime in
  `docs/authentication.md`). No GroupMember / AssignedRole edge of a deleted mapping stays behind; re-granting the same
  user works without `409` and yields the new groups' roles only. The role-less `xt_` user left behind is removed by the
  cleanup of AB#8305.

## 9. Client flow (Studio AB#8314, octo-cli, MCP)

1. The administrator, signed in to T, enters the source tenant id and the exact user name or e-mail.
2. `POST ExternalTenantUserMappings/sourceUserLookup` → `200` shows `userName` / `displayName`; `404` shows one neutral
   message ("No user found that can be granted access"), never a reason; `429` shows "Too many lookups, try again
   later".
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
