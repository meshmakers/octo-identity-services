# Changelog

Notable changes of the OctoMesh identity services. The CK model `System.Identity` keeps its own changelog in
`src/Persistence.IdentityCkModel/ConstructionKit/`.

## Unreleased

### Fixed

- **Sign-in and token refresh work with several identity replicas and across restarts (AB#7892).** Authorization codes,
  refresh tokens and PAR `request_uri`s were mapped to their tenant in a static in-process dictionary. With two replicas
  (test-2, AB#8402) the token request of an app whose OIDC client lives in a sub-tenant (Energy Community) often hit the
  replica without the entry; the client was looked up in the system tenant and `POST /connect/token` answered
  `401 invalid_client`, the app looped back to tenant discovery. After a restart, clients refreshing without `acr_values`
  fell back to the system tenant the same way. Now every such value carries its tenant (`OidcTenantMarker`,
  `{tenantId}:{value}`; inside the URN for `request_uri`), like the device code since AB#7891: marked on the response,
  stripped before OpenIddict reads the request. The marker only selects the tenant token store, so a changed marker is
  rejected like an unknown value (`invalid_grant`). Nothing extra is stored; `TokenToTenantMap` is gone.
  `/connect/revocation` and `/connect/introspect` resolve the tenant of a marked refresh token too (before, revoking the
  refresh token of a sub-tenant public client without a bearer header failed with `invalid_client`).
  **Client impact:** none — codes, refresh tokens and `request_uri`s are opaque and passed back unchanged; their values
  are longer by the tenant prefix. Values issued before the update keep the old fallback (`acr_values`, else system
  tenant). **Operator note:** deploy with a single replica and the `Recreate` strategy first; enable more than one replica only
  after every pod runs this version (old pods reject marked values). A rollback below this version makes refresh tokens
  issued since the update unusable; those users sign in again.

### Added

- **Every pipeline service account holds `StreamDataReader` (AB#8581).** The asset repository gates stream-data reads on a
  StreamData role (AB#8559). The Communication Controller adds `StreamDataReader` to declarative service accounts on reconcile
  (AB#8563), but not to legacy accounts (created before CK 3.32.0, no `AssignedRoleNames`). Identity now grants the role to every
  `octo-pipeline-sa-*` client the same way it grants `FileManagement`: in the identity-data command that creates or touches the
  account, and at every tenant setup (identity start, tenant create, full tenant update). The grant is additive — a legacy account
  keeps every role it had — a declarative account holds the role once, only clients with the exact prefix are touched and only when
  the role is seeded. Both baseline roles now come from one list (`PipelineServiceAccountBaselineRoles`); the former
  `PipelineServiceAccountFileRoleGrant` / `PipelineServiceAccountFileRoleLock` are `PipelineServiceAccountRoleGrant` /
  `PipelineServiceAccountRoleLock`. The REST/CLI proof report of AB#6542 still covers `FileManagement` only.
  Known gap, unchanged from AB#6467 and now also for `StreamDataReader`: the client-id prefix is the only trust check, so a
  client administrator can obtain the baseline roles for a client it creates under the prefix without holding them (AB#8618).

  **Operator note:** the manual `octo-cli -c AddClientToRole … StreamDataReader` step for legacy pipeline service accounts before a
  tenant switches the stream-data gate to `Enforce` is **no longer needed**. Once identity with this change runs, the next identity
  start (or tenant setup, or workload deploy) grants the role.

### Deprecated

- **Identity wave 1 of the REST user endpoints (AB#8415).** `PUT users/{userName}/roles`,
  `PUT`/`DELETE users/{userName}/roles/{roleName}` and `POST users/{userName}/merge` are deprecated in favour of the methods
  `User.SetRoles`, `User.AddRole`, `User.RemoveRole` and `User.Merge` (GraphQL `systemIdentityUsers { … }`). Every response
  carries `Link: <method documentation>; rel="deprecation"`, the OpenAPI operations are `deprecated: true` and every call is
  counted on `octo.rest.deprecated.calls` (endpoint template, client id, status class). The dates are configuration, not code
  (`RestDeprecation:Waves:IdentityUsers1:Since|Sunset`, Helm `restDeprecation.waves.IdentityUsers1.since|sunset`): **deprecated
  since 2026-11-08** (first production delivery of r3.5.68, the first release with this change), **sunset date to be announced**
  (Gerald 2026-11-11: no fixed compatibility window; the sunset date is decided once the migration functions are implemented, so
  no `Sunset` value is configured and no `Sunset` header is sent until then). `since` is set for all clusters in
  `octo-mesh-deployment` and takes effect with each cluster's next deploy; until then a cluster sends no `Deprecation` header. The endpoints are removed only after the sunset and only when the call counts show that
  the clients have switched. Behaviour, routes, bodies and status codes are unchanged. `POST users` and
  `POST users/ResetPassword` are not part of this wave; they follow with AB#8418 in a wave of their own.

### Fixed

- **The self-grant refusal reads correctly for clients (AB#8583).** The `title` of the REST `403 self-grant` problem said
  "You cannot grant additional roles to your own user." also to client-credentials callers (AB#8569). It now reads "You cannot grant additional roles to yourself." for users and clients. The code `self-grant` and the method error
  (`METHOD_FORBIDDEN`, `reason=self-grant`) are unchanged.

- **`AddClientToGroup -cid <clientId>` works with the client id (AB#8571).** `PUT`/`DELETE {tenant}/v1/groups/{group}/members/clients/{client}`
  passed the value straight into an rtId parse, so the OAuth client id — what octo-cli documents and sends — answered `500`; only the client's
  rtId worked. Both now work: the rtId of an existing client wins, otherwise the value is looked up as client id (so a client id that looks like an
  rtId works too). An unknown client id or rtId answers `404` with a message instead of `500` and writes nothing. `DELETE` with the rtId of a deleted client still removes its leftover edge. `Group.AddMember` / `Group.RemoveMember` resolve clients the same
  way (shared `GroupClientMemberResolver`). The role change guard judges the resolved client as before.

- **A client can no longer grant roles to itself (AB#8569).** The `self-grant` rule of the role change guard only knew user sessions, so a
  client-credentials client holding `UserManagement` (e.g. through `TenantOwners`) could add itself to a group carrying an app role such as
  `EnergyCommunityOperators` and gain `EnergyCommunityManagement` with its own token. A client-credentials caller is now "self" for its own client,
  with the semantics of the user path: direct client roles (`PUT clients/{id}/roles`, `PUT clients/{id}/roles/{roleName}`), its own group membership
  (REST and `Group.AddMember`), a role added to a group its client is in, directly or through a parent group (REST and `Group.SetRoles`), and a group nested into
  such a group answer `403 self-grant` (`METHOD_FORBIDDEN`, `reason=self-grant`), with the same WARN log and `Identity.RoleChangeRefused` event. A user
  session that carries the client's id as `client_id` is not that client. Removing its own rights, grants to other principals (AB#8564), `role-not-held` for
  platform roles and service-internal provisioning over the bus are unchanged. A scratch-tenant creator client can no longer give itself an app role.

- **Tenant owners can assign the roles their tenant's blueprints seed (AB#8564).** The role change guard of AB#7914/AB#7927/AB#7928
  refused every built-in role the caller did not hold, so a tenant owner could not give a client or user `EnergyCommunityManagement`,
  `EnergyCommunityReporting`, `MeterReporter` or `MeshmakersAccounting`, neither directly nor through group membership or nesting
  (`403 role-not-held`). A caller holding `UserManagement` may now grant **app roles** (built-in roles of a blueprint other than
  `System.Identity.Bootstrap`) without holding them. **Platform roles**, the 17 roles of the Bootstrap seed, keep the protection; a group
  that carries both needs only its platform roles held. The platform set is read from the embedded Bootstrap blueprint (no hand-kept list;
  fail closed when it cannot be read). Callers without `UserManagement`, `self-grant`, `last-administrator` and the data-policy protection of
  AB#5859 are unchanged. Refusals are logged as before; an allowed app-role grant is logged at INFO with caller, target and roles.

### Changed

- **AB#8529** — the first tenant administrator of a tenant without the `TenantOwners` group (direct-role fallback of
  `UserManagementService.CreateAdminUserAsync`) also gets the role `DataModelManagement`, which the asset repository now
  requires for importing CK models, catalog imports, `FixAll`, blueprint install/update/uninstall and catalog refresh.
  `TenantOwners` already carries the role; no seed change.

- **The cross-tenant allow-list answers with the SDK's `CrossTenantGrantPermissionsDto` (AB#8521).** octo-sdk #102 (AB#8346)
  added the DTO to `Communication.Contracts`; the controller-local class of the same name made the build fail (CS0104). The
  `GET`/`PUT CrossTenantGrantPermissions` answers now use the SDK type; the `PUT` body binds to the server-side
  `CrossTenantGrantPermissionsPutBody`, because the SDK DTO defaults the list to `[]` and a body without
  `targetTenantIds` must stay a `400` instead of clearing the list. JSON, ETag/`If-Match`, `412` and `428` are unchanged.
- **One password-policy describer for every REST facade (AB#8415, follow-up of AB#8414).** `UsersController` rebuilds the
  `failedDetails` of a `PASSWORD_POLICY_VIOLATION` with `PasswordPolicyErrorDescriber`, as the account page does; codes and
  descriptions are unchanged.

- **Device-code sign-in works across identity replicas and restarts (AB#7891).** The device flow no longer keeps a
  `device_code`/`user_code` → tenant mapping in process memory (the static `TokenToTenantMap` of
  `OidcTenantResolutionMiddleware`). The device page sends its tenant as `acr_values=tenant:{tenantId}` to
  `/connect/deviceverification`, and the issued `device_code` carries its tenant (`{tenantId}:{code}`), which the
  middleware strips again on `/connect/token`. Before, every second redeem on test-2 (two identity replicas) failed with
  `invalid_grant` and the Allow page could land in the system tenant. No change for octo-cli/octo-sdk (the device code
  is opaque to clients); device codes issued by an older identity before the rollout fail once and need a new
  `login -i`. Documented in `docs/authentication.md` (Device Authorization Flow, note 5).

- **Removing a sibling-tenant grant cuts the user's access at the next token exchange (AB#8344).** For a source tenant
  that is no registry ancestor of T, the exchange gate now also requires that the mapping itself grants a role in T (its
  direct roles or its groups' roles); a role attached directly to the `xt_` shadow user no longer keeps a sibling user in T
  once the mapping is deleted or grants nothing. The next exchange after a deleted grant, a removed last group or emptied
  group roles answers `access_denied` with the prefix `tenant_not_provisioned` (before: `unauthorized_client` after a
  deletion, or admitted through a direct role of the shadow user); a withdrawn permission keeps `grant_not_permitted`. Each
  refusal is audited in T and S (`Identity.CrossTenantExchangeRefused`, `reason`); its description tells the user that an
  administrator of T must grant access again (not `ProvisionCurrentUser -ttid`, which serves ancestor sources only). A direct
  `roleIds` entry of a deleted role grants nothing. Already issued exchanged tokens stay
  valid until `exp` (no refresh token; the client's `AccessTokenLifetime`, default 1 h). Ancestor sources are unchanged.
  See `docs/authentication.md`, "Removing a Sibling-Tenant Grant".

- **REST role and merge endpoints run the `User` methods (AB#8412).** `PUT users/{userName}/roles`,
  `PUT`/`DELETE users/{userName}/roles/{roleName}` and `POST users/{userName}/merge` are facades of `User.SetRoles-1`,
  `User.AddRole-1`, `User.RemoveRole-1` and `User.Merge-1`: the controller resolves the user (and the role ids / names) and
  calls the method in-process through the dispatcher (AB#8411, nothing on the bus); the role change guard, the role
  difference and the merge exist once, in the handlers. Routes, request and response shapes and status codes are unchanged.
  Behaviour changes for REST callers:
  - every call writes one `Identity.Method` audit event (success and refusal; `rolesBefore`/`rolesAfter`, merge details);
    a guard refusal keeps the `Identity.RoleChangeRefused` record and the WARN log of AB#7914;
  - merge: the caller needs write access to the source user (data permissions, AB#7035) — not readable answers `404`
    "Source user … not found", not writable `403` problem `METHOD_FORBIDDEN` (only with enforcing data-permission policies);
  - merge: a failed login or delete step answers `400` as before, but the `failedDetails` carry only the error `code`
    (no `description`); an unexpected failure answers `500` with the message "Merging the users failed." instead of the
    exception text; the source user name is trimmed;
  - role endpoints: an unexpected failure answers `500` problem details (`METHOD_HANDLER_FAILED`);
  - with `IdentityApiAuthorization:RoleEnforcement=Warn` (not the default) a caller without `UserManagement` is now
    refused (`403`) by the method instead of being let through with a warning.
  The endpoints work whatever `Methods:Identity:EnablePasswordMethods` says (no secret). See `CLAUDE.md`, section
  "REST facades of the role and merge endpoints (AB#8412)", for the parity table.

- **REST user create and administrator password reset run the `User` methods (AB#8413).** `POST users` and
  `POST users/ResetPassword` are facades of `User.CreateUser-1` and `User.ResetPassword-1`, called in-process through the
  dispatcher. With `Methods:Identity:EnablePasswordMethods=false` (the production gate until B0) the two handlers are registered
  local only (not announced, no queue): REST keeps working, GraphQL still answers `METHOD_HANDLER_NOT_AVAILABLE`, and no password
  reaches the broker. The switch now governs the bus offering only (`docs/configuration.md`). Routes, request and response shapes and
  status codes are unchanged; the query-parameter form of ResetPassword stays refused (AB#8008). Behaviour changes for REST callers:
  - **an administrator reset lifts the lockout** (`LockoutEnd` cleared, `AccessFailedCount` 0), as the method does;
  - every call writes one `Identity.Method` audit event (create: `userName`, `withPassword`; reset: `lockoutLifted`); the
    "Password changed" log line of a reset names the path `MethodResetPassword` (was `AdminResetPassword`) and the acting user
    by the user name of its `sub` (a client-credentials caller stays `client <id>`);
  - create trims the user name and the e-mail address and stores a blank e-mail as `null`;
  - an unexpected failure answers `500` with "Creation of user failed." / "Reset of password failed." instead of the exception text;
  - with `IdentityApiAuthorization:RoleEnforcement=Warn` (not the default) a caller without `UserManagement` is now refused (`403`);
  - create with `resetPasswordOnLogin: true`: the flag is a second write after the method stored the user; when that write fails the
    endpoint answers `500` "The user was created, but ResetPasswordOnLogin could not be set." instead of `200` (the user exists without
    the flag; CodeRabbit follow-up of #269).
  The password-reset notification is still sent once per reset (by the facade until AB#7775 moves it into the method). See
  `CLAUDE.md`, section "REST facades of create user and password reset (AB#8413)", for the parity table.

- **Account pages change and set passwords through `User` methods; new `User.SetPassword-1` (AB#8414, System.Identity
  3.2.0).** `POST {tenant}/api/manage/change-password` and `POST {tenant}/api/manage/set-password` (the identity account SPA,
  session cookie, same origin) are facades of `User.ChangePassword-1` and the new `User.SetPassword-1` (self only, first local
  password of a user with external logins only; `PASSWORD_ALREADY_SET` when the user has one). They call the method in-process
  through `IIdentityMethodFacade.InvokeForAccountOwnerAsync`: the caller is the cookie's user with no role and the base scope
  `octo_api` only, so the declaration admits it through `allowSelf` on its own user and nothing else; a bearer token still never
  reaches these endpoints. With `Methods:Identity:EnablePasswordMethods=false` both handlers are registered local only (no queue,
  not announced): the account pages keep working, GraphQL answers `METHOD_HANDLER_NOT_AVAILABLE`, no password reaches the broker.
  The endpoints are facades without deprecation (Odin, 2026-11-07). Routes, request and response shapes and status codes are
  unchanged (`200` with `PasswordResultDto`; policy errors keep their descriptions). Behaviour changes for the account page:
  - change-password: a **wrong current password counts as a failed sign-in** (lockout counter, AB#7854) and a **locked-out user
    is refused** ("The account is locked out. Try again later."); before, neither was checked;
  - every call writes one `Identity.Method` audit event; the "Password changed" log line names the path `MethodChangePassword` /
    `MethodSetPassword` (was `ChangePassword` / `SetPassword`);
  - an unexpected failure (handler failed, timeout) answers `500` with `Success=false` and the generic message instead of an
    unhandled exception;
  - after a success the session cookie is re-issued from the stored user, i.e. with the new security stamp.
  See `CLAUDE.md`, section "Account pages run the password methods (AB#8414)".

### Added

- **Sibling-tenant users granted with chosen groups (AB#8343).** `POST {T}/v1/ExternalTenantUserMappings` takes optional
  `groupIds` (groups of T; an unknown id answers `400` problem `UnknownGroup` with `unknownGroupIds`, nothing stored) and
  checks the source: a registry ancestor of T, or a tenant whose allow-list permits T (AB#8345), and a user with that id
  must exist there (for a sibling also: no `xt_` user, may sign in). Every refusal answers one `403` problem
  `SourceTenantNotPermitted`. The stored user name — and the one in the grant audit events — is taken from the source
  tenant's user record, never from the request's `sourceUserName`. The groups' roles go through the role-change guard
  (AB#7927) like direct roles. No OctoTenant login provider is created. The tenant-switch gate
  (`ValidateCrossTenantAccessAsync`, token exchange and the other switch paths) admits a non-ancestor source only when T
  holds a mapping for the user and the source permits T at that moment; the first exchange creates the `xt_` user with
  exactly the mapping's group and direct roles. A withdrawn permission answers the exchange with `access_denied` /
  `grant_not_permitted`. **Behaviour change:** the route used to store any source tenant and user id unchecked; a mapping
  for an unrelated tenant or an unknown user is now refused (`403`), also under `CrossTenantAncestry=Warn`. Contract:
  `docs/CONCEPT-SIBLING-TENANT-GRANTS.md` §2.2, §8; `docs/authentication.md`, *Granting a Sibling-Tenant User With Groups*.

- **Cleanup of rights-less `xt_` shadow users (AB#8305).** `IdentityApiAuthorization:ShadowUserCleanup`
  (`OCTO_IDENTITYAPIAUTHORIZATION__SHADOWUSERCLEANUP`, Helm `services.identity.shadowUserCleanup`) = `Off` (default) /
  `DryRun` / `Apply`. Two minutes after the start, identity checks every `xt_` user of the system tenant and of every
  registered tenant once: a user without role, group, any other association, role-granting mapping of its name chain in
  the tenant, mapping elsewhere that uses it as source, and without password, two-factor, external login, user token or
  claim is a candidate. **Rule A:** a mapping keeps its user only when it grants a role (non-empty `MappedRoleIds`, or a
  member of a group that holds a role, nested groups included); an empty mapping is deleted together with its user, and
  OAuth tokens/authorizations (valid or not) keep nobody and are revoked with the user. `DryRun` logs every candidate
  (tenant, rtId, user name, creation date, empty mappings, OAuth counts), the skip reasons of every other `xt_` user and a
  summary per tenant, and writes nothing; `Apply` re-checks each candidate, revokes its tokens and authorizations, deletes
  its empty mappings and the user through the identity user store, with one `Identity.ShadowUserDeleted` event per user
  (naming the deleted mapping ids) in the tenant's event log. Off reads nothing. A
  failing tenant does not stop the others, the run never blocks the start-up, and an Apply whose mapping read fails in any
  tenant runs as DryRun. Runbook in `docs/authentication.md`.
  **Chained names:** an empty mapping is kept for a kept `xt_` user only when that user depends on it — its nearest tier
  (`xt_{SourceTenantId}_{SourceUserName}` = the whole name), or all of its chain mappings when it has neither a nearest-tier
  nor a role-granting mapping. Before, any kept user whose longer chain merely ended with the mapping's tier protected it,
  so `xt_accountingmanagement_xt_octosystem_<n>` in test-2 `gastrodemo`/`handelsdemo` was a candidate with
  `emptyMappings=none` (the kept `xt_karlplus_xt_accountingmanagement_…` matched the same mapping) and Apply would have
  left its empty mapping behind.
- **Concurrent edits of the cross-tenant allow-list cannot overwrite each other (AB#8432, security).**
  `GET`/`PUT CrossTenantGrantPermissions` answer an `ETag` (strong, derived from the normalized list only). A `PUT` with
  a stale `If-Match` answers `412` (problem code `CrossTenantGrantPermissionsChanged`, current tag in `ETag`) and writes
  nothing; read, compare and write run in one MongoDB transaction, so parallel `PUT`s with the same tag have exactly one
  winner. A `PUT` without `If-Match` answers `428` (`IfMatchRequired`) when the new option
  `Identity:CrossTenantGrantPermissions:RequireIfMatch` (env `OCTO_IDENTITY__CROSSTENANTGRANTPERMISSIONS__REQUIREIFMATCH`)
  is on; it is **off by default** during the client rollout, so Refinery Studio (AB#8430), octo-frontend-libraries and
  octo-sdk callers without `If-Match` keep working (last writer wins, as before). A `PUT` that leaves the list unchanged
  now writes nothing at all — not even `changedBy`/`changedAtUtc` (Ariadne's review of #275) — and records no event.
  The identity CORS policy exposes the `ETag` header to browser clients. Contract and rollout order:
  `docs/CONCEPT-SIBLING-TENANT-GRANTS.md` §6.1.

- **Source tenant decides which tenants may look up and grant its users (AB#8345, security).** `GET/PUT
  {S}/v1/CrossTenantGrantPermissions` (`{ "targetTenantIds": [...] }`) keeps the allow-list of a source tenant S;
  only S's administrators (`UserManagement` and `TenantManagement`, token issued for S —
  `IdentityCrossTenantGrantPermissionsPolicy`) read or change it, T's administrators get `403`. The new production
  `ISourceTenantGrantPolicy` (`AllowListSourceTenantGrantPolicy`) permits T exactly when T is on S's list, read on every
  call (removal acts with the next request) and fails closed. Every change is written into S's event log
  (`Identity.CrossTenantGrantPermissionsChanged`, AB#8342 audit API). Default for every tenant, existing ones included: empty
  list = nobody, so behaviour is unchanged after the upgrade. Stored as the tenant configuration row
  `CrossTenantGrantPermissions` in S — **no CK change**. A sibling lookup from a permitted T now finds the user; from
  any other tenant it answers the same `404` as for a non-existent tenant. See `docs/CONCEPT-SIBLING-TENANT-GRANTS.md`
  §6, `docs/authentication.md`, `docs/system-api.md`.
- **Cross-tenant grant audit events in both tenants (AB#8342, security).** Lookups, grant create / change / removal through
  `ExternalTenantUserMappings` and `AdminProvisioning`, the first token exchange into a tenant and refused exchanges from a sibling source are written
  into the runtime event log of the target tenant T **and** the source tenant S (categories `Identity.CrossTenantLookup`,
  `Identity.CrossTenantGrantCreated`, `…GrantChanged`, `…GrantRemoved`, `…FirstExchange`, `…ExchangeRefused`; a lookup naming
  a non-existent tenant only in T). Details name actor, source and target tenant, mapping id, groups and roles — never the
  identifier of a missed lookup, an e-mail address, a token or a password. `IIdentityAuditService` gains `StoreInfoAsync` /
  `StoreWarningAsync` for an explicit tenant; failure auditing is unchanged, and a failed audit write never breaks the request.
  Replaces the no-op `ISourceUserLookupAuditSink` of AB#8341. No CK change (existing `System.Notification` `category` /
  `details`). See `docs/authentication.md` → "Cross-Tenant Grant Audit Events".
- **Exact source user lookup for sibling-tenant grants (AB#8341, security).** `POST
  {T}/v1/ExternalTenantUserMappings/sourceUserLookup` (policy `IdentityUserAdministrationWritePolicy` in T) finds exactly
  one user of a source tenant S by exact user name or exact e-mail and returns id, user name and display name — no
  e-mail, no listing, no prefix/substring/wildcard/regex/operator semantics. Every negative case (S absent or empty,
  S neither a registry ancestor of T nor permitting T, no or more than one match, `xt_` shadow user, locked-out or
  sign-in-blocked user, empty identifier) answers the same `404` problem `SourceUserNotFound`; the queries run in every
  case, so the timing does not tell the cases apart. Until AB#8345 the permission decision is
  `DenyNonAncestorsSourceTenantGrantPolicy`: only registry ancestors are found. Limited per caller and target tenant by
  `Identity:SourceUserLookupRateLimit` (default 20 per 10 minutes) → `429` `SourceUserLookupRateLimited` with
  `Retry-After` and `retryAfterSeconds`. The identifier is never logged in clear; audit hook
  `ISourceUserLookupAuditSink` (no-op until AB#8342). See `docs/CONCEPT-SIBLING-TENANT-GRANTS.md`, `docs/configuration.md`.

### Documentation

- **Contract for sibling-tenant user lookup and grants (AB#8340).** `docs/CONCEPT-SIBLING-TENANT-GRANTS.md` fixes the
  routes, DTOs, problem codes, the uniform-404 rule, the lookup rate limit, the audit events and the revocation
  semantics for granting a user of a non-ancestor tenant access to a target tenant (Feature AB#8313). No behaviour
  change yet; the routes are implemented by AB#8341–AB#8345.

### Fixed

- **An interactive cross-tenant login or a tenant switch no longer writes an `ExternalTenantUserMapping` (AB#8439).**
  `AuthApiController.SignInCrossTenantUserAsync` (password login on the child tenant, `cross-tenant-login`, completion of
  the cross-tenant 2FA challenge) and `tenant-switch` created a bare mapping (no roles, no group) together with a new
  `xt_` shadow user, as the token exchange did until AB#7088. That mapping counted as explicit provisioning
  (`IsExplicitlyProvisionedAsync`), so `AllowSelfRegistration=false` let the person in on every later login once the
  shadow user was gone, and it kept the shadow user out of the AB#8305 cleanup. Now only an admin action (mapping API,
  `ProvisionCurrentUser`, Add Cross-Tenant User) creates a mapping. The tenant switch also applies the self-registration
  gate of the login before it creates a shadow user (it had none). Behaviour changes:
  - admin-created mappings and existing shadow users work as before (roles, groups, explicit provisioning);
  - a person who enters a child tenant only by self-registration (`AllowSelfRegistration=true`) gets the shadow user and
    the first-login groups, but no mapping; the child tenant therefore no longer appears in that person's
    `allowed_tenants` of the parent tenant (tenant picker, e-mail-first discovery) — a selection hint only, not an
    authorization; signing in to the child tenant directly is unchanged;
  - existing bare mappings stay until they are cleaned up (AB#8305).
  Tests: `CrossTenantLoginMappingTests` (integration), `CrossTenantLoginTests` (unit).

- **Grant audit events no longer reach a tenant that does not admit the target (AB#8436, security).** A mapping names its
  source tenant and user name as T's administrator sends them, so since AB#8342 an administrator of any tenant could write
  `Identity.CrossTenantGrantCreated` / `GrantChanged` / `GrantRemoved` events with free text into (and flood) the event log
  of any other registered tenant. The grant event now goes to S only when S is a registry ancestor of T or permits T
  (`ISourceTenantGrantPolicy`); otherwise it is recorded in T only. The mapping routes accept and refuse exactly as before
  (the create gate is AB#8343).
- **The read-only role-check script works through the Rancher proxy (AB#8431).**
  `scripts/identity-secret-management-role-check.sh` passed its JavaScript with `mongosh --eval` inside the `kubectl exec`
  request; through Rancher the 5.5 KB inventory step returned an nginx error page. The JavaScript now travels on stdin
  (after the password line) to a short in-pod runner that runs it from a private temporary file and removes it. Still
  read-only (`secondaryPreferred`, no token exchange); output and exit codes unchanged.
- **`User.ResetPassword` with a caller whose subject is not an object id (AB#8413).** The handler looked the acting user up by
  the `sub` claim and failed with `METHOD_HANDLER_FAILED`; it now skips the lookup, like `User.Merge`.
- **`User.Merge` with a caller whose subject is not an object id (AB#8412).** The handler looked the acting user up by the
  `sub` claim and failed with `METHOD_HANDLER_FAILED` when it was no object id; it now skips the lookup (the actor is
  logged with subject and client).
- **The login page no longer offers parent tenants the tenant registry does not back, and names a refused tenant switch
  (AB#8367).** Under `IdentityApiAuthorization:CrossTenantAncestry=Enforce` the login page lists only OctoTenant
  identity providers whose parent is a registry ancestor (under `Warn` all, with the AB#8339 warning).
  `POST auth/cross-tenant-token` answers a registry refusal with `403 problem+json`, code
  `CrossTenantSourceNotAncestor`, and the login page shows "This tenant does not accept sign-in from <source>" at once
  instead of a generic error after a detour through the source tenant's login. See `docs/authentication.md`.
- **The tenant registry, not a tenant's own identity providers, decides cross-tenant ancestry (AB#8339, security).**
  A tenant administrator could point an OctoTenant identity provider — or an admin-provisioning mapping, which creates
  one — at any tenant of the cluster and so read that tenant's user directory (`adminProvisioning/{target}/sourceUsers`)
  and let its users switch or log in. The provisioning source users, the tenant switch / token exchange gate and the
  cross-tenant password login now accept only tenants the tenant registry confirms as ancestors; the
  `xt_` sibling-shadow path is unchanged. Creating a mapping from a non-ancestor source answers `403`
  (`CrossTenantSourceNotAncestor`), an OctoTenant provider with a non-ancestor parent `400`
  (`OctoTenantParentNotAncestor`). **Staged:** new switch `IdentityApiAuthorization:CrossTenantAncestry`
  (`OCTO_IDENTITYAPIAUTHORIZATION__CROSSTENANTANCESTRY`, Helm `services.identity.crossTenantAncestry`) = `Warn`
  (default — behaviour as before, every provider-only ancestor logged with both tenant ids) / `Enforce`. Switch to
  `Enforce` per cluster after the inventory and the Warn log are reviewed. See `docs/authentication.md`,
  *Registry Decides Cross-Tenant Ancestry*.
- **Token exchange no longer leaves an `xt_` shadow user in a tenant it refuses (AB#8304).** The exchange
  now decides before it creates: a caller without a shadow user in the target tenant gets one only when the
  tenant's `ExternalTenantUserMapping`s grant it at least one role (directly or through the mapping's groups);
  otherwise it is refused with `access_denied` / `tenant_not_provisioned` and nothing is written. Existing
  shadow users behave as before. **Behaviour change:** a new cross-tenant user is let in through a mapping
  (Studio *Add Cross-Tenant User*, `CreateExternalTenantUserMapping`, `ProvisionCurrentUser -ttid`), no longer
  by granting a role to a left-over `xt_` user. Existing role-less `xt_` users are cleaned up separately
  (AB#8305). See `docs/authentication.md`.
- **Deleting an `AdminProvisioning` mapping no longer fails when its audit group read fails (AB#8437).**
  `DELETE AdminProvisioning/{targetTenantId}/{mappingRtId}` read the mapping's group names for the
  `Identity.CrossTenantGrantRemoved` event inside the delete transaction and unguarded, so a failing read answered `500`.
  The read now runs in a session of its own and is guarded: a failure is logged, the event is recorded without groups and
  the mapping is deleted. Concept §7 now states that the `AdminProvisioning` routes write grant events (as built in AB#8342).
