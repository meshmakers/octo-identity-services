# Changelog

Notable changes of the OctoMesh identity services. The CK model `System.Identity` keeps its own changelog in
`src/Persistence.IdentityCkModel/ConstructionKit/`.

## Unreleased

### Deprecated

- **Identity wave 1 of the REST user endpoints (AB#8415).** `PUT users/{userName}/roles`,
  `PUT`/`DELETE users/{userName}/roles/{roleName}` and `POST users/{userName}/merge` are deprecated in favour of the methods
  `User.SetRoles`, `User.AddRole`, `User.RemoveRole` and `User.Merge` (GraphQL `systemIdentityUsers { … }`). Every response
  carries `Link: <method documentation>; rel="deprecation"`, the OpenAPI operations are `deprecated: true` and every call is
  counted on `octo.rest.deprecated.calls` (endpoint template, client id, status class). The dates follow Gerald's rule
  (2026-11-07) and are **set at rollout**, not in this release: `Deprecation` is sent once
  `RestDeprecation:Waves:IdentityUsers1:Since` (Helm `restDeprecation.waves.IdentityUsers1.since`) is set to the delivery day
  of the release that contains this change; `Sunset` once `…:Sunset` is set to one week after that release runs on both
  prod-1 and prod-2. The dates are entered here and on the deprecated-endpoints page when they are set. Behaviour, routes,
  bodies and status codes are unchanged. `POST users` and `POST users/ResetPassword` follow with AB#8418.

### Changed

- **One password-policy describer for every REST facade (AB#8415, follow-up of AB#8414).** `UsersController` rebuilds the
  `failedDetails` of a `PASSWORD_POLICY_VIOLATION` with `PasswordPolicyErrorDescriber`, as the account page does; codes and
  descriptions are unchanged.

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

- **Cleanup of rights-less `xt_` shadow users (AB#8305).** `IdentityApiAuthorization:ShadowUserCleanup`
  (`OCTO_IDENTITYAPIAUTHORIZATION__SHADOWUSERCLEANUP`, Helm `services.identity.shadowUserCleanup`) = `Off` (default) /
  `DryRun` / `Apply`. Two minutes after the start, identity checks every `xt_` user of the system tenant and of every
  registered tenant once: a user without role, group, any other association, mapping of its name chain in the tenant,
  mapping elsewhere that uses it as source, and without password, two-factor, external login, user token, claim or OAuth
  token/authorization is a candidate. `DryRun` logs every candidate (tenant, rtId, user name, creation date), the skip
  reasons of every other `xt_` user and a summary per tenant, and writes nothing; `Apply` deletes the candidates through the
  identity user store with one `Identity.ShadowUserDeleted` event per user in the tenant's event log. Off reads nothing. A
  failing tenant does not stop the others, the run never blocks the start-up, and an Apply whose mapping read fails in any
  tenant runs as DryRun. Runbook in `docs/authentication.md`.
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
