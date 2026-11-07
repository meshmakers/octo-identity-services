# Changelog

Notable changes of the OctoMesh identity services. The CK model `System.Identity` keeps its own changelog in
`src/Persistence.IdentityCkModel/ConstructionKit/`.

## Unreleased

### Changed

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

### Added

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
