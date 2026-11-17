# Changelog

## 3.4.0 - 2026-11-17

_Required bump level: minor._

AB#9037, AB#9039: System.Identity 3.4.0 adds methods so the REST secret write endpoints and the data-policy enforcement switch become
facades of them: `Client.UpdateSecret-1`, `ApiResource.AddSecret-1`, `ApiResource.RemoveSecret-1`, `ApiResource.UpdateSecret-1` (roles
`TenantManagement`, `UserManagement`, `SecretManagement`; `secretValue` and the generated secret `sensitive`; errors `SECRET_NOT_FOUND`,
`CONCURRENT_CHANGE`) and `DataPolicy.SetEnforcementMode-1` (role `UserManagement`). `Client.AddSecret-1` and `Client.RemoveSecret-1` are
unchanged (an error code added to them would be a Major, row M8). Compile gate against the published 3.3.0: required level MINOR, minimum
version 3.4.0.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import,
no per-tenant step, **no FixAll**. No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

### Added

- Method 'Client-1/UpdateSecret-1' added _(minor — purely additive method)_
- Methods 'ApiResource-1/AddSecret-1', 'ApiResource-1/RemoveSecret-1', 'ApiResource-1/UpdateSecret-1' added _(minor — purely additive methods)_
- Method 'DataPolicy-1/SetEnforcementMode-1' added _(minor — purely additive method)_

## 3.3.0 - 2026-11-16

_Required bump level: minor._

System.Identity 3.3.0 adds methods so the REST group and client endpoints become facades of them:
`Group.AddChildGroup-1` and `Group.RemoveChildGroup-1` (nested groups; errors `CHILD_GROUP_NOT_FOUND`, `CHILD_GROUP_ALREADY_IN_GROUP`,
`CHILD_GROUP_NOT_IN_GROUP`, `GROUP_CYCLE`), and `Client.SetRoles-1`, `Client.AddRole-1`, `Client.RemoveRole-1`,
`Client.ApplyOverlayUris-1` and the static `Client.CleanOverlayEntries-1` (roles `TenantManagement` or `UserManagement`), with the result
records `ClientOverlayUrisResult`, `ClientOverlayCleanResult`, `ClientOverlayCleanEntry` and their `RuntimeState` attributes. The child
group methods are their own methods instead of a third `GroupMemberKind` value because an error code added to `Group.AddMember-1` would be
a Major. Compile gate against the published 3.2.0: required level MINOR, minimum version 3.3.0.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import,
no per-tenant step, **no FixAll**. No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

### Added

- Methods 'Group-1/AddChildGroup-1', 'Group-1/RemoveChildGroup-1' added _(minor — purely additive methods)_
- Methods 'Client-1/SetRoles-1', 'Client-1/AddRole-1', 'Client-1/RemoveRole-1', 'Client-1/ApplyOverlayUris-1', 'Client-1/CleanOverlayEntries-1' added _(minor — purely additive methods)_
- Records 'ClientOverlayUrisResult-1', 'ClientOverlayCleanResult-1', 'ClientOverlayCleanEntry-1' and their attributes added _(minor — purely additive)_

## 3.2.0 - 2026-11-07

_Required bump level: minor._

AB#8414: System.Identity 3.2.0 adds `User.SetPassword-1`: the signed-in user who has only external logins sets a first
local password (`allowSelf`, `newPassword` sensitive; errors `PASSWORD_POLICY_VIOLATION`, `PASSWORD_ALREADY_SET`,
`SHADOW_USER_PASSWORD_NOT_ALLOWED`). The identity account page `POST {tenant}/api/manage/set-password` is its facade. Like
every password method it is offered on the bus only with `Methods:Identity:EnablePasswordMethods=true`.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import,
no per-tenant step, **no FixAll** (AB#7998). No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

### Added

- Method 'User-1/SetPassword-1' added _(minor — purely additive method)_

## 3.1.1 - 2026-11-06

_Required bump level: patch (no structural change)._

AB#8095: System.Identity 3.1.1 drops the two `compatibility.acknowledge` entries of 3.1.0 (`Client-1/AddSecret-1` and
`Client-1/RemoveSecret-1`, roles widened by `SecretManagement`). An acknowledgement is valid for the one release that
introduces the change; against the published 3.1.0 it is stale (`OCTO-CK204`). The compiled model carries the
acknowledgements, so the model without them can no longer be published as 3.1.0 (`OCTO-CK205`, published versions are
immutable) - hence the patch. Types, attributes, records, methods, ids and defaults are identical to 3.1.0; no migration.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import,
no per-tenant step, **no FixAll** (AB#7998). Ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

## 3.1.0 - 2026-11-05

_Required bump level: minor._

AB#8095: System.Identity 3.1.0 admits `SecretManagement` on the method path. `Client.AddSecret-1` and
`Client.RemoveSecret-1` declare `authorization.roles: [ TenantManagement, UserManagement, SecretManagement ]`, so a caller
holding only `SecretManagement` passes the method gateway as it passes the REST path (AB#5861). Under
`SecretManagementRoleEnforcement=Enforce` the identity handlers still refuse `TenantManagement`/`UserManagement`-only callers
with `METHOD_FORBIDDEN`. Removing those two roles from the declaration is a Major (row M12) and waits for the next
System.Identity major.

Rollout: service-managed - ships inside the identity service with the regular identity release train and is applied on
identity startup in every tenant. No catalog import, no per-tenant step, **no FixAll** (AB#7998). Blueprint ranges
`System.Identity-[3.0.0,4.0)` (System.Identity.Bootstrap and dependents) stay satisfied.

### Changed

- Method 'Client-1/AddSecret-1': signature changed 'Instance (description?: String, expirationDate?: DateTime) -> String sensitive; errors [CLIENT_SECRET_NOT_REQUIRED]; authorization roles [TENANTMANAGEMENT, USERMANAGEMENT], allowSelf false, scopes []; timeout 15s, idempotent false' → 'Instance (description?: String, expirationDate?: DateTime) -> String sensitive; errors [CLIENT_SECRET_NOT_REQUIRED]; authorization roles [SECRETMANAGEMENT, TENANTMANAGEMENT, USERMANAGEMENT], allowSelf false, scopes []; timeout 15s, idempotent false' _(none — signature summary — the level comes from the method field changes)_
- Method 'Client-1/RemoveSecret-1': signature changed 'Instance (secretValue: String sensitive) -> none; errors [SECRET_NOT_FOUND]; authorization roles [TENANTMANAGEMENT, USERMANAGEMENT], allowSelf false, scopes []; timeout 15s, idempotent false' → 'Instance (secretValue: String sensitive) -> none; errors [SECRET_NOT_FOUND]; authorization roles [SECRETMANAGEMENT, TENANTMANAGEMENT, USERMANAGEMENT], allowSelf false, scopes []; timeout 15s, idempotent false' _(none — signature summary — the level comes from the method field changes)_

### Behavioural changes

- Method 'Client-1/AddSecret-1': roles changed 'TenantManagement, UserManagement' → 'SecretManagement, TenantManagement, UserManagement' _(minor — method authorization roles widened — looser; security: method access widened (row M12); requires acknowledge with a security reason (row M12) — requires acknowledge)_
- Method 'Client-1/RemoveSecret-1': roles changed 'TenantManagement, UserManagement' → 'SecretManagement, TenantManagement, UserManagement' _(minor — method authorization roles widened — looser; security: method access widened (row M12); requires acknowledge with a security reason (row M12) — requires acknowledge)_

### Acknowledged changes

- Method 'Client-1/AddSecret-1': roles changed 'TenantManagement, UserManagement' → 'SecretManagement, TenantManagement, UserManagement' _(minor — acknowledged: AB#8095: SecretManagement-only holders may now call AddSecret-1 (REST parity, AB#5861); under Enforce the handler still refuses TenantManagement/UserManagement-only callers)_
- Method 'Client-1/RemoveSecret-1': roles changed 'TenantManagement, UserManagement' → 'SecretManagement, TenantManagement, UserManagement' _(minor — acknowledged: AB#8095: SecretManagement-only holders may now call RemoveSecret-1 (REST parity, AB#5861); under Enforce the handler still refuses TenantManagement/UserManagement-only callers)_
