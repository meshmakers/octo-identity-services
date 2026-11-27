# Changelog

## 3.9.0 - 2026-11-27

_Required bump level: minor._

System.Identity 3.9.0 lets a client hand roles to its mirrors in the child tenants: the original carries the allow-list
`Client.MirrorRoleNames`, the tracking row `ClientMirror` records what identity assigned on each mirror, and `Client.SetMirrorRoles-1`
sets the list (with a dry run) and reconciles the mirrors. With the default empty list nothing changes for any existing client or
mirror. Compile gate against 3.8.0: required level MINOR, nothing to acknowledge.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import, no per-tenant
step, **no FixAll**. No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

### Added

- Optional attribute 'Client.MirrorRoleNames' (StringArray, TenantOwned) _(minor)_
- Optional attributes 'ClientMirror.ManagedRoleNames', 'ClientMirror.DeclinedRoleNames' (StringArray) and 'ClientMirror.ManagedMirrorRtId' (String) _(minor)_
- Method 'Client.SetMirrorRoles-1' (roles TenantManagement; errors MIRROR_ROLE_NOT_ALLOWED, CLIENT_NOT_CONFIDENTIAL, CONCURRENT_CHANGE) _(minor)_
- Records 'ClientMirrorRolesResult', 'ClientMirrorRoleTenantResult' and their RuntimeState member attributes _(minor)_

## 3.8.0 - 2026-11-18

_Required bump level: minor._

System.Identity 3.8.0 adds the create, update and delete methods of identity providers, e-mail domain group rules, data permissions
and data policies and clients, and the update and delete of external tenant user mappings, so the remaining REST CRUD endpoints of
identity administration become facades (generic writes of these types are refused since 3.6.0). No secret is readable or returned:
the client secret parameters are `sensitive` and write-only. Compile gate against 3.7.0: required level MINOR, nothing to acknowledge.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import, no per-tenant
step, **no FixAll**. No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

### Added

- Static method 'IdentityProvider.CreateIdentityProvider-1', methods 'IdentityProvider.UpdateIdentityProvider-1', 'IdentityProvider.DeleteIdentityProvider-1' _(minor)_
- Static method 'EmailDomainGroupRule.CreateEmailDomainGroupRule-1', methods 'EmailDomainGroupRule.UpdateEmailDomainGroupRule-1', 'EmailDomainGroupRule.DeleteEmailDomainGroupRule-1' _(minor)_
- Methods 'ExternalTenantUserMapping.UpdateMapping-1', 'ExternalTenantUserMapping.DeleteMapping-1' _(minor)_
- Static method 'DataPermission.CreateDataPermission-1', methods 'DataPermission.DeleteDataPermission-1', 'DataPermission.CreatePolicy-1', 'DataPolicy.DeleteDataPolicy-1' _(minor)_
- Static method 'Client.CreateClient-1', methods 'Client.UpdateClient-1', 'Client.DeleteClient-1' _(minor)_

## 3.7.0 - 2026-11-18

_Required bump level: minor._

System.Identity 3.7.0 adds the create, update and delete methods of roles, groups, API scopes and API resources, so their REST CRUD
endpoints become facades (generic writes of these types are refused since 3.6.0). Compile gate against 3.6.0: required level MINOR, nothing
to acknowledge; the acknowledgements of 3.6.0 are removed (valid for one release).

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import, no per-tenant
step, **no FixAll**. No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

### Added

- Static method 'Role.CreateRole-1', methods 'Role.UpdateRole-1', 'Role.DeleteRole-1' _(minor)_
- Static method 'Group.CreateGroup-1', methods 'Group.UpdateGroup-1', 'Group.DeleteGroup-1' _(minor)_
- Static method 'ApiScope.CreateApiScope-1', methods 'ApiScope.UpdateApiScope-1', 'ApiScope.DeleteApiScope-1' _(minor)_
- Static method 'ApiResource.CreateApiResource-1', methods 'ApiResource.UpdateApiResource-1', 'ApiResource.DeleteApiResource-1' _(minor)_

## 3.6.0 - 2026-11-17

_Required bump level: minor (acknowledged)._

System.Identity 3.6.0 restricts who writes identity data: every root type declares
`writeAccess: { channels: [ System.Identity/IdentityService ] }`, inherited by the resources (`ApiScope`, `ApiResource`,
`IdentityResource`) and the identity providers. No service opens a session on that channel, so only system sessions write these types
(the identity service's stores, blueprint seeds, the system path of `ImportRt`, tenant restores); every caller-scoped write - generic
GraphQL mutations, the caller path of `ImportRt`, adapter write nodes - is refused by the engine with message 144. Generic reads are
unchanged. Compile gate against the published 3.5.0: required level MINOR with 19 acknowledged changes (row T8), minimum version 3.6.0.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import,
no per-tenant step, **no FixAll**. No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied. **Gate:** the model carries
`minEngineVersion` 3.5.71; every service of the environment must run an engine >= 3.5.71 before this release reaches it.

### Changed

- `writeAccess` added to 'Client-1', 'ClientMirror-1', 'DataPermission-1', 'DataPolicy-1', 'DataProtectionKey-1',
  'EmailDomainGroupRule-1', 'ExternalTenantUserMapping-1', 'Group-1', 'IdentityProvider-1', 'OAuthAuthorization-1', 'OAuthToken-1',
  'Permission-1', 'PermissionRole-1', 'PersistedGrant-1', 'Resource-1', 'Role-1', 'ServerSideSession-1', 'User-1',
  'VerifiedExternalIdentifier-1' _(minor + acknowledge — security: write access restricted, row T8)_

## 3.5.0 - 2026-11-17

_Required bump level: minor._

System.Identity 3.5.0 adds methods so the REST client mirror and admin provisioning endpoints become facades of them:
`Client.ProvisionMirrors-1`, `Client.ProvisionMirrorInTenant-1`, `Client.RotateMirrorSecret-1` (result `sensitive`),
`Client.RemoveMirror-1` and `Client.SetMirrorAutoProvision-1` (roles `TenantManagement`, `UserManagement`; the rotation also
`SecretManagement`), and the static `ExternalTenantUserMapping.ProvisionAdmin-1`, `ProvisionAdminWithGroups-1`,
`ProvisionCurrentUser-1`, `RemoveAdminProvisioning-1` (roles `TenantManagement`, `UserManagement`) and `CreateMapping-1` (role
`UserManagement`), with the result records `ClientMirrorBackfillResult`, `ClientMirrorProvisionResult`, `AdminProvisioningResult`
and their `RuntimeState` attributes. `CreateMapping-1` does not set `replacesGenericCreate`: on the existing type
`ExternalTenantUserMapping` the flag is a Major (row M16); it is planned for the next major. Compile gate against the published
3.4.0: required level MINOR, minimum version 3.5.0.

Rollout: service-managed - ships inside the identity service with the regular identity release train. No catalog import,
no per-tenant step, **no FixAll**. No data migration; ranges `System.Identity-[3.0.0,4.0)` stay satisfied.

### Added

- Methods 'Client-1/ProvisionMirrors-1', 'Client-1/ProvisionMirrorInTenant-1', 'Client-1/RotateMirrorSecret-1', 'Client-1/RemoveMirror-1', 'Client-1/SetMirrorAutoProvision-1' added _(minor — purely additive methods)_
- Methods 'ExternalTenantUserMapping-1/ProvisionAdmin-1', 'ExternalTenantUserMapping-1/ProvisionAdminWithGroups-1', 'ExternalTenantUserMapping-1/ProvisionCurrentUser-1', 'ExternalTenantUserMapping-1/RemoveAdminProvisioning-1', 'ExternalTenantUserMapping-1/CreateMapping-1' added _(minor — purely additive methods)_
- Records 'ClientMirrorBackfillResult-1', 'ClientMirrorProvisionResult-1', 'AdminProvisioningResult-1' and their attributes added _(minor — purely additive)_

## 3.4.0 - 2026-11-17

_Required bump level: minor._

System.Identity 3.4.0 adds methods so the REST secret write endpoints and the data-policy enforcement switch become
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
