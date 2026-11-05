# Changelog

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
