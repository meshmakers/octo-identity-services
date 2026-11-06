# Changelog

Notable changes of the OctoMesh identity services. The CK model `System.Identity` keeps its own changelog in
`src/Persistence.IdentityCkModel/ConstructionKit/`.

## Unreleased

### Documentation

- **Contract for sibling-tenant user lookup and grants (AB#8340).** `docs/CONCEPT-SIBLING-TENANT-GRANTS.md` fixes the
  routes, DTOs, problem codes, the uniform-404 rule, the lookup rate limit, the audit events and the revocation
  semantics for granting a user of a non-ancestor tenant access to a target tenant (Feature AB#8313). No behaviour
  change yet; the routes are implemented by AB#8341–AB#8345.

### Fixed

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
