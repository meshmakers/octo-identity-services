# Changelog

Notable changes of the OctoMesh identity services. The CK model `System.Identity` keeps its own changelog in
`src/Persistence.IdentityCkModel/ConstructionKit/`.

## Unreleased

### Fixed

- **System.Identity ships as 3.1.1 (AB#8095).** 3.1.0 (`SecretManagement` on `Client.AddSecret-1`/`RemoveSecret-1`) could
  not be published again after its acknowledgements were removed (`OCTO-CK205`/`OCTO-CK203`), which kept the identity
  main CI red. 3.1.1 is the same model; nothing changes for tenants beyond 3.1.0.
- **Token exchange no longer leaves an `xt_` shadow user in a tenant it refuses (AB#8304).** The exchange
  now decides before it creates: a caller without a shadow user in the target tenant gets one only when the
  tenant's `ExternalTenantUserMapping`s grant it at least one role (directly or through the mapping's groups);
  otherwise it is refused with `access_denied` / `tenant_not_provisioned` and nothing is written. Existing
  shadow users behave as before. **Behaviour change:** a new cross-tenant user is let in through a mapping
  (Studio *Add Cross-Tenant User*, `CreateExternalTenantUserMapping`, `ProvisionCurrentUser -ttid`), no longer
  by granting a role to a left-over `xt_` user. Existing role-less `xt_` users are cleaned up separately
  (AB#8305). See `docs/authentication.md`.
