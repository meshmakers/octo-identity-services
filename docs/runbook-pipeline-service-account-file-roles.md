# Runbook: pipeline service accounts hold FileManagement (AB#6542)

Proof report for the grant described in `persistence.md` ("FileManagement for the pipeline service accounts").
Run it before S9 (AB#6183 / AB#6181) on each tenant.

- Endpoint (read-only, policy `IdentityTenantAdministrationReadPolicy`):
  `GET {identity}/{tenantId}/system/v1/pipelineServiceAccountFileRoles`
- CLI: `octo-cli -c CheckPipelineServiceAccountFileRoles` (tenant from the context / `-tid`). Exit code is non-zero
  when at least one account lacks FileManagement, so a script can loop over the tenants and gate on it.
- Result: `tenantId`, `status`, `missingCount`, `accounts[]` with `clientId`, `rtId`, `hasFileManagement`. No secrets.
- `status`: `AllCovered`, `MissingGrants` (the only one to act on), `NoAccounts`, `NotApplicable` (tenant has no
  System.Files model) and `RoleMissing` (FileManagement not seeded yet; the next setup retries).
- A missing account is fixed by the existing grant, which re-runs on identity start, tenant create, full tenant
  update, failed-tenant retry and on every controller identity-data command. Re-run the check afterwards.
- The check never writes. It reuses `PipelineServiceAccountFileRoleGrant.Plan` as the single definition of
  "holds the role".
