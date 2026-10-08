# Rollout: role enforcement on the identity REST API (AB#5859)

Since AB#5859 the tenant REST API (`{tenant}/v1/...`) needs a tenant role in addition to `octo_api`
(table: `docs/system-api.md` § Authorization Policies). Before, any signed-in user could administer identity.
Decision: **`Enforce` on every environment**, with a precheck before each rollout. `Warn` is only the
emergency exit.

| Area | Required role (any of) |
|---|---|
| users, roles (write), groups, external tenant user mappings, e-mail bindings, data permissions | `UserManagement` |
| clients, mirrors, API resources/scopes/secrets, identity providers, e-mail domain rules, admin provisioning | `TenantManagement`, `UserManagement` |
| directory reads (role names, a client's roles/actors) | the above + `AdminPanelManagement`, `CommunicationManagement` |
| `GET users/directory` (assignee picker) | no role; token tenant must equal the route tenant |
| log level | `TenantManagement` in the system tenant |

Order: **test-2 → prod-2 → prod-1**. Only move to the next environment once steps 1–4 pass.

## 1. Precheck (read-only)

```bash
scripts/identity-rest-role-precheck.sh --context <env>_octosystem --discover all            # whole installation
scripts/identity-rest-role-precheck.sh --context <env>_octosystem meshtest energyiq --all   # selected tenants, incl. INFO rows
```

- `<env>` = `test-2`, `prod-2`, `prod-1`. octo-cli has no per-call tenant switch: the script uses one
  context per tenant (`<env>_<tenant>`; otherwise `--map <tenant>=<ctx>`). Tenants without a context are
  listed as `SKIPPED` (exit 1): create the context (`octo-cli -c AddContext ...`, `LogIn -i`) or accept the gap.
- `--discover all` only works from the system tenant; otherwise the default (`recursive`) applies.
- Exit code: `0` clean, `2` findings, `1` error / incomplete. Output is TSV; e-mail addresses are masked
  (`--with-email` to show them for step 2).
- `FINDING`: subject has admin roles (`*Management`) or client roles, but neither `UserManagement` nor
  `TenantManagement`. `REVIEW`: `client_credentials` client without group-inherited roles.
- **Gap:** octo-cli does not expose **direct** user/client role assignments, only group roles (incl.
  `TenantOwners`) and the roles of external tenant user mappings. Check `REVIEW` rows and users with
  directly assigned roles in Studio (Users → Roles, Clients → Roles). Whether a subject *actually* uses
  the identity API is only visible in the warn log (step 5).

## 2. Assign missing roles (Gerald, write commands)

Prefer groups (`TenantOwners` = full admin) over direct roles. The group RtId comes from `GetGroups`
(the script prints group names; `octo-cli --context <ctx> -c GetGroups | grep -v eyJ`).

```bash
# User -> TenantOwners (or a dedicated admin group)
octo-cli --context <env>_<tenant> -c AddUserToGroup -id "<group-rtid>" -uid "<user-rtid>"
# User -> single role
octo-cli --context <env>_<tenant> -c AddUserToRole -un "<userName>" -r "UserManagement"
# Cross-tenant user (external mapping): -rids REPLACES the role list - include the existing roles
octo-cli --context <env>_<tenant> -c UpdateExternalTenantUserMapping -id "<mapping-rtid>" -rids "<existing>,UserManagement"
# Service client calling the identity API (provisioning/automation)
octo-cli --context <env>_<tenant> -c AddClientToRole -id "<clientId>" -r "TenantManagement"
octo-cli --context <env>_<tenant> -c AddClientToGroup -id "<group-rtid>" -cid "<clientId>"
```

Only give `UserManagement` to people who should manage users; `TenantManagement` is enough for
clients/API resources/identity providers. Then re-run step 1 until no `FINDING` rows remain
(or the remaining rows are intentional - note them).

## 3. Release identity + chart (default `Enforce`)

- Identity image with AB#5859 through the services train / hotfix (`octo-mesh-deployment`).
- `octo-mesh` chart (octo-helm-core) with `services.identity.apiRoleEnforcement` (default `Enforce`,
  env `OCTO_IDENTITYAPIAUTHORIZATION__ROLEENFORCEMENT`). Do **not** set the value in
  `clusters/<env>/values-octo-mesh.yaml` - the default applies.
- Deploy through the regular CD (`deploy-octo-mesh-core-services-test-2.yml` or
  `deploy-octo-mesh-core-services.yml`).

## 4. Smoke tests (right after the deploy)

1. **Admin in Studio**: Users, Groups, Clients, Identity Providers open and save → OK.
2. **User without role** (test user without `UserManagement`/`TenantManagement`):
   `octo-cli --context <ctx-of-test-user> -c GetUsers` → `Forbidden`/403;
   Studio user administration shows no data / 403.
3. **`users/directory`** as a normal user: `GET {tenant}/v1/users/directory?take=1` → 200 with only
   `userId`/`displayName` (needs only the matching token tenant). No app uses it yet — the meshmakers-app
   ToDo assignee picker still calls `users/getPaged` and shows an empty list for users without
   `UserManagement` until it switches to the directory.
4. **Service clients**: adapters/pipelines run (communication controller reads client roles/actors via
   `CommunicationManagement`); CI/provisioning (`ci-deploy`, `claude-agent`) runs one read
   command against the identity API.
5. **Logs** for 30-60 min: no unexpected `Identity API call denied` lines
   (Loki: `{namespace="octo", container="identity"} |= "AB#5859"`). Evaluate a log extract with the script:

```bash
scripts/identity-rest-role-precheck.sh --warn-log identity-<env>.log --context <env>_octosystem
```

The script also aggregates Enforce `denied` lines (tenant/subject/client/path); `--context` resolves
subject IDs to user names.

## 5. Emergency exit: `Warn`, evaluate, back to `Enforce`

1. In `octo-mesh-deployment`, `clusters/<env>/values-octo-mesh.yaml`:
   ```yaml
   services:
     identity:
       apiRoleEnforcement: Warn
   ```
   and run the CD pipeline from step 3 (identity pod restarts). Faster stop-gap via Breakglass/Semaphore:
   set `OCTO_IDENTITYAPIAUTHORIZATION__ROLEENFORCEMENT=Warn` on the identity deployment - always
   follow up with the values change, or the next deploy resets it to `Enforce`.
2. Let it run for a while, then save the log (the script itself never calls kubectl):
   ```bash
   kubectl logs -n octo deploy/<identity-deployment> --since=24h > identity-<env>-warn.log
   scripts/identity-rest-role-precheck.sh --warn-log identity-<env>-warn.log --context <env>_octosystem
   ```
   Every `would-deny` row = a subject/client that needs a role → assign it (step 2).
   `would-deny-provisioning` = admin provisioning outside the caller's tenant subtree (stays forbidden; fix the caller).
3. Once the warn log has no new `would-deny` lines: remove the value again (default `Enforce`),
   deploy, and repeat step 4.
