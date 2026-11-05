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
   (Dash0, dataset `<env>`: `k8s.container.name is identity` + `otel.log.body contains AB#5859`). Evaluate a log extract with the script:

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

## AB#5861: `SecretManagement` for API secret writes

Since AB#5861 creating, rotating and deleting API secrets (REST `apiSecrets/*` writes, a `clientSecret` in client
create/update, the `Client.AddSecret`/`RemoveSecret` methods) needs the tenant role `SecretManagement`. It ships
**staged**: `IdentityApiAuthorization:SecretManagementRoleEnforcement` defaults to `Warn` — `TenantManagement` or
`UserManagement` still pass and every such call is logged
`This would be denied with SecretManagementRoleEnforcement=Enforce (AB#5861)`. Releasing the identity image changes
nothing for callers; only the switch to `Enforce` does.

**Why staged (lockout analysis):** `SecretManagementAdminGrant` (AB#5544, runs once per tenant from
`SetupTenantAsync` on identity start, existing tenants included) granted the role only to local users holding both
`AdminPanelManagement` and `TenantManagement` at that moment. Not covered, so denied under `Enforce` unless assigned:
cross-tenant administrators (shadow users `xt_*`, external tenant user mappings — e.g. platform admins administering
customer tenants from the system tenant), clients with `TenantManagement`, users with only `TenantManagement` or
`UserManagement`, administrators added after the grant ran (except the first admin of a new tenant), and anybody who
holds the admin roles only through `TenantOwners` membership created after the grant.

Who must hold `SecretManagement`: the human administrators who manage client/API secrets. Client credentials accounts
only where a documented automation creates secrets through the identity REST API (none known: the communication
controller provisions and rotates pipeline service account secrets over the bus, not REST). Never assign it to
`TenantOwners`.

Order per cluster: **test-2 → prod-2 → prod-1**.

1. **Inventory (read-only)** — who holds the role, who would lose secret writes:
   ```bash
   # kube context with access to the mongodb namespace (breakglass or Semaphore, never extra RBAC rights)
   scripts/identity-secret-management-role-check.sh --kubeconfig <file> --context <kube-ctx>               # all tenants
   scripts/identity-secret-management-role-check.sh --kubeconfig <file> --context <kube-ctx> meshtest      # selected tenants
   scripts/identity-secret-management-role-check.sh --kubeconfig <file> --context <kube-ctx> --ids-only    # rtIds only (for work items)
   scripts/identity-secret-management-role-check.sh --self-check                                           # write guard only
   ```
   The script reads the cluster's MongoDB directly (`mongosh` in the `octo-mongodb-<n>` pod,
   `readPreference=secondaryPreferred`): the tenant list from `octosystem`, per tenant DB the identity roles, groups,
   users, clients, external tenant user mappings and the `AssignedRole`/`GroupMember`/`ChildGroup` associations. It
   uses no octo-cli and no token exchange and writes nothing: its JavaScript
   (`scripts/identity-secret-management-role-check.{snapshot,inventory}.js`) uses read operations only, a guard refuses
   to run on any write-capable call (tested by `scripts/tests/identity-secret-management-role-check.test.sh`), and an
   identity snapshot (users, `xt_` users, mappings, newest change per tenant DB) taken before and after must be equal —
   otherwise exit 1. Queries project only the attributes they need (no password hashes, security stamps or client
   secrets); the MongoDB password goes from the cluster secret to `mongosh` on stdin only.
   `LOSES` rows hold `TenantManagement`/`UserManagement` but not `SecretManagement`; `NO-ROLE` = tenant without the
   role (bootstrap < 1.7.0, identity not restarted since); `ERROR` = tenant database not found (exit 1).

   > The earlier version (until AB#8155) ran `octo-cli GraphQl -tid <tenant>` per tenant. That token exchange created
   > an `xt_` shadow user for the caller in every tenant that had none yet — the inventory was not read-only. Shadow
   > users created by earlier runs are not removed by the new script.
2. **Deploy the identity release** (default `Warn`, nothing changes) and let it run for a while.
3. **Warn log**: every API secret write by a caller without the role is logged:
   ```bash
   scripts/identity-rest-role-precheck.sh --warn-log identity-<env>.log --context <env>_octosystem
   ```
   (Dash0, dataset `<env>`: `k8s.container.name is identity` + `otel.log.body contains AB#5861`.) Every
   `would-deny-secret` row is a subject that needs `SecretManagement`.
4. **Assign the role** to the people (and the documented automations) from steps 1 and 3 (Gerald):
   ```bash
   octo-cli --context <env>_<tenant> -c AddUserToRole -un "<userName>" -r "SecretManagement"
   # cross-tenant administrator: -rids REPLACES the role list - include the existing roles
   octo-cli --context <env>_<tenant> -c UpdateExternalTenantUserMapping -id "<mapping-rtid>" -rids "<existing>,SecretManagement"
   ```
5. **Switch to `Enforce` per cluster through values** (the AB#7581 pattern: chart value with the same default as the
   code, overridden per cluster in `octo-mesh-deployment`, `clusters/<env>/values-octo-mesh.yaml`):
   ```yaml
   services:
     identity:
       secretManagementRoleEnforcement: Enforce   # rendered as OCTO_IDENTITYAPIAUTHORIZATION__SECRETMANAGEMENTROLEENFORCEMENT
   ```
   then run the cluster's CD. The `octo-mesh` chart value (`Warn` | `Enforce`, default `Warn`, any other value fails the
   render, like `apiRoleEnforcement`) is a follow-up in octo-helm-core and must be released before this step; the
   identity release itself needs no value. Only switch once steps 1 and 3 show no row that should keep access.
   Smoke test: an administrator with the role creates and deletes a test secret in Studio; a user with only
   `TenantManagement` gets `403` with
   `{"message": "Access is denied: this operation requires the role 'SecretManagement' in the tenant. ..."}`.
6. **Emergency exit**: back to `Warn` (remove the cluster value and run the CD) — or the cluster-wide `apiRoleEnforcement: Warn`, which
   relaxes every role policy including this one.

### AB#8095: the method path admits `SecretManagement` (System.Identity 3.1.0)

Up to System.Identity 3.0.1 the CK declared `authorization.roles: [ TenantManagement, UserManagement ]` on
`Client.AddSecret-1` and `Client.RemoveSecret-1`. The method gateway checks the declared roles (any-of), so a caller
holding **only** `SecretManagement` was refused on the method path although REST admits it, and a `TenantManagement`-only
caller passed the gateway and was refused by the identity handler under `Enforce`.

System.Identity **3.1.0** declares `[ TenantManagement, UserManagement, SecretManagement ]` on both methods:

| Caller holds only | `Warn` | `Enforce` |
|-------------------|--------|-----------|
| `SecretManagement` (direct, via group, via external tenant user mapping) | allowed | allowed |
| `TenantManagement` or `UserManagement` | allowed, logged (`AB#5861`) | `METHOD_FORBIDDEN` from the handler (`reason` = `role-required`), nothing changes, one audit record |

- **Minor**, not Major: a role added is a method authorization widening (row M12 of `docs/ck-semver-rules.md` in
  `octo-construction-kit-engine`), acknowledged in `ckModel.yaml` (`compatibility.acknowledge`, valid for the release that
  publishes 3.1.0 only - remove the entries in the next release of the model, `OCTO-CK204`). The effective rule does not
  loosen: the handler still enforces `SecretManagement` under `Enforce`. Removing `TenantManagement`/`UserManagement` from
  the declaration is a role removal (Major) and waits for the next System.Identity major.
- **Rollout:** System.Identity is service-managed - it ships inside the identity service with the regular identity release
  train and is applied on identity startup in every tenant (with `System.Identity.Bootstrap`). No catalog import, no
  per-tenant step. **No FixAll** (AB#7998: FixAll upgrades libraries beyond the ranges of installed dependents, e.g.
  Basic.Energy 2.0.0 over EnergyIQ's `[1.9,2.0)`); a Minor inside `[3.0.0,4.0)` needs none. A tenant that shows
  `ResolveFailed` afterwards is repaired with a targeted `ImportFromCatalog` of the affected model.
- **Check after the release reaches a cluster:** `octo-cli --context <env>_<tenant> -c LibraryStatus` shows
  System.Identity 3.1.0 and no `ResolveFailed`, in a sample of tenants including `energyiq`.
