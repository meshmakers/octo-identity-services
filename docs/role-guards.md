---
description: "Group-based role inheritance, role change guard (no escalation, last administrator), app and platform roles, first administrator"
applies_to: "**/{Authorization/RoleChange,AdminRoleMigration}/**, {Group*Resolver,GuardedEntityMutation,OctoRoleStore,*GroupStore,RolesController,GroupsController}.cs"
---

# Role inheritance and role change guards

## Group-Based Role Inheritance

Groups are organizational units that can be assigned roles. Users become group members and inherit all roles from their groups. Groups can be nested (groups within groups) for hierarchical role inheritance.

All group relationships (role assignments, user members, external user members, nested groups) are stored as **CK associations**, not as denormalized StringArray attributes. This is the idiomatic Octo CK approach for entity relationships.

**Association Roles** (defined in `ConstructionKit/associations/identity-associations.yaml`):
- `AssignedRole`: Links User or Group → Role (N:N)
- `GroupMember`: Links Group → User or ExternalTenantUserMapping (N:N)
- `ChildGroup`: Links parent Group → child Group (N:N)

Key components:
- **`RtGroup`**: CK type (`ck-group.yaml`) with attributes: `GroupName`, `NormalizedGroupName`, `GroupDescription`. Relationships via associations: `AssignedRole` → Role, `GroupMember` → User/ExternalTenantUserMapping, `ChildGroup` → Group
- **`IdentityAssociationConstants`**: Central constants for association role IDs (`AssignedRoleId`, `GroupMemberId`, `ChildGroupId`)
- **`IGroupStore`** / **`GroupStore`**: CRUD operations for groups plus association-based relationship management (role assignments, member users, member external users, child groups)
- **`IGroupRoleResolver`** / **`GroupRoleResolver`**: Resolves effective roles for a user by traversing group memberships recursively (max depth 10, cycle-safe)
- **`OctoUserStore`**: `GetRolesAsync` and `IsInRoleAsync` merge direct roles (via `AssignedRole` associations) with group-inherited roles — this is the critical path for JWT token role claims
- **`GroupsController`**: REST API at `{tenantId}/v1/groups` with full CRUD, role assignment, member management, and circular group prevention
- **`TenantOwners`** group: Default group provisioned in every tenant with all 10 default roles. Created by `DefaultConfigurationCreatorService` and `IdentityAssociationMigration` (migration 9→10)

Current identity schema (migration) version: `23` (migration 21→22 added the `RtOAuthAuthorization`/`RtOAuthToken` OpenIddict store types; 22→23 re-runs the full index update so abstract collection roots get their indexes). Current CK model version: `System.Identity-2.30.0` (2.30.0 = `User.DisableTwoFactor-1`, see below; 2.29.0 = the identity method declarations, see below; 2.28.0 = first ckLanguage 2 release with access modifiers, see below; 2.19.0–2.23.0 were ownership/runtime-state classifications, 2.24.0 added `DataPolicy.ProtectBlueprintLocked`, 2.25.0 the `Secret` identity-provider `ClientSecret`, 2.27.0 the `Secret` credential material of a user, see the sections below) — the 2.12.0→2.17.0 changes (verified-identifier directory) are additive schema needing no numeric migration; 2.17.0→2.18.0 REPLACED `RtUser.PreferredChannel` with `RtUser.PreferredChannelBindingId` (revision, binding-specific preference). The feature shipped the day before the replacement with no external consumers, so the old attribute was dropped without a migration — any stored kind-level values are simply ignored (users re-select).

## Role change guard: no escalation, last administrator stays

`IRoleChangeGuard` (`src/IdentityServices/Authorization/RoleChange/RoleChangeGuard.cs`, scoped) is the one rule set for changes of the **direct** roles of a
user. Callers: `UsersController` (`DELETE users/{u}`; the role endpoints and `POST users/{u}/merge` run the methods, section
"REST facades of the role and merge endpoints" in `docs/identity-rest-facades.md`), the three role method handlers (`UserRoleMethodHandlerBase.GuardAsync`) and `IUserMergeService` (source user). It is **never** called from `OctoUserStore`/`UserManager`: first admin of a new tenant
(`UserManagementService`), the Bootstrap blueprint seed, the one-time grants (`SecretManagementAdminGrant`, file role grants), the scratch-tenant creator grant, cross-tenant
provisioning and the login group rules assign roles through the store and stay unrestricted (`TheGuard_IsNotCalledFromTheUserStoreOrTheUserManager…` pins the constructors).
The role change guards on groups, mappings and role definitions (next section) and on client roles (section below) reuse it: `EvaluateGrantAsync(caller, addedRoleNames)` is the "grant only what you hold" part alone.

| Rule (checked in this order, on the **difference** before/after, never on the full list) | REST | Method (`METHOD_FORBIDDEN`, parameter `reason`) |
|---|---|---|
| `self-grant`: caller `sub` == target rtId and a direct role is **added** (removing own roles and an unchanged list are fine) | 403 problem+json, `code` | `self-grant` |
| `role-not-held`: an added **built-in** role (stored `RtWellKnownName`) is not in the caller's role claims; custom roles are free; removing is never judged. A caller holding `UserManagement` is refused only for **platform** roles; **app** roles are free for it (section "App roles and platform roles" below) | 403, `code`, `roleNames` | `role-not-held` + `roleNames` (comma separated) |
| `last-administrator`: the target effectively holds `UserManagement` now, not after the change, and **no other user** holds it (direct, through groups incl. nested, `xt_` shadow users through mappings via `IGroupRoleResolver`; **clients do not count**; a tenant with zero holders is not blocked) | 409, `code` | `last-administrator` |

- **Caller** = `RoleChangeCaller` (`sub`, `client_id`, `role` claims of the validated token; for methods the validated `CkMethodPrincipal`, never the informational `Caller`).
  A client-credentials caller has no `sub`: never self for a **user**, judged with the client's roles; it is self for its **own client**
  (section "Client-credentials callers are self for their own client" below). No exemption for services (none calls these endpoints).
- **No CK change.** Error contract is `METHOD_FORBIDDEN` + `reason` (`CkMethodOutcome.Forbidden`); a new declared code would be a Major of System.Identity.
  REST answers `application/problem+json` (`RoleChangeProblems`, `code` extension, readable `title` that Studio shows). Hard switch, no warn mode.
- **Audit.** Methods: the existing `Identity.Method` event carries `reason` (+ `roleNames`). REST: one failure event `Identity.RoleChangeRefused` through
  `IIdentityAuditService` (caller, target rtId, reason, role names, request path; never a token or password) plus a WARN log.
- **REST SetRoles** validates every role id first (404 changes nothing; it used to strip the direct roles first) and writes only the difference.
- **Residual race:** two administrators removing each other's `UserManagement` in parallel can both pass the check (no cross-request lock); documented.
- The last-administrator search is only run when the target loses `UserManagement`: direct holders, members of groups whose subtree carries the role, then (rare path) every `xt_` user
  through `IGroupRoleResolver`.
- **Tests:** `Api/TenantApi/RoleChangeGuardTests` (every rule through REST and through the method handlers with the same assertions: self-grant, held/not held/custom, difference,
  client caller, last administrator direct/group/nested group/mapping/client-not-counted/zero holders, delete + merge, audit records), `UserRoleMethod*Tests` (updated parity),
  `RoleChangeCallerTests`. The tests that need "exactly one administrator" first remove every holder of the test database (`ClearAdministratorsAsync`).

## App roles and platform roles

Tenant owners could not hand out the roles their own blueprints seed (e.g. `EnergyCommunityManagement` of EnergyCommunity.Base):
`role-not-held` judged every built-in role alike. Decision by Gerald (2026-11-08): holders of `UserManagement` may grant **app roles**;
**platform roles** keep the role change guard protection.

- **Platform role** = a built-in role (stored `RtWellKnownName`) that `System.Identity.Bootstrap` seeds (today the 17 roles of
  `seed-data/roles.yaml`: `TenantManagement`, `UserManagement`, `StreamDataAdmin`, `SecretManagement`, `DataModelManagement`, …).
  **App role** = every other built-in role, i.e. one a blueprint installed in the tenant seeds. Custom roles (no `RtWellKnownName`) stay free for everybody.
- **How the service knows.** `IPlatformRoleCatalog` / `BootstrapPlatformRoleCatalog` (`Authorization/RoleChange/PlatformRoleCatalog.cs`, singleton) reads the
  seed files of the **embedded** Bootstrap blueprint (`IBlueprintEmbeddedSource` of `System.Identity.Bootstrap`, the same resources the service applies to every
  tenant) once and collects `rtWellKnownName` and `rtId` of every `System.Identity/Role` entity. A role matches by either. No hand-kept name list: a role added to the
  Bootstrap seed is a platform role with the same build. **Fail closed:** when no role can be read, every built-in role counts as a platform role (the old rule) and an
  ERROR is logged. The engine stores no per-entity blueprint ownership (`BlueprintInstallation` has none), so the seed is the reliable source.
- **Rule** (`RoleChangeGuard.EvaluateGrantCoreAsync`, used by direct user roles, client roles, group roles, group membership, group nesting and mappings): an added
  built-in role the caller does not hold is allowed when the caller holds `UserManagement` **and** the role is not a platform role; otherwise `role-not-held`.
  A group (or nested group tree) with app **and** platform roles needs only its platform roles held; the refusal lists only those. `self-grant` and
  `last-administrator` are unchanged and still win (a tenant owner cannot add themselves to an app-role group). Callers without `UserManagement` get no relaxation.
  The data-policy protection (`identity.administration`) is untouched.
- **Log.** Refusals are unchanged (WARN + `Identity.RoleChangeRefused`). An allowed grant of app roles the caller does not hold writes one INFO line
  `Role change allowed (app-role-grant): caller …, target …, app roles [...]` (`RoleChangeDecision.AppRolesNotHeld`); it is written only when the whole change is allowed.
- **Tests:** `Api/TenantApi/AppRoleGrantTests` (REST, real MongoDB, production catalog: direct grant to client and user, group membership, group roles, nesting, each with
  app role / platform role / mixed group, caller with and without `UserManagement`, self-grant still refused), `Authorization/RoleChangeGuardAppRoleTests` (rule and INFO log),
  `Authorization/PlatformRoleCatalogTests` (the 17 seed roles, app roles, rtId match, fail closed). The older guard tests create many distinct "built-in" roles; in the test host a
  role whose `rtWellKnownName` starts with `platform-` counts as a platform role (`Infrastructure/TestPlatformRoles.cs`), so those role-change-guard tests keep judging platform roles.

## Client-credentials callers are self for their own client

A client-credentials client holding `UserManagement` (e.g. through `TenantOwners`) could add itself to `EnergyCommunityOperators` with its own token
and gain the app role: `self-grant` only knew user sessions. Decision by Gerald (2026-11-08): the self-grant block holds for app roles too
(four-eyes principle); a user administrator may grant app roles to others, never to themselves. The rule mirrors the user path, no new rule:

- **Who is self.** `RoleChangeCaller.SelfClientId` = the `client_id` of a token **without** `sub` (client credentials; an impersonated token carries the target's
  `client_id` and roles, so the target is self). A user session also carries a `client_id` (the application it signed in with); that client is not the user and is
  never self. The guard maps the id to the client of the tenant (`IOctoClientStore.FindRtClientByIdAsync`) and compares group members by rtId **and** by OAuth client id.
- **Judged like a user on its own user:** direct client roles (`PUT clients/{id}/roles`, `PUT clients/{id}/roles/{role}` through `EvaluateClientGrantAsync`:
  self-grant first, then the grant rule), group membership (`MemberAdded` of its own client, REST and `Group.AddMember`), a role added to a group its client reaches
  (`GroupRoles`, directly or through a parent group, REST and `Group.SetRoles`) and a group nested into such a group (`MemberAdded` of kind group); the walk is
  `RoleGraph.GroupsReachingClient`, the same as for users and as `GroupRoleResolver`. Answer and audit are those of the user path (`403 self-grant`, `METHOD_FORBIDDEN`
  + `reason=self-grant`, WARN `caller client <id>` + `Identity.RoleChangeRefused`). The `title` reads "You cannot grant additional roles to yourself." for both callers.
- **Free:** removing its own roles or memberships, granting to other clients and users (unchanged), and every path that does not call the guard: the bus
  path (`DistClientDto.AssignedRoleNames`, pipeline service accounts of the communication controller), Bootstrap seed, setup, the scratch-tenant creator grant
  (`TenantOwners`), cross-tenant provisioning.
- **Consequence:** a scratch-tenant creator client (`Create --scratch`, member of `TenantOwners`) can no longer give itself an app role a blueprint seeds later;
  a user administrator or another client grants it.
- **Tests:** `Authorization/RoleChangeGuardClientSelfTests` (unit: membership by rtId and client id, group roles direct and nested, nesting, other client,
  removal, user session with the same `client_id`, direct client grant), `Api/TenantApi/AppRoleGrantTests` region "Client self-grant" (REST) and the
  client-caller cases (`AddMember_AClient…`, `SetRoles_AClient…`, `RemoveMember_AClient…`) of `Api/Methods/GroupMethodTests`.

## Role change guard on groups, mappings and role definitions

`IRoleChangeGuard` (above) also judges the group / mapping graph and role definitions, with the same reasons, status codes and audit
(`Identity.RoleChangeRefused`, written by `IRoleChangeRefusals`, scoped, used by the three controllers):

| Caller | Check |
|---|---|
| `GroupsController`: `PUT groups/{id}/roles`, `PUT members/users/{u}`, `PUT members/clients/{c}`, `PUT members/groups/{g}`, `DELETE members/users/{u}`, `DELETE members/groups/{g}`, `DELETE groups/{id}` | `EvaluateAsync(caller, RoleGraphChange)` (`GroupRoles`, `MemberAdded`, `MemberRemoved`, `GroupDeleted`). `DELETE members/clients/{c}` is not judged (nothing is granted, clients are no administrators); the scratch-tenant revoke marker stays. Since System.Identity 3.3.0 the role and member endpoints are facades: the `Group.*` handlers call the guard and the controller maps the refusal back (`RoleChangeProblems.RefusalOf`, `docs/identity-rest-facades.md`); only `DELETE groups/{id}` calls it in the controller |
| `ExternalTenantUserMappingsController`: create, update, delete | `MappingRoles` (existing id, or the source identity of a new mapping), `MappingDeleted` |
| `RolesController`: `PUT roles/{name}` with another name, `DELETE roles/{name}` | `EvaluateRoleDefinition(role, newName)`: a role with an `rtWellKnownName` answers 409 `built-in-role` (+ `roleNames`); custom roles and a same-name save are untouched |

- **One graph, one rule.** `RoleGraph` (`Authorization/RoleChange/RoleGraph.cs`, internal) loads groups (roles, child groups, user / client / mapping
  members), mappings (mapped role ids), all users, the mappings serving each `xt_` shadow user and the direct holders of `UserManagement`. A change is applied to a
  clone and `Holders()` (direct + groups incl. nested (depth 10, cycle safe) + mapping roles + groups of a mapping; existing **users** only, clients excluded)
  is compared before and after: refused (409) when holders existed and none is left. A tenant without holders is not blocked. Cost: one read of all groups,
  mappings and users per change (the 7914 check read the same data).
- **Granted roles** = for `GroupRoles` the added role ids, for `MemberAdded` the effective roles (own + nested) of the group (for a child group: of the child), for
  `MappingRoles` the added mapped role ids; a member that is already there grants nothing. **Self** = the caller is the added user, or the group whose roles
  grow (or the group a child is added to) is reached by the caller (member directly, via a mapping that serves it, or a parent group of it), or the mapping serves the
  caller (for a new mapping its source identity is in the caller's `xt_` chain). A client-credentials caller is self the same way for its own client
  (the added client, or a group its client reaches directly or as a parent group). Self wins over `role-not-held`; roles are resolved to names and judged with
  `EvaluateGrantAsync` (built-in only). Group create with initial roles (`Group.CreateGroup`, REST `POST groups`, System.Identity 3.7.0) judges
  them with the grant rule only (`EvaluateGrantAsync`: a built-in role the caller does not hold is `role-not-held`); a new group has no members, so the
  self and last-administrator rules cannot apply. Before 3.7.0 the REST create wrote the initial roles unjudged.
- **Role definitions:** `Role.UpdateRole` / `Role.DeleteRole` (REST `PUT` / `DELETE roles/{name}`) refuse a built-in role (`EvaluateRoleDefinition`,
  `built-in-role`, 409 on REST).
- **Not guarded on purpose:** `GroupStore`/`ExternalTenantUserMappingStore` and everything that uses them directly: Bootstrap seed, setup, scratch-tenant grant,
  cross-tenant provisioning (`AdminProvisioningController`), `LoginGroupAssignmentService`. Group methods call `EvaluateAsync(caller, RoleGraphChange)`
  and answer `METHOD_FORBIDDEN` with the `reason`; direct client roles: see the section on client roles.
- **Tests:** `Api/TenantApi/GroupRoleChangeGuardTests` (REST on real MongoDB: self-grant direct / via parent / via child / via mapping, role-not-held for roles, members,
  clients, nested groups, mappings, idempotent re-add, last administrator for member removal, role removal, delete, child group, mapping update / delete, mapping-in-group,
  clients not counting, built-in role rename / delete, audit record, unchanged flows) and `Authorization/RoleGraphTests` (holders, clone, cycle, references).

## Role change guard on client roles

A tenant administrator (`TenantManagement` is enough for the client endpoints) could give a client a built-in role they do not
hold (e.g. `UserManagement`) and then act as that client. `ClientsController` therefore runs the "grant only what you hold" part of
`IRoleChangeGuard` (`EvaluateGrantAsync`) before it writes a client role:

| Endpoint | Judged | Refusal |
|---|---|---|
| `PUT clients/{id}/roles` (replace-all, role ids) | every role id is resolved first (unknown or malformed id = 404, nothing written; it used to write the edge blindly); the **added** roles (not in the client's direct roles). Only the difference is written (`IClientRoleStore.ApplyRoleChangesAsync`), never the kept roles | 403 problem+json `code=role-not-held`, `roleNames` |
| `PUT clients/{id}/roles/{roleName}` | the role; a role the client already holds directly is answered 200 without a write | same |
| `DELETE clients/{id}/roles/{roleName}` | never (removing is no escalation) | - |

- **Built-in roles only** (stored `RtWellKnownName`); custom roles are free. No last-administrator rule for clients (clients are no
  administrators, role change guard decision 2). The self-grant rule applies to a client-credentials caller changing its own client
  (`EvaluateClientGrantAsync`, section below). The caller is the token (`RoleChangeCaller.FromPrincipal`): user or client-credentials token, judged with its own
  role claims. Hard switch, no warn mode.
- **Audit:** `IRoleChangeRefusals` writes the WARN line and the `Identity.RoleChangeRefused` event (caller, `client <clientId>`, reason, role names), as for groups.
- 🔴 **Write only what was judged.** `SetRoleIdsAsync` (replace-all) re-reads the assignments in its own transaction and inserts every missing
  wanted role. Used after the check, a role that a concurrent request removed between the check and the write would be restored by a caller who does
  not hold it (review finding on #224). The controller therefore writes only the judged additions and the removals; kept roles are never written.
  `SetRoleIdsAsync` stays for internal callers. Pinned by `ClientsControllerRoleGuardTests` (unit) and
  `ClientRoleAssignmentIntegrationTests.ApplyRoleChanges_WritesOnlyTheGivenDifference_AndNeverRestoresAnUnlistedRole`.
- **Not guarded on purpose:** the bus path (`CreateIdentityDataCommandRequestConsumer`, `DistClientDto.AssignedRoleNames`: service accounts and
  client mirroring between services, no caller) and `IClientRoleStore` itself; client mirrors get no roles anyway. Granting a client roles through
  a group (REST `PUT groups/{id}/members/clients/{c}`, method `Group.AddMember` with `memberKind=Client`) was already judged by the group guard and the group methods.
- **No client role method exists** in System.Identity 2.29.0 (`Client` declares only `AddSecret` / `RemoveSecret`); the method transport for
  client roles is `Group.AddMember`. No CK change.
- **Tests:** `Api/TenantApi/ClientRoleChangeGuardTests` (REST on real MongoDB: not held / held / custom for both endpoints, `TenantManagement` without
  `UserManagement` cannot grant `UserManagement`, difference only, client-credentials caller, unknown / malformed id, audit record, guard not on the bus
  or store path), `ServiceAccountClientProvisioningIntegrationTests.BusPath_StillAssignsABuiltInRole_WithoutTheRoleChangeGuard`,
  `GroupMethodTests.AddMember_AClientIntoAGroupWithABuiltInRoleTheCallerLacks_IsRefused_RoleNotHeld` (method transport).

## First administrator is a member of TenantOwners

`UserManagementService.CreateAdminUserAsync` (setup endpoints `setup/create-admin` and `v1/setup`) adds the first administrator to the `TenantOwners` group (`AddToTenantOwnersAsync`, via `IGroupStore`). That membership
replaces the direct roles: the direct roles (`AddDirectAdministratorRolesAsync`, incl. `DataModelManagement` and `SecretManagement`) are only the
fallback for a tenant without a usable group. `TenantOwners` carries every built-in platform role (`SecretManagement` too), among them the
`StreamData*` roles the direct grants lack; without the membership the administrator holds fewer roles than the group and the guard above refuses adding anyone to it
(`role-not-held`). The first administrator therefore holds `SecretManagement` through the group once the setup step
`TenantOwnersSecretManagementGrant` has added the edge; if that step fails (logged, setup continues, retried on the next setup) the
administrator lacks the role until then (see "API secret writes need `SecretManagement`" in `docs/architecture.md`); the XML doc of `AddToTenantOwnersAsync` ("every non-secret built-in role") predates that change. The step is idempotent (an existing membership is not added again; a setup
re-run is refused anyway while users exist) and optional like the file roles: a tenant without the group logs a warning and keeps the direct roles. The setup goes
through the stores, not the guarded controllers, on purpose. The scratch-tenant creator (`ScratchTenantGrantService`) and cross-tenant admin provisioning
(`AdminProvisioningController`) already put their subject into `TenantOwners`; nothing changed there.
The direct-role fallback (tenant without `TenantOwners`, `AddDirectAdministratorRolesAsync`) also grants `DataModelManagement`: the asset
repository's `DataModelManagementPolicy` requires that role for `ImportCk`, catalog imports, `FixAll`, blueprint install/update/uninstall and catalog
refresh, so a fallback administrator would otherwise be locked out of every data model change. `TenantOwners` already carries the role (bootstrap seed,
role `66…0B`), so no seed bump is needed.

- **Tests:** `UserManagementServiceTests` (membership added / not twice / missing group) and `Api/Setup/SetupAdminTenantOwnersTests` (real MongoDB: setup via REST, the admin adds
  another user to `TenantOwners`, control case without the membership = 403 `role-not-held`, re-run refused without a second edge, guard not injected into setup/group store).
