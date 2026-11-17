---
description: "Identity CK method declarations and host, User.ChangePassword/ResetPassword, role, group, child-group, client role/overlay and client-secret methods"
applies_to: "src/IdentityServices/Methods/**, **/Services/{SelfService,SecretManagement}/**, *DataPermission*.cs"
---

# Identity CK methods

## CK method host of the identity service and `User.ChangePassword`

The identity service hosts CK methods as a remote handler (bus transport, SDK `Meshmakers.Octo.Services.Methods`). All of it lives in
`src/IdentityServices/Methods/`; a later handler story (`User.ResetPassword` is the second one, section below) adds a handler class and **one row** to
`IdentityMethodHost.Handlers` (method id constant of `SystemIdentityCkIds`, handler type, `CarriesSecret`, `b => b.Handle<T>(id)`) - nothing else.

- **Host setup** (`IdentityMethodHost`, called once from `Program.cs` after `AddOctoIdentityPersistence`): `AddCkMethodHandlers("IdentityService", ...)`,
  `AddCkMethodHandlerDiscovery()` in the event hub configuration, and `AddCkMethodCallerTokenValidation()` with the authority of this service
  (`Identity:AuthorityUrl`, issuer with trailing slash; `Methods:Token` can override; Development accepts the self-signed local authority). The host
  validates the forwarded access token before the handler runs (a call without a valid token is `METHOD_FORBIDDEN`) and hands the validated caller
  as `context.CallerPrincipal`. Without any selected handler nothing is hosted (no queue, no announcement, no token validation requirement); the role methods
  carry no secret and are always selected, so the host runs in every configuration and only the password methods wait for the switch.
- **Production gate `Methods:Identity:EnablePasswordMethods`** (default **false**, env `OCTO_Methods__Identity__EnablePasswordMethods`, Helm value
  `services.identity.methods.enablePasswordMethods` in the octo-helm-core `octo-mesh` chart, set per cluster in octo-mesh-deployment
  `clusters/<c>/values-octo-mesh.yaml` (on in test-2, staging-1, prod-1 and prod-2 since 2026-11-10/11, startup log `EnablePasswordMethods=True`)): decided by Gerald 2026-10-23, no method carrying a password or secret on staging-1, prod-1,
  prod-2 before B0 (restricted broker user). **The switch controls the bus only**. Off: handlers whose registration has
  `CarriesSecret = true` are not offered on the bus, the service announces no password method and the gateway (GraphQL) answers
  `METHOD_HANDLER_NOT_AVAILABLE`; the rows with `ServesRestFacade = true` (`User.CreateUser`, `User.ResetPassword`, also
  `User.ChangePassword`, `User.SetPassword`) are registered **local only** (`HandleLocalOnly`, `IdentityMethodHost.SelectLocalOnlyHandlers`: no
  announcement, no queue) so their REST facades `POST users`, `POST users/ResetPassword`, `api/manage/change-password` and `set-password` keep
  working in-process; the client secret methods stay unregistered. A GraphQL call of a method that is off is refused by the asset-repo
  gateway before the send (common-services dispatcher: no live handler in the registry = `METHOD_HANDLER_NOT_AVAILABLE` /
  `no-live-handler`, nothing on the broker, no `S-FAULT`); with an asset-repo on an older common-services package one non-persistent
  send still reached RabbitMQ and came back unroutable. On (local, test-2 with
  test accounts): all offered on the bus (and called in-process by the facades).
  `IdentityMethodDeclarationsIntegrationTests.EveryHandlerRegistration_FlagsASecretCarryingMethod_AsTheModelDeclaresIt` compares every
  `CarriesSecret` with the compiled model (a sensitive parameter or result), so a new handler cannot pass the gate by a forgotten flag.
  The switch is read while the service collection is built: restart the service after changing it.
- **Startup validation tenant.** The SDK (octo-common-services) normalizes the tenant id of the start-up validation to the lower case CK
  cache key, so a default installation (`SystemTenantId` = `OctoSystem`) validates its methods without configuration; `IdentityMethodHost` sets no
  `Methods:ValidationTenantIds` any more (the workaround was removed). Needs the common-services package or newer.
  `TheStartupValidation_NeedsNoIdentityWorkaround_WithTheDefaultConfiguration` pins that the host adds nothing. On a rolling upgrade the System.Identity model of
  the system tenant must already be the embedded version when the validation runs; the identity setup imports it first.
  Since a later common-services release the validation loads (or waits for) the CK cache of the validation tenant within `Methods:CacheLoadTimeout`
  instead of skipping an unloaded tenant; a test that fakes `ICkCacheService` must answer `IsTenantLoaded` with `true` for the lower-case key
  (`TheStartupValidation_LooksTheMethodUpInTheLowerCaseCacheOfTheDefaultSystemTenant`), otherwise the source throws "cache not loaded".
- **Tenant on the bus.** A handler has no HTTP request, but every store resolves its tenant through `IMultiTenancyResolverService`. The handler calls
  `IMethodTenantAccessor.BindAsync(context.TenantId)` **before** it resolves `UserManager`, the stores or `IUserCredentialChangeService` from its scope
  (it takes `IServiceProvider` for exactly that reason); `MethodTenantResolverService` answers with the bound tenant and falls back to the HTTP
  resolution when none is bound (HTTP requests are unchanged). Never resolve a store in a handler constructor.
- **`User.ChangePassword`** (`UserChangePasswordHandler`): self only. The declared authorization (`allowSelf`, no role) also admits an administrator for any
  target (default-deny rule of the SDK), so the handler requires `CallerPrincipal.SubjectId == TargetRtId` itself and answers `METHOD_FORBIDDEN`
  (`reason=not-self`) **before** any lookup: identical for an existing and a missing target, for another user, for an administrator and for a service
  token (administrators use `ResetPassword`). Order: tenant, user, shadow user (`SHADOW_USER_PASSWORD_NOT_ALLOWED`), lockout (`USER_LOCKED_OUT`),
  `UserManager.ChangePasswordAsync` (wrong current password = `CURRENT_PASSWORD_INVALID`, counted with the atomic lockout counter;
  policy failure = `PASSWORD_POLICY_VIOLATION` with one detail per failed rule, code only e.g. `PasswordTooShort`, never a value), counter reset, then
  `IUserCredentialChangeService.OnPasswordChangedAsync(..., PasswordChangePath.MethodChangePassword, ...)` (security stamp, revocation of all refresh
  tokens and authorizations of the user in this tenant, log line). A failing revocation throws, the caller gets `METHOD_HANDLER_FAILED`.
  REST: `ManageApiController.ChangePassword` is its facade (`docs/identity-rest-facades.md`, section "Account pages run the password methods").
- **Audit.** `IdentityMethodAuditWriter` writes one event per call (success and failure) into the event log of the tenant (category `Identity.Method`,
  details `methodId`, `invocationId`, `outcome` (`SUCCESS` or the error code), `targetRtId`, `callerSubject`; no parameter, no hash, no token). It is
  not `IIdentityAuditService` (that one reads the tenant from the HTTP request and persists failures only). The gateway-side one-per-invocation record
  `Method.Invocation` (`ICkMethodAuditRecorder`) is written where a call is dispatched (the SDK's remote host does not run the pipeline); it is a different category.
- **Secrets.** `currentPassword` / `newPassword` are only passed to `UserManager`; the generated parameter record prints `***`. Never log or audit the
  parameters or `context.Parameters`.
- **Tests:** `Api/Methods/UserChangePasswordMethodTests` (real MongoDB and identity host with the switch on; the bus side (endpoints, announcement) is removed in the test host
  because it has no broker): success with new/old sign-in and revocation, wrong current password, lockout, policy, other user / missing target / service token
  / administrator, shadow user, forged caller without a valid token, method without handler; `Methods/IdentityMethodHostTests` (switch default and
  selection, audit). A valid-token call through the real bus is verified on the local stack (see the PR).

## User role methods `SetRoles`, `AddRole`, `RemoveRole`

`UserSetRolesHandler`, `UserAddRoleHandler`, `UserRemoveRoleHandler` (`src/IdentityServices/Methods/`, shared flow in `UserRoleMethodHandlerBase<T>`) replace
or change the **direct** roles of a user (the `AssignedRole` association; roles inherited from groups are never read or written, as in REST). The rule is
**REST parity, never more**; the guards of `UsersController` (`PUT users/{u}/roles`, `PUT/DELETE users/{u}/roles/{r}`) are, and the handlers implement exactly this list:

| Guard of REST | In the method |
|---------------|---------------|
| write policy: scope `octo_api` (not `octo_api.read_only`) and tenant role `UserManagement` (`IdentityUserAdministrationWritePolicy`, `RoleEnforcement=Enforce`) | gateway checks the declared role; the handler checks scope + role again on the validated `CallerPrincipal` (forged bus message) -> `METHOD_FORBIDDEN`, `reason=role-required`. Warn mode of REST is not copied |
| user must exist (404) | `METHOD_TARGET_NOT_FOUND` (also for a target that is no object id and for an unknown tenant) |
| role must exist, by name, case-insensitive (404) | `ROLE_NOT_FOUND` with parameter `roleName` |
| AddRole of an assigned role (400) | `ROLE_ALREADY_ASSIGNED` |
| RemoveRole of a role that is not assigned (400) | `ROLE_NOT_ASSIGNED` |
| client-credentials tokens are judged by their client roles | a service token with `UserManagement` is allowed |

REST and the methods share the escalation rules of `IRoleChangeGuard` (next section); before it REST had no other rule and the methods copied that.
`SetRoles` takes role **names**, REST takes ids; both resolve every role first (one unknown role changes nothing) and write only the difference (REST used to remove all direct roles first).

Audit: the `Identity.Method` event of every call (success and every refusal, `IdentityMethodAuditWriter`) additionally carries `rolesBefore` and `rolesAfter`
(direct role names, sorted, comma separated; absent when the caller was refused before the target was read). Role methods are not behind
`Methods:Identity:EnablePasswordMethods` (`CarriesSecret = false`; the model-vs-registration test guards the flag). Tests: `Api/Methods/UserRoleMethodTests`
(every guard, case/duplicates, empty list, audit, forged caller, hosting), `UserRoleMethodParityTests` (REST and method side by side per guard, the
documented difference, self grant), `IdentityMethodHostTests`. The integration test factory removes the bus side of the method host
(`CkMethodHandlerStartupService`, heartbeat) because the test host has no broker.

## `User.ResetPassword`

`UserResetPasswordHandler` (`src/IdentityServices/Methods/`, one row in `IdentityMethodHost.Handlers`, `CarriesSecret = true`: offered on the
bus only with `Methods:Identity:EnablePasswordMethods`, off = `METHOD_HANDLER_NOT_AVAILABLE` for the gateway; `ServesRestFacade = true`: local
only while the switch is off, for the REST facade `POST users/ResetPassword`). A user administrator (`UserManagement`) sets a new password
without the current one.

- **Caller.** The SDK evaluates the declared role before the handler; the handler checks `CallerPrincipal.Roles` for `UserManagement` again
  (defense in depth, `METHOD_FORBIDDEN` / `missing-role`) **before** the tenant is bound or the target is looked up, so an unauthorized caller gets the same answer
  for an existing and a missing target and `METHOD_TARGET_NOT_FOUND` is only seen by an authorized one. Service tokens with the role are allowed
  (actor `client <id>`, the `AuditActor` form; a user caller is named by the user name looked up from `sub`). A user without the role cannot reset their own password with it (`ChangePassword` is for that).
- **Order.** role, tenant, user, shadow user (`SHADOW_USER_PASSWORD_NOT_ALLOWED`), remember `IsLockedOutAsync`, `GeneratePasswordResetTokenAsync` +
  `ResetPasswordAsync` (policy failure = `PASSWORD_POLICY_VIOLATION`, codes only, **nothing else changes, the lockout stays**), then
  `SetLockoutEndDateAsync(user, null)` + `ResetAccessFailedCountAsync(user)` through `UserManager` (guarded, versioned store write; never write the user
  entity directly), then `IUserCredentialChangeService.OnPasswordChangedAsync(..., PasswordChangePath.MethodResetPassword, <caller user name>)` (security
  stamp, revocation of refresh tokens and authorizations; throws on failure = `METHOD_HANDLER_FAILED`).
- **REST difference** (`UsersController.ResetPassword`; body-only, see "No credential values in request URLs" in `docs/credential-security.md`): REST does **not** lift the lockout and e-mails a second reset token; the method lifts
  the lockout and sends **no** e-mail (adds the notification).
- **Audit.** `IdentityMethodAuditWriter.RecordAsync(..., extraDetails)`: one `Identity.Method` event per call in a `finally` (success, every failure, and an
  exception as `METHOD_HANDLER_FAILED`), details as `ChangePassword` plus `lockoutLifted` (`true` only when the user was locked out at call time and the call succeeded).
- **Tests:** `Api/Methods/UserResetPasswordMethodTests` (real MongoDB; event repository and logger captured: locked-out user end to end, counter-only user,
  service token, missing role for existing and missing target, unknown target, policy violation, shadow user, failing revocation, forged caller on the host;
  password canary never in audit events or logs), `IdentityMethodHostTests` (switch, audit details).

## Group and data-permission methods

`Group.AddMember`, `Group.RemoveMember`, `Group.SetRoles`, `DataPermission.GrantToRole`, `DataPermission.RevokeFromRole` (declared in System.Identity 2.29.0,
no model change). Five handlers in `src/IdentityServices/Methods/` (`GroupMemberMethodHandlerBase<T>` with `GroupAddMemberHandler` / `GroupRemoveMemberHandler`,
`GroupSetRolesHandler`, `DataPermissionRoleMethodHandlerBase<T>` with `DataPermissionGrantToRoleHandler` / `DataPermissionRevokeFromRoleHandler`) and five rows in
`IdentityMethodHost.Handlers`, all `CarriesSecret = false` (hosted whatever `EnablePasswordMethods` says). Shared flow in `IdentityAdminMethodHandlerBase<T>`
(caller rule, target id, tenant binding, one `Identity.Method` event per call in a `finally`); `IdentityMethodCallerRules.IsAdministrator` is the same rule the
user role handlers use (scope `octo_api` + role `UserManagement` on the **validated** principal, `METHOD_FORBIDDEN` / `role-required` otherwise).

| Rule | REST (`GroupsController`, `DataPermissionsController`) | Method |
|------|------|------|
| Caller | `IdentityUserAdministrationWritePolicy` | the same, repeated on the validated principal; forged bus caller rejected by the host |
| Target | 404 for an unknown group (data permission: unhandled exception) | `METHOD_TARGET_NOT_FOUND` |
| Guard | `IRoleChangeGuard.EvaluateAsync(caller, RoleGraphChange.MemberAdded / MemberRemoved / GroupRoles)`: `self-grant`, `role-not-held`, `last-administrator` (403 / 409 problem) | the same call with the same change records; refusal = `METHOD_FORBIDDEN` + parameter `reason` (+ `roleNames`), audited with `reason` |
| Client removal | no guard (a client gives nothing to anybody); records the scratch tenant revocation before the removal | the same, same `IScratchTenantGrantService.RecordRevocationAsync` |
| Data permission grant / revoke | no guard (data access, not roles) | none either |
| Unknown or duplicate member / role | engine error 500 / silent no-op | typed errors `MEMBER_NOT_FOUND`, `MEMBER_ALREADY_IN_GROUP`, `MEMBER_NOT_IN_GROUP`, `ROLE_NOT_FOUND`, `PERMISSION_ALREADY_GRANTED`, `PERMISSION_NOT_GRANTED` (stricter, never more) |

- **Member ids.** `memberKind` User or Client; `memberId` is the rtId (as in the REST route); for a client the OAuth client id is accepted too. `Group.SetRoles`
  takes role **names** (the model's parameter) and resolves them to the role ids the guard judges (`GroupRoles(groupId, roleIds)`); all names are checked first
  (one unknown role changes nothing).
- **Referenced entities.** The target is checked by the gateway (`dataAccess: Write`). Members and roles the method touches besides the target are checked
  with `IRtDataPermissionEvaluator` (`IdentityMethodCall.EvaluateAsync`, the caller's `RtSecurityContext` from the validated principal): not visible = `MEMBER_NOT_FOUND` /
  `ROLE_NOT_FOUND`; `DataPermission.GrantToRole` additionally needs `Write` on the role (the grant is stored on it), refusal = `METHOD_FORBIDDEN` / `reason` = `data-permission`.
  Without enforcing policies on those types (the default) every check is open, as in REST.
- **Data permission methods check their target themselves.** The REST endpoints are facades that call in-process, where no gateway checks
  `dataAccess`. `DataPermission.GrantToRole` / `RevokeFromRole` (and `DataPolicy.SetEnforcementMode`, next section) therefore evaluate the target permission
  (policy) for `Write` first (`IdentityMethodCall.CheckTargetWritableAsync`): not visible = `METHOD_TARGET_NOT_FOUND`, readable but not writable = `METHOD_FORBIDDEN` /
  `data-permission`. **Revoking from a role the caller cannot read** while the role holds the permission is `METHOD_FORBIDDEN` / `data-permission`, not
  `ROLE_NOT_FOUND`: the grant is visible through the permission (REST lists `grantedRoleNames`), a success without a change would mislead, and a change behind
  the caller's back is what the check prevents (CWE-863); a role that holds no grant still answers `ROLE_NOT_FOUND`. `METHOD_FORBIDDEN` is a platform code,
  so no declared error list changes (no M8).
- **Audit.** `Identity.Method` event per call (success, every refusal, exception as `METHOD_HANDLER_FAILED`): group methods add `memberKind`, `memberId`, `rolesBefore` /
  `rolesAfter` (role names, `SetRoles`) and `reason` / `roleNames` of a guard refusal; data permission methods add `permissionId` and `roleName`. Identifiers only.
- **Nothing is revoked.** A group change shows in the next token (`OctoTokenClaimsService` reads the effective roles, groups included), as with REST.
- **Tests:** `Api/Methods/GroupMethodTests` (all operations, every refusal, caller theory, forged caller, audit, evaluator), `GroupMethodParityTests` (REST and method side
  by side per guard), `DataPermissionMethodTests` (operations, errors, caller theory, forged caller, REST parity, audit, evaluator), `Methods/IdentityMethodHostTests`
  (selection). The last-administrator tests clear the administrators of the shared test database first, like `GroupRoleChangeGuardTests`.

## Child group methods `Group.AddChildGroup`, `Group.RemoveChildGroup` (System.Identity 3.3.0)

Nested groups (`ChildGroup` association). Own methods, not a third `GroupMemberKind` value: the cycle refusal needs its own error code, and
an error code added to `Group.AddMember-1` is a Major. Handlers in `Methods/GroupChildGroupHandlers.cs` (`GroupChildGroupHandlerBase<T>` on
`IdentityAdminMethodHandlerBase<T>`: caller `UserManagement`, one `Identity.Method` event per call with `memberKind` `Group` and `memberId`).

- **Parameter** `childGroupId` (rtId). Not an object id, not existing, or not readable by the caller = `CHILD_GROUP_NOT_FOUND`.
- **AddChildGroup** order (as the REST endpoint): group, child group, a group in itself (`GROUP_CYCLE`, parameter `cycle` = `self`), already a
  member (`CHILD_GROUP_ALREADY_IN_GROUP`), a cycle - the group reachable from the child through its child groups, depth-first
  (`GroupGraph.WouldCreateCycleAsync`; `GROUP_CYCLE`, `cycle` = `descendant`), the role change guard (`RoleGraphChange.MemberAdded` with
  `GroupMemberKind.Group`), write.
- **RemoveChildGroup**: not a member = `CHILD_GROUP_NOT_IN_GROUP`; a member the caller cannot read = `METHOD_FORBIDDEN` (`data-permission`); guard
  `MemberRemoved`; the edge to a group that no longer exists is still removed. `Group.RemoveMember` refuses an unreadable member of the group the same way.
- `execution`: timeout 30 s, not idempotent (a repeated call answers the typed error). REST facades: `docs/identity-rest-facades.md`.

## Client role and overlay methods (System.Identity 3.3.0)

`Client.SetRoles-1`, `Client.AddRole-1`, `Client.RemoveRole-1`, `Client.ApplyOverlayUris-1` and the static `Client.CleanOverlayEntries-1`.
Roles `TenantManagement` or `UserManagement` (the REST policy `IdentityTenantAdministrationWritePolicy` of `ClientsController`),
`dataAccess: Write`; the handlers repeat the rule on the validated principal (`IdentityMethodCallerRules.IsTenantAdministrator`). No secret:
hosted whatever `EnablePasswordMethods` says.

| Method | Parameters | Result | Errors | Idempotent / timeout |
|---|---|---|---|---|
| `SetRoles` | `roleNames` (complete list) | - | `ROLE_NOT_FOUND` | yes / 30 s |
| `AddRole` | `roleName` | - | `ROLE_NOT_FOUND` | yes (a role held directly is a success without a write) / 30 s |
| `RemoveRole` | `roleName` | - | `ROLE_NOT_FOUND` | yes (a role not held is a success) / 30 s |
| `ApplyOverlayUris` | `overlayName`, optional `redirectUris`, `postLogoutRedirectUris`, `allowedCorsOrigins` | `ClientOverlayUrisResult` (added / skipped per list) | `INVALID_OVERLAY_NAME`, `NO_OVERLAY_URIS`, `CONCURRENT_CHANGE` | yes (a re-run adds and writes nothing) / 30 s |
| `CleanOverlayEntries` (static) | optional `overlayName` | `ClientOverlayCleanResult` (clients affected, entries removed, one `ClientOverlayCleanEntry` per changed client) | `INVALID_OVERLAY_NAME`, `CONCURRENT_CHANGE` | yes / 60 s |

- **Roles** (`Methods/ClientRoleHandlers.cs`, `ClientRoleMethodHandlerBase<T>`): only the direct roles (`AssignedRole`) are read and written,
  only the difference is written (`IClientRoleStore.ApplyRoleChangesAsync`), so a kept role is never written again. A role that is unknown or
  not readable is `ROLE_NOT_FOUND` and nothing changes; removing a held role the caller cannot read (`RemoveRole`, or dropping it in
  `SetRoles`; `Group.SetRoles` the same) is `METHOD_FORBIDDEN` (`data-permission`). `rolesAfter` in the audit is read back from the store after the write. Every added role runs `IRoleChangeGuard.EvaluateClientGrantAsync`: a built-in role the
  caller does not hold (`role-not-held`) and any role for a client-credentials caller's own client (`self-grant`) are refused with
  `METHOD_FORBIDDEN` - the same answer as `User.AddRole`. Removals are never judged. Audit: `clientId`, `rolesBefore`, `rolesAfter`.
- **Overlay URIs** (`Methods/ClientOverlayHandlers.cs`, rules in `ClientOverlayUris`): an overlay URI is written with
  `Source = "overlay:<overlayName>"`; a URI already in the list (any source, ordinal) is skipped; blanks are ignored. Every write is one
  version-checked read-modify-write through `IOctoClientStore.MutateAsync`; nothing is written when nothing changes. `ApplyOverlayUris`
  publishes the CORS client refresh after every successful call; `CleanOverlayEntries` once when anything was removed. Audit details are
  counts and the overlay name, never a URI.
- **Result records** (`records/ck-clientOverlayResults.yaml`, attributes `attributes/clientOverlayResult-attributes.yaml`, `RuntimeState`): the
  shape of the REST responses, flattened per list.
- REST facades and parity tables: `docs/identity-rest-facades.md`. Tests: `Api/TenantApi/ClientRestMethodFacadeTests`,
  `Methods/IdentityMethodHostTests`, the `ClientsController*` unit tests.

## `DataPolicy.SetEnforcementMode` (System.Identity 3.4.0)

`DataPolicySetEnforcementModeHandler` (`Methods/DataPermissionRoleMethodHandlerBase.cs`, one row in `IdentityMethodHost.Handlers`, `CarriesSecret = false`) switches a
data policy between `Enforce` and `AuditOnly` (parameter `enforcementMode`, enum `DataPolicyEnforcementMode`). Caller rule of REST
(`IdentityUserAdministrationWritePolicy`: `octo_api` + `UserManagement`), target = the policy rtId, evaluated for `Write` first (see above), then the data permission the policy is bound to (`PolicyPermission`; the mode decides
whether that permission is enforced at all, so switching it is a change of the permission too). The mode the policy
already has is a success without a write. The write goes through `IDataPermissionStore.SetPolicyEnforcementModeAsync`, as REST did; after every successful call
(also when the mode was already set) the handler invalidates the cached policy table of this process (`IDataPermissionResolver.Invalidate`), so the identity replica that served the call applies the
new mode at once. Other identity replicas and every other service that evaluates data policies (asset repository, mesh adapter, report and bot services)
pick it up only when their cached table expires (TTL 60 s, no invalidation event): up to one minute after the switch they may still apply the old mode. The mode changes
data visibility tenant-wide, so the `Identity.Method` event carries `enforcementModeBefore` and `enforcementModeAfter`. REST facade:
`PUT dataPermissions/policies/{policyRtId}/enforcementMode`. Tests: `Api/TenantApi/DataPermissionRestMethodFacadeTests` (REST and method switch to Enforce give the
same fail-closed read verdict).

## Secret methods `Client.AddSecret`, `Client.UpdateSecret`, `Client.RemoveSecret`, `ApiResource.AddSecret`, `ApiResource.UpdateSecret`, `ApiResource.RemoveSecret`

`ClientAddSecretHandler` and `ClientRemoveSecretHandler` (declared in System.Identity 2.29.0), `ClientUpdateSecretHandler`, `ApiResourceAddSecretHandler`,
`ApiResourceUpdateSecretHandler` and `ApiResourceRemoveSecretHandler` (System.Identity 3.4.0), all in `src/IdentityServices/Methods/ClientSecretHandlers.cs`.
The shared flow is `SecretOwnerMethodHandlerBase<TOwner>` (`ClientSecretMethodHandlerBase.cs`): caller rule, target, **data permission of the owner**,
generate / update / remove, version-checked write, cache event and audit; `ClientSecretMethodHandlerBase` (owner `RtClient`, mirror sync after the write) and
`ApiResourceSecretMethodHandlerBase` (owner `RtApiResource`) only name the owner and its secret list. Six rows in `IdentityMethodHost.Handlers`, all
`CarriesSecret = true` (a `sensitive` result or `secretValue`) and `ServesRestFacade = true`: **offered on the bus only with
`Methods:Identity:EnablePasswordMethods`** (off = `METHOD_HANDLER_NOT_AVAILABLE` for the gateway) and registered **local only** while it is off, because the REST
secret write endpoints of `ApiSecretsController` are their facades (`docs/identity-rest-facades.md`).

- **Update** (`UpdateSecret`): names the secret like `RemoveSecret` (stored value or clear text), replaces description and expiration date of the first match
  (an omitted value is cleared, as the REST `PUT` did), keeps value and `Type`; an expiration in the past is accepted (it retires the secret); the reserved mirror
  description is refused as on `AddSecret`, and so is any update of a mirror's own secret (the record that carries it). Errors `SECRET_NOT_FOUND`, `CONCURRENT_CHANGE`.
- **API resource** (introspection secrets): the same generator, format, rules and audit as the client methods (the owner has no public variant, so no
  `CLIENT_SECRET_NOT_REQUIRED`); audit detail `apiResourceName` instead of `clientId`.
- **Owner data permission.** Before anything is changed the owner is evaluated for `Write` with the caller's roles: not visible =
  `METHOD_TARGET_NOT_FOUND`, readable but not writable = `METHOD_FORBIDDEN` / `data-permission`. Open without an enforcing policy on the owner type.
- **Concurrency.** `CONCURRENT_CHANGE` after 20 lost version-checked writes on the four new methods; `Client.AddSecret` / `Client.RemoveSecret` keep their error list
  (a new code would be a Major, row M8) and answer `METHOD_HANDLER_FAILED` in that case.

| Rule | REST before the facades (`ApiSecretsController`) | Method |
|------|------|------|
| Caller | `IdentitySecretAdministrationPolicy` (`octo_api` + `SecretManagement`, staged: in `Warn` also `TenantManagement`/`UserManagement`) | the same, repeated on the validated principal (`DecideClientSecretCaller`) before the target is read: `METHOD_FORBIDDEN` / `role-required`, identical for an existing and a missing target; forged bus caller rejected by the host |
| Target | client id in the route, 404 | target rtId of the client; unknown, not an object id or unknown tenant = `METHOD_TARGET_NOT_FOUND` |
| Generate | 32 bytes CSPRNG, URL-safe Base64, stored as Base64 SHA-256 | the same (`ClientMirrorSecrets.GenerateSecret`, `OctoSecretHasher.HashSecret`), record `Type = SharedSecret`; the clear text is the result, returned once |
| Public client | accepted | `CLIENT_SECRET_NOT_REQUIRED` (it never authenticates with a secret) |
| Expiration in the past | accepted | `METHOD_VALIDATION_FAILED` (`field=expirationDate`) |
| Remove | by the stored value (Base64 in the route); 404 without the value (since the predicate delete; before it, the delete removed nothing, see below) | by the stored value **or** the clear text (hashed, fixed-time compare); every match removed with `RemoveAll`; no match = `SECRET_NOT_FOUND` without parameters |
| Write | `IOctoClientStore.MutateAsync` (version-checked, mirror sync) + `CorsClientsUpdate` | version-checked read-modify-write of the client (`MutateClientAsync`: read, change, replace with the read `rtVersion`, re-read and re-apply on `RtVersionConflictException`, 20 attempts), so concurrent adds keep every secret and an add never brings a removed secret back; then mirror sync and `CorsClientsUpdate`, both best effort (5 s bound for the publish: a committed change is never reported as failed) |
| Description | free text | `octo:mirror-own-secret` (the marker of a mirror's own secret) = `METHOD_VALIDATION_FAILED` (`field=description`) |

- **Authentication** goes through `OctoApplicationManager` (every unexpired record of the client), so a new secret authenticates at once and a removed one
  fails at once (entity caching is off).
- **Audit:** one `Identity.Method` event per call in a `finally` (success, every refusal, exception = `METHOD_HANDLER_FAILED`), details as the other methods plus
  `clientId`, `secretCount` (records after the write) and, for RemoveSecret, `removedCount`. Never the secret, the hash, `secretValue` or the description.
- **Secrets in logs:** the handlers log nothing. The engine's MongoDB command log at **Debug** (`MongoRepositoryClient`, off by default) renders the update
  command and therefore the stored hash of every client secret write (REST included); the clear text never reaches a log.
- **Tests:** `Api/Methods/ClientSecretMethodTests` (real MongoDB, real token endpoint: add -> stored value is the hash -> client credentials token OK ->
  remove -> token refused; remove by stored value; UserManagement and service token callers; caller theory without role/scope for existing and missing
  target; unknown target; public client; expiration; unknown value without echo; failing store audited; forged caller on the host; canary: the secret and a
  clear-text `secretValue` in no audit event and no log line at any level, the hash in none at Information or above; parallel adds + remove lose no
  update; reserved description; broker down still returns the committed secret), `Methods/IdentityMethodHostTests` (gate and caller rule),
  `Methods/ClientSecretHandlerFailureTests` (an exception is audited once as `METHOD_HANDLER_FAILED`), `Api/TenantApi/SecretRestMethodFacadeTests`
  (every REST write runs its method in-process with one event and nothing on the broker, both switch values; REST and method side by side for add, update,
  expired secret, unknown value, duplicate records and unknown owner, client and API resource; canary of the clear text; `SecretManagementRoleEnforcement=Enforce`
  on both paths; another tenant's token, a caller without the role; an owner the caller cannot read or write).

## Client mirror methods (System.Identity 3.5.0)

Instance methods on the **parent** client: the method runs in the parent tenant, the handler writes into the child tenant through
`IClientMirrorProvisioningService` (`Methods/ClientMirrorHandlers.cs`, shared flow `ClientMirrorMethodHandlerBase<TParameters, TOutcome>`). Roles
`TenantManagement` or `UserManagement` (REST `IdentityTenantAdministrationWritePolicy`), the rotation also `SecretManagement` (REST
`IdentitySecretAdministrationPolicy`, staged by `SecretManagementRoleEnforcement` exactly like the secret methods); `dataAccess: Write`.

| Method | Parameters | Result | Errors | Idempotent / timeout |
|---|---|---|---|---|
| `ProvisionMirrors` | - | `ClientMirrorBackfillResult` (child tenants considered, newly provisioned, already present) | `AUTO_PROVISION_DISABLED`, `BACKFILL_NOT_STARTED` | yes / 300 s |
| `ProvisionMirrorInTenant` | `childTenantId` | `ClientMirrorProvisionResult` (flagged clients considered, newly provisioned, already present) | `AUTO_PROVISION_DISABLED` | yes / 120 s |
| `RotateMirrorSecret` | `childTenantId` | `String`, **sensitive** (the new secret, once) | `MIRROR_NOT_FOUND`, `CLIENT_SECRET_NOT_REQUIRED` | no / 60 s |
| `RemoveMirror` | `childTenantId` | - | `MIRROR_NOT_FOUND` | no / 60 s |
| `SetMirrorAutoProvision` | `enabled` | - | `CONCURRENT_CHANGE` | yes / 30 s |

- **Order of checks, before any write in either tenant:** caller rule -> target client exists (`METHOD_TARGET_NOT_FOUND`) -> the caller may read
  **and** write the parent client (`IRtDataPermissionEvaluator`: not visible = `METHOD_TARGET_NOT_FOUND`, read only = `METHOD_FORBIDDEN` /
  `data-permission`) -> a named child tenant lies in the subtree of the caller's token tenant (`CrossTenantMethodSupport.CheckTargetTenantAsync`, the
  rule `AdminProvisioningTargetScope` that the REST filter uses; `RoleEnforcement=Warn` stages it only for REST facade calls, a bus
  or GraphQL call is refused in either mode) -> the mirror service checks it again against the parent
  tenant's subtree. A child outside either subtree is `METHOD_FORBIDDEN` with `reason = tenant-out-of-scope`; nothing is written in the child tenant.
- **Caller tenant.** `CkMethodPrincipal.TokenTenantId` (the `tenant_id` claim, set on both transports), else `TenantId` (validated by the bus host);
  none = out of scope (fail closed). Not the tenant of the call: an allow-listed cross-tenant service client is judged by its own tenant.
- **Rotation.** `CarriesSecret = true`, `ServesRestFacade = true`: bus handler only with `EnablePasswordMethods`, else local only for its REST facade. The
  secret is minted and stored as the mirror's own secret (description marker `octo:mirror-own-secret`, so the mirror sync and the reconciliation keep it);
  the clear text is only the result. Audit details never carry it or its hash.
- **Audit:** one `Identity.Method` event per call: `clientId`, `childTenantId`, `enabled` (flag), `newlyProvisioned` (backfill), `reason` on a refusal.
- REST facades and parity table: `docs/identity-rest-facades.md`. Tests: `Api/TenantApi/ClientMirrorRestMethodFacadeTests`,
  `Controllers/ClientMirrorControllerTests`, `Methods/IdentityMethodHostTests`, `Persistence/IdentityMethodDeclarationsIntegrationTests`.

## Admin provisioning and the mapping create (System.Identity 3.5.0)

Static methods on `System.Identity/ExternalTenantUserMapping` (`Methods/AdminProvisioningHandlers.cs`); the provisioning writes are
`AdminProvisioning/AdminProvisioningService.cs` (moved out of `AdminProvisioningController`, created per call from the invocation's services). They
are the Feature's `Tenant.ProvisionAdmin`.

| Method | Parameters | Result | Errors | Roles / timeout |
|---|---|---|---|---|
| `ProvisionAdmin` | `targetTenantId`, `sourceTenantId`, `sourceUserId`, `sourceUserName`, optional `roleIds` | `AdminProvisioningResult` | `TENANT_NOT_FOUND`, `SOURCE_TENANT_NOT_ANCESTOR`, `MAPPING_ALREADY_EXISTS` | `TenantManagement`, `UserManagement` / 60 s |
| `ProvisionAdminWithGroups` | `targetTenantId`, `sourceTenantId`, `sourceUserId`, `sourceUserName`, optional `groupIds` | `AdminProvisioningResult` | as `ProvisionAdmin` | `TenantManagement`, `UserManagement` / 60 s |
| `ProvisionCurrentUser` | `targetTenantId` | `AdminProvisioningResult` with `outcome` = `created` / `repaired` / `already-provisioned` | `TENANT_NOT_FOUND`, `CALLER_NOT_A_USER`, `HOME_IDENTITY_UNRESOLVED`, `TENANT_INITIALIZING` | `TenantManagement`, `UserManagement` / 90 s, idempotent |
| `RemoveAdminProvisioning` | `targetTenantId`, `mappingRtId` | - | `TENANT_NOT_FOUND`, `MAPPING_NOT_FOUND` | `TenantManagement`, `UserManagement` / 60 s |
| `CreateMapping` | `sourceTenantId`, `sourceUserId`, `sourceUserName`, optional `roleIds`, `groupIds` | `AdminProvisioningResult` | `SOURCE_TENANT_NOT_PERMITTED`, `MAPPING_ALREADY_EXISTS`, `UNKNOWN_GROUP` | `UserManagement` / 60 s |

- **Target tenant first.** The `ProvisionAdmin*`, `ProvisionCurrentUser` and `RemoveAdminProvisioning` methods run in the caller's tenant and check
  `targetTenantId` against the caller's token tenant subtree before any lookup (`METHOD_FORBIDDEN`, `reason = tenant-out-of-scope`); a caller of the
  system tenant reaches every tenant. Then the rules of the REST endpoints: target exists, source tenant is a registry ancestor of the target
  (`ICrossTenantAncestryGuard`), one mapping per source user (`existingMappingId` names the existing one), the source tenant becomes the target's login
  parent (`OctoTenantIdentityProvider`), a mapping that carries `TenantManagement` joins `TenantOwners`.
- **`ProvisionCurrentUser`** provisions the validated caller (subject + token tenant), never a parameter; a cross-tenant shadow user as its home identity.
  The user name is the one stored in the caller's tenant (the method caller carries no profile claims). A target that is still initializing is retried
  with back-off (10 attempts), then `TENANT_INITIALIZING`.
- **`CreateMapping`** writes into the tenant of the call with the cross-tenant checks of the REST create (`ISourceTenantGrantAdmission`, duplicates,
  groups, `IRoleChangeGuard` with `RoleGraphChange.MappingRoles`); a guard refusal is `METHOD_FORBIDDEN` + `reason` (+ `roleNames`). It does not set
  `replacesGenericCreate` (a Major on the existing type, row M16; next major).
- **Audit:** one `Identity.Method` event per call (`targetTenantId`, `sourceTenantId`, `mappingRtId`, `provisioningOutcome`, `reason`), plus the cross-tenant grant
  events (`Identity.CrossTenantGrantCreated/Changed/Removed`) as before, with the caller's stored user name (a service caller: its client id).
- REST facades and parity table: `docs/identity-rest-facades.md`. Tests: `Api/TenantApi/AdminProvisioningRestMethodFacadeTests`, the controller-level
  persistence suites through `ProvisioningMethodTestFacade`, `Controllers/AdminProvisioningDeleteAuditTests`.

## Target data permission in the handlers

Every handler of an instance method that a REST facade calls evaluates its target with `IdentityMethodCall.CheckTargetWritableAsync`
(not readable = `METHOD_TARGET_NOT_FOUND`, read only = `METHOD_FORBIDDEN` / `data-permission`), the check the GraphQL gateway runs before
dispatch: in `IdentityAdminMethodHandlerBase` for all its methods (target type from the registered method id), in `UserRoleMethodHandlerBase`,
`UserResetPasswordHandler`, `ClientApplyOverlayUrisHandler`, `SecretOwnerMethodHandlerBase` and `ClientMirrorMethodHandlerBase`. List of the REST
answers this changed: `docs/identity-rest-facades.md` ("The target's data permission on every facade").
