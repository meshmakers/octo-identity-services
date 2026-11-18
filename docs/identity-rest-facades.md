---
description: "REST facades of the identity methods (users, groups, clients, secrets, data permissions, CRUD); deprecation waves; account pages"
applies_to: "{IdentityMethodFacade,IdentityRestDeprecation,UsersController,ManageApiController,RoleChangeProblems,ResetUserPasswordRequestDto,ApiSecretsController,DataPermissionsController,ClientMirrorController,AdminProvisioningController,RolesController,GroupsController,ApiScopesController,ApiResourcesController}.cs"
---

# REST facades, deprecations and account pages

## REST facades of the role and merge endpoints

`UsersController.UpdateUserRoles` (`PUT users/{u}/roles`), `AddUserToRole` (`PUT users/{u}/roles/{r}`), `RemoveRoleFromUser`
(`DELETE users/{u}/roles/{r}`) and `MergeUsers` (`POST users/{u}/merge`) are **facades** of `User.SetRoles-1`, `User.AddRole-1`,
`User.RemoveRole-1` and `User.Merge-1`. They contain no role-change or merge rule of their own (no `AddToRoleAsync`,
`RemoveFromRoleAsync` or `IUserMergeService` call): they resolve the user name to the rtId (and SetRoles the role ids to names),
call the method through `IIdentityMethodFacade` (`src/IdentityServices/Methods/IdentityMethodFacade.cs`) and map the envelope with
`CkMethodFacadeResults.ToActionResult` (octo-common-services) plus per-endpoint `CkMethodFacadeOptions`.

- **In-process.** `IdentityMethodHost.AddIdentityCkMethodHost` registers `AddCkMethodDispatcher()` and the facade; `Program.cs` adds
  `AddCkMethodHandlerRegistryFeed()` to the event hub. The identity service hosts the handlers, so the dispatcher runs them in this
  process (transport `in-process`, nothing on the broker, same invocation core as a bus call: declared authorization, validation,
  audit, `ck.method.*` metrics). The four methods carry no secret and are hosted whatever `Methods:Identity:EnablePasswordMethods`
  says, so the endpoints work on every cluster. The create and reset facades (see the next section) and the account pages reuse
  `IIdentityMethodFacade` (password methods with `HandleLocalOnly` while the switch is off).
- **Caller.** `CkMethodPrincipal.FromClaimsPrincipal(User)` in a `CkMethodPrincipalScope`. The write policy of the endpoints already
  requires scope `octo_api` and role `UserManagement`, which is what the handlers check again; no token reaches the facade without it.
- **Audit.** Every REST call writes exactly one `Identity.Method` event (the handler's). A guard refusal (`METHOD_FORBIDDEN` with
  `reason` `self-grant` / `role-not-held` / `last-administrator`) is turned back into the role-change-guard answer: 403/409 problem+json via
  `RoleChangeProblems`, the WARN log and the `Identity.RoleChangeRefused` record (REST contract, kept).

Parity table (REST before -> facade; the method wins unless the REST contract would change):

| Point | REST before | Now |
|---|---|---|
| Routes, request and response bodies, status codes | - | unchanged (success `200` empty, `MapSuccess`) |
| User / role not found | 404 `NotFoundErrorDto` | unchanged: resolved in the controller; `METHOD_TARGET_NOT_FOUND` / `ROLE_NOT_FOUND` (race) map to the same 404 |
| SetRoles unknown role id | 404, nothing changed | unchanged (ids resolved before the call) |
| AddRole of a role held **through a group** | 400 "already has role" (`IsInRoleAsync`) | **kept** in the facade (read-only `IsInRoleAsync` pre-check); the method alone would add the direct role |
| RemoveRole of a role held **only through a group** | 200, nothing changed | **kept**: `ROLE_NOT_ASSIGNED` maps to 200; audit outcome `ROLE_NOT_ASSIGNED` |
| Guard refusals | 403/409 problem, `Identity.RoleChangeRefused`, WARN | unchanged, plus the `Identity.Method` event |
| Audit of a success | none | one `Identity.Method` event (`rolesBefore`/`rolesAfter`; merge: `sourceUserName`, `sourceRtId`, `transferredLogins`, `revokedTokens`) |
| Merge source data permission | none | method wins: not readable = 404 "Source user ... not found", not writable = 403 problem `METHOD_FORBIDDEN` (`data-permission`) |
| Merge login/delete failure | 400, `failedDetails` with code + description | 400, same message, `failedDetails` with `code` only (the envelope carries codes) |
| Unexpected failure | merge: 500 `InternalServerErrorDto(exception message)`; roles: unhandled 500 | merge: 500 `InternalServerErrorDto("Merging the users failed.")`; roles: 500 problem `METHOD_HANDLER_FAILED`; no exception text leaves the service |
| `RoleEnforcement=Warn` (not the default) | caller without `UserManagement` let through and logged | **intended REST change:** refused by the method (403 problem, `role-required`), as for the user facades - a method has no staged warn mode, and `Enforce` is the default |
| Merge `sourceUserName` | as sent | trimmed by the method |

Fix on the way: `UserMergeHandler` looked the acting user up by `sub` and threw for a subject that is no object id; it now skips
the lookup. Tests: `Api/TenantApi/UserRestMethodFacadeTests` (one `Identity.Method` event per REST call incl. refusal and merge,
REST and the dispatcher call side by side, in-process transport, both switch values, group-inherited role contract) plus the
unchanged REST suites (`RoleChangeGuardTests`, `UsersMergeTests`, `UserRoleMethodParityTests`, `TenantApiRoleAuthorizationTests`).
`UserMergeMethodTests.Method_MergingAwayTheLastUserAdministrator…` now expects two `Identity.Method` events (its method call and its
REST call each write one).

## Deprecation of the role and merge endpoints: identity wave 1

The four endpoints above carry `[OctoRestDeprecated(Wave = IdentityRestDeprecation.UsersWave1, Link = …)]`
(`src/IdentityServices/TenantApi/v1/IdentityRestDeprecation.cs`; `octo-common-services/docs/rest-deprecation.md`). Links:
`User.SetRoles/AddRole/RemoveRole` -> `…/identityService/methods#user-roles`, `User.Merge` -> `…#usermerge`.

- **No dates in code.** Wave dates (Gerald 2026-11-11, replaces the rules of 2026-11-07 and 2026-11-10): since
  **2026-11-08** (first prod delivery of r3.5.68, the first release with 33d0dbbe), sunset **to be announced** — no fixed
  compatibility window, Gerald decides the date once the migration functions are implemented; until then `sunset` stays empty
  and no `Sunset` header is sent. Removal only on the `octo.rest.deprecated.calls` evidence. Set in `octo-mesh-deployment`
  `base/values-octo-mesh.yaml` (all clusters, effective with each cluster's next deploy). Both dates come from `RestDeprecation:Waves:IdentityUsers1:Since|Sunset`
  (env `OCTO_RestDeprecation__Waves__IdentityUsers1__Since|Sunset`, Helm `restDeprecation.waves.IdentityUsers1.since|sunset` in
  octo-helm-core). Unset -> no `Deprecation`/`Sunset` header; `Link`, OpenAPI `deprecated` and the counter
  `octo.rest.deprecated.calls` always apply. An invalid configured date fails the start.
- **Not in this wave**: `POST users` and `POST users/ResetPassword` (own wave `IdentityUsersPassword`, next section) and the
  account pages of `ManageApiController` (facades without deprecation, decided 2026-11-07).
- **Tests**: `Api/TenantApi/UsersRestDeprecationTests` — headers per endpoint with and without configured dates, a counted
  successful call (`client_id` `octo-cli`, endpoint template, no user name or tenant), unmarked user endpoints without headers,
  exactly the wave endpoints carry the attribute (four of wave 1, two of the password wave).

## Deprecation of create user and admin reset: identity password wave

`POST users` and `POST users/ResetPassword` carry `[OctoRestDeprecated(Wave = IdentityRestDeprecation.UsersPasswordWave, Link = …)]`
(wave `IdentityUsersPassword`; links `…/identityService/methods#usercreateuser` and `…#userresetpassword`). A wave of its own
because it starts with another release than wave 1: `since` is the delivery day of the release that contains the password wave (octo-cli and
octo-mcp-service call the methods), set by Ops in `octo-mesh-deployment` (`restDeprecation.waves.IdentityUsersPassword.since`,
env `OCTO_RestDeprecation__Waves__IdentityUsersPassword__Since|Sunset`); sunset to be announced (Gerald's rule of 2026-11-11, as
wave 1). The Helm chart renders every wave generically, no chart change. Without dates the endpoints answer exactly as before; only
`Link`, the OpenAPI flag and the counter are added. The headers are computed from the attribute and the configuration only, never
from the request, so no user name, e-mail or password reaches a header or a metric label. Not changed: the REST reset still sends
the password-reset e-mail, the method does not. SDK side: `IIdentityServicesClient.CreateUser` / `ResetPassword` are
`[Obsolete]` (octo-sdk).
Tests: `Api/TenantApi/UsersPasswordRestDeprecationTests` (headers with dates, since without sunset, both endpoints without dates
behave as before, successful calls counted, request canaries in no header and no label); the endpoint set is pinned in
`UsersRestDeprecationTests`. Shared collector: `Api/TenantApi/DeprecatedCallCollector`.

## REST facades of create user and password reset

`UsersController.Post` (`POST users`) and `UsersController.ResetPassword` (`POST users/ResetPassword`) are **facades** of the static
`User.CreateUser-1` and of `User.ResetPassword-1`, through `IIdentityMethodFacade` like the role and merge endpoints (the target
rtId is `null` for the static create). Creation, policy, lockout, session revocation and audit exist only in the handlers.

- **Password in-process only, whatever the switch says.** With `Methods:Identity:EnablePasswordMethods=false` (staging-1, prod-1, prod-2
  until B0) the two handlers are registered with `HandleLocalOnly` (`IdentityMethodHandlerRegistration.ServesRestFacade`,
  `IdentityMethodHost.SelectLocalOnlyHandlers`): not announced, no queue, so GraphQL `User.CreateUser` / `User.ResetPassword` still answer
  `METHOD_HANDLER_NOT_AVAILABLE` and no password reaches the broker. With the switch on they are bus handlers and the dispatcher still runs the
  REST call in-process. One row in `IdentityMethodHost.Handlers` stays the single list (`For<THandler>(id, carriesSecret,
  servesRestFacade)` builds both registration forms).
- **Notification.** The method does not send the password-reset notification yet; the facade sends it after a success. When
  the follow-up that removes the duplicate notification lands, remove that call: `UserPasswordRestMethodFacadeTests` counts exactly one notification per REST reset.
- **REST-only field.** `RegisterUserDto.ResetPasswordOnLogin` has no method parameter; when true the facade sets it on the new user after the
  method returned (the rtId is the bare result string). If the user is not found or that update fails, the endpoint answers `500`
  (`ResetPasswordOnLoginNotSetMessage`), never `200` — the user then exists without the flag (`RestCreate_ResetPasswordOnLoginWriteFails_Is500_NotASilentSuccess`).
- **Error bodies.** The envelope carries only rule codes; the facade rebuilds the REST `details` (code + description) of a policy violation or an
  invalid user name / e-mail from `UserManager.ErrorDescriber` and the password options, so `OperationFailedErrorDto` keeps its shape.

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, request and response bodies, status codes | - | unchanged (create and reset: `200` empty) |
| `EnablePasswordMethods=false` | own code, worked | works: handlers local only, in-process, nothing on the broker |
| Password in the query string | 400 | unchanged (`[RefuseCredentialInQuery]`, `CredentialsNotInUrlTests`) |
| Create without password | 400 (model validation, `Password` is `[Required]`) | unchanged; an invitation without password stays method-only |
| Create: user name / e-mail | stored as sent | trimmed by the method; a blank e-mail is stored as `null` |
| Create: duplicate name / e-mail | 409 problem `USER_ALREADY_EXISTS`, `field` | unchanged (`USER_ALREADY_EXISTS` mapped by `field`) |
| Create: reserved `xt_` name | 400 message | unchanged (pre-check; `USER_NAME_RESERVED` maps to the same answer) |
| Policy violation / invalid name or e-mail | 400 `OperationFailedErrorDto`, details code + description | unchanged (descriptions rebuilt from the codes) |
| Create: welcome notification | once | once (`IUserCreationService` in the handler) |
| Reset: lockout | left in place | **lifted** (`LockoutEnd = null`, `AccessFailedCount = 0`) |
| Reset: sessions | revoked (`PasswordChangePath.AdminResetPassword`) | revoked (`PasswordChangePath.MethodResetPassword` in the "Password changed" log line) |
| Reset: acting user in that log line | `AuditActor`: `preferred_username`, else `client <id>` | user name looked up from `sub`, else `client <id>`, else the subject |
| Reset: notification | once | once (facade, earlier) |
| Reset: unknown user / shadow user | 404 / 400 | unchanged (pre-checks; `METHOD_TARGET_NOT_FOUND` / `SHADOW_USER_PASSWORD_NOT_ALLOWED` map to the same) |
| Audit | none (reset: the credential-change log line) | one `Identity.Method` event (create: `userName`, `withPassword`; reset: `lockoutLifted`) |
| Unexpected failure | 500 `InternalServerErrorDto(exception message)` | 500 `InternalServerErrorDto("Creation of user failed." / "Reset of password failed.")`, no exception text |
| `RoleEnforcement=Warn` (not the default) | caller without `UserManagement` let through and logged | refused by the method (403 problem) |

Fix on the way: `UserResetPasswordHandler` looked the acting user up by `sub` and threw for a subject that is no object id (like
`User.Merge`); it now skips the lookup. Tests: `Api/TenantApi/UserPasswordRestMethodFacadeTests` (both switch values: locked-out
user reset over REST - sign-in, lockout lifted, refresh tokens revoked, one audit event, one notification, no `CkMethodRequest` on the event
hub, canary absent from logs, audit and activity tags; REST create the same; policy violation; REST and dispatcher side by side for create
with password, invitation, duplicate name and e-mail, policy violation, unknown user, shadow user), `Methods/IdentityMethodHostTests`
(local-only selection, registration forms, never both), plus the unchanged REST suites (`UsersCreateTests`, `ShadowUserPasswordTests`,
`CredentialsNotInUrlTests`, `PasswordChangeRevokesSessionsTests`, `TenantApiRoleAuthorizationTests`).

## Account pages run the password methods (System.Identity 3.2.0)

`ManageApiController.ChangePassword` (`POST {tenant}/api/manage/change-password`) and `ManageApiController.SetPassword`
(`POST {tenant}/api/manage/set-password`) - the backend of the identity account SPA, session cookie, same origin - are **facades** of
`User.ChangePassword-1` and of the new `User.SetPassword-1` (`UserSetPasswordHandler`). They stay facades **without deprecation**
(decided 2026-11-07: same-origin account pages, not a public API). Password rules, lockout, session revocation and audit exist only in
the handlers.

- **`User.SetPassword-1`** (`ck-user.yaml`, System.Identity 3.2.0, additive Minor): `allowSelf`, `newPassword` sensitive, errors
  `PASSWORD_POLICY_VIOLATION`, `PASSWORD_ALREADY_SET`, `SHADOW_USER_PASSWORD_NOT_ALLOWED`. Self only like `ChangePassword` (the handler
  answers `METHOD_FORBIDDEN`/`not-self` before any lookup, also for an administrator). Order: tenant, user, shadow user, existing password
  (`PASSWORD_ALREADY_SET`: without a current password this method never replaces one), `AddPasswordAsync`, then
  `IUserCredentialChangeService.OnPasswordChangedAsync(..., PasswordChangePath.MethodSetPassword, ...)`. One audit event per call.
- **Caller of the cookie path.** A session cookie carries no OAuth scope, and the evaluator requires `octo_api` for every call.
  `IIdentityMethodFacade.InvokeForAccountOwnerAsync` therefore builds the caller itself: subject = the cookie's user id, **no role**,
  scope `octo_api` only, target = that user. With no role the declaration can admit it only through `allowSelf` on its own user - never
  an administrator path, never another user. The facade refuses (`METHOD_FORBIDDEN`, no call) a principal that is not an authenticated
  `Identity.Application` identity or whose user id is not the target. No evaluator change; the token path is unchanged: a bearer token
  never reaches the account endpoints (their default scheme is the cookie), and through GraphQL a token without `octo_api` gets
  `METHOD_FORBIDDEN` (`AccountPasswordMethodFacadeTests.ATokenWithoutTheApiScope_*`).
- **Switch.** Both rows of `IdentityMethodHost.Handlers` carry `ServesRestFacade = true`: with `EnablePasswordMethods=false` they are
  registered local only (in-process, no queue, not announced), so the account pages work and no password reaches the broker.
- **Session.** The method rotates the security stamp; the controller re-reads the user and calls `RefreshSignInAsync` with it, so the
  page's own cookie carries the new stamp and stays valid while every other session ends at its next stamp validation.
- **Answers.** The pre-checks of the controller (user, shadow user, confirmation mismatch; set-password: existing password, read-only,
  to keep the answer order) are unchanged. Envelope mapping: `CURRENT_PASSWORD_INVALID` -> `Errors = ["Incorrect password."]`
  (describer), `USER_LOCKED_OUT` -> `"The account is locked out. Try again later."`, `PASSWORD_POLICY_VIOLATION` -> descriptions rebuilt
  from the rule codes (`Methods/PasswordPolicyErrorDescriber`), `PASSWORD_ALREADY_SET` -> the earlier message, anything unexpected ->
  `500` with `Success=false` and the generic message.

Parity table (account page before -> facade):

| Point | Before | Now |
|---|---|---|
| Routes, bodies, status codes | - | unchanged (`200` + `PasswordResultDto`) |
| `EnablePasswordMethods=false` | own code, worked | works: handlers local only, in-process, nothing on the broker |
| Wrong current password | `Errors = ["Incorrect password."]`, not counted | same answer, **counted as a failed sign-in** (lockout) |
| Locked-out user changes the password | allowed | **refused** (`USER_LOCKED_OUT`) |
| Policy violation | descriptions of the failed rules | unchanged (rebuilt from the codes) |
| Set-password with an existing password / shadow user | refused | unchanged (pre-check; the method refuses as well) |
| Sessions | other refresh tokens revoked, own cookie refreshed | unchanged; the cookie is refreshed from the stored user (new stamp) |
| "Password changed" log line | path `ChangePassword` / `SetPassword` | `MethodChangePassword` / `MethodSetPassword` |
| Audit | none | one `Identity.Method` event per call |
| Unexpected failure | unhandled exception | `500`, `Success=false`, generic message |

Tests: `Api/Manage/AccountPasswordMethodFacadeTests` (both switch values: change - new works, old fails, refresh tokens revoked, this
session stays and another session ends with the stamp validated per request, one audit event, nothing on the event hub, canary absent
from logs, audit and activity tags; set the same; wrong current password counted; lockout; policy descriptions; set-password method:
`PASSWORD_ALREADY_SET`, shadow user, another user and an administrator `METHOD_FORBIDDEN`; tokens without `octo_api` refused; a bearer
token does not reach the endpoints; the facade guard), `Api/Methods/UserChangePasswordMethodTests` (switch off: local only),
`Methods/IdentityMethodHostTests`, `IdentityMethodDeclarationsIntegrationTests` (declaration, sensitive parameter, `CarriesSecret` vs.
model), plus the unchanged `PasswordChangeRevokesSessionsTests` and `ShadowUserPasswordTests`. `UsersController.DescribeIdentityErrors`
is a pure mapper onto `PasswordPolicyErrorDescriber` (33d0dbbe); no REST or account path builds password-policy texts
itself. `Api/PasswordPolicyMessageParityTests` keeps it that way: one password that breaks several rules gets the same rule
codes from `User.CreateUser`, `User.ResetPassword` and `User.ChangePassword`, and REST `POST users`, REST `POST users/ResetPassword`
(code + description) and the account page's `change-password` and `set-password` (descriptions) show exactly
`PasswordPolicyErrorDescriber.Describe` of the method envelope, in `en` and `de` (same `Accept-Language` on every path).

## REST facades of the group role and membership endpoints (System.Identity 3.3.0)

The seven write endpoints of `GroupsController` are **facades** of the `Group` methods; the controller holds no role-diff, membership
or cycle rule of its own (no `IGroupStore` write, no guard call, no scratch-tenant revoke):

| REST endpoint | Method |
|---|---|
| `PUT groups/{g}/roles` (role ids in the body) | `Group.SetRoles-1` (role names) |
| `PUT` / `DELETE groups/{g}/members/users/{user}` | `Group.AddMember-1` / `Group.RemoveMember-1`, `memberKind` `User` |
| `PUT` / `DELETE groups/{g}/members/clients/{client}` | `Group.AddMember-1` / `Group.RemoveMember-1`, `memberKind` `Client` |
| `PUT` / `DELETE groups/{g}/members/groups/{child}` | `Group.AddChildGroup-1` / `Group.RemoveChildGroup-1` (new in 3.3.0) |

Same path as the user facades: `IIdentityMethodFacade` (in-process, outside the request, caller from the bearer token), envelope mapped with
`CkMethodFacadeOptions`. The `dataAccess: Write` check on the target is a check of the method gateway of the asset repository (GraphQL);
the in-process REST path checks the REST policy and the handler rules, as before. A guard refusal (`METHOD_FORBIDDEN` with `reason` `self-grant` / `role-not-held` / `last-administrator`, decoded by
`RoleChangeProblems.RefusalOf`) is turned back into the audited REST answer of `IRoleChangeRefusals` (403/409 problem, WARN log,
`Identity.RoleChangeRefused`, target `group <rtId>`). `Group.AddChildGroup` and `Group.RemoveChildGroup` are own methods instead of a third
`GroupMemberKind` value, because the cycle refusal needs its own error code and an error code added to `Group.AddMember-1` is a Major
(row M8 of the CK SemVer rules).

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, bodies, status codes of a success | `200` empty | unchanged |
| Group not found | `404` empty | unchanged (`METHOD_TARGET_NOT_FOUND` -> empty `404`) |
| SetRoles: unknown role id | engine error (`RuntimeRepositoryException`), unhandled `500` | **intended REST change:** `404` `Role with id '…' not found.`, nothing changed - the `500` was a bug |
| Add a user that does not exist (or an id that is no object id) | engine error (`RuntimeRepositoryException`), unhandled `500` | **intended REST change:** `404` `User '…' not found.` (`MEMBER_NOT_FOUND`) - the `500` was a bug |
| Add a member twice | `200` | `200`, nothing written (`MEMBER_ALREADY_IN_GROUP` / `CHILD_GROUP_ALREADY_IN_GROUP`) |
| Remove a non-member / unknown user | `200` (an id that is no object id: unhandled `500`) | `200` (`MEMBER_NOT_IN_GROUP` / `MEMBER_NOT_FOUND` mapped back); the `500` for a malformed id was a bug |
| Add / remove client by client id or rtId | resolver in the controller | same resolver in the handler; unknown client id `404` `Client '…' not found. …`, leftover edge of a deleted client's rtId still removed, an rtId that is no member `200` |
| Remove client from TenantOwners of a scratch tenant | revoke recorded first, revoker = `preferred_username`, else `client_id` | revoke recorded first by the handler; the stored revoker is the caller's subject (user id), else its client id (internal record, no REST answer changes) |
| Child group in itself | `400` `A group cannot be a member of itself.` | unchanged (`GROUP_CYCLE`, `cycle=self`) |
| Child group cycle (group reachable from the child) | `400` `Adding this group would create a circular reference.` | unchanged (`GROUP_CYCLE`, `cycle=descendant`) |
| Child group that does not exist / no object id | `404` `Child group not found.` / unhandled `500` | `404` `Child group not found.` for both (`CHILD_GROUP_NOT_FOUND`); **intended REST change** for the malformed id - the `500` was a bug |
| SetRoles: dropping a held role the caller cannot read (only with an enforcing data policy on roles) | removed regardless of the data policy | **intended REST change:** `403` problem `METHOD_FORBIDDEN` (`data-permission`), nothing changed (as `Client.SetRoles` and the removals) |
| Member or child group the caller cannot read (only with an enforcing data policy on the type; open by default) | not checked: changed anyway | **intended REST change:** add answers like for an unknown member (`404`, existence not told); removing such a **member of the group** is `403` problem `METHOD_FORBIDDEN` (`data-permission`) and changes nothing - the membership is visible through the group, a success without a change would mislead; removing one that is no member answers as for an unknown member (`200`, or `404` for a child group or a client named by client id). REST ignoring an enforcing data policy was the gap the data-permission check closes |
| Remove a child group: id that is no object id | unhandled `500` | **intended REST change:** `404` `Child group not found.` - the `500` was a bug |
| Guard refusals | 403/409 problem, `Identity.RoleChangeRefused`, WARN | unchanged, plus the `Identity.Method` event |
| Audit of a success | none | one `Identity.Method` event per call (`rolesBefore`/`rolesAfter`; members `memberKind`, `memberId`) |
| Unexpected failure | unhandled `500` | `500` problem `METHOD_HANDLER_FAILED` (same status, no exception text) |
| `RoleEnforcement=Warn` (not the default) | caller without `UserManagement` let through and logged | **intended REST change:** refused by the method (403 problem, `role-required`), as for the user facades - a method has no staged warn mode, and `Enforce` is the default |

Group create, update and delete are facades since System.Identity 3.7.0 (section "REST facades of the role, group, API scope and API resource
CRUD" below); the group reads stay REST reads.

Tests: `Api/TenantApi/GroupRestMethodFacadeTests` (per endpoint: exactly one `Identity.Method` event, in-process, the ambient-state probe sees
no request state at handler entry; 403 for a caller without `UserManagement`; the two cycle answers with today's body; REST and the dispatcher
side by side for the child group methods; non-member removals), `Methods/IdentityMethodHostTests`, the controller unit tests
`GroupsControllerScratchRevokeTests` (real handler behind the controller, `HandlerBackedMethodFacade`), plus the unchanged REST suites
(`GroupRoleChangeGuardTests`, `GroupMethodTests`, `GroupMethodParityTests`, `TenantApiRoleAuthorizationTests`).

## REST facades of the client role and overlay endpoints (System.Identity 3.3.0)

The role and overlay write endpoints of `ClientsController` are **facades** of new `Client` methods. The controller resolves the OAuth client
id of the route to the rtId (the method target) and, for the replace-all, the role ids to names; every rule lives in the handler
(`Methods/ClientRoleHandlers.cs`, `Methods/ClientOverlayHandlers.cs`):

| REST endpoint | Method |
|---|---|
| `PUT clients/{id}/roles` (role ids) | `Client.SetRoles-1` (role names) |
| `PUT clients/{id}/roles/{role}` | `Client.AddRole-1` |
| `DELETE clients/{id}/roles/{role}` | `Client.RemoveRole-1` |
| `POST clients/{id}/overlayUris` | `Client.ApplyOverlayUris-1` (result record `ClientOverlayUrisResult`) |
| `DELETE clients/cleanOverlayEntries[?overlayName=]` | static `Client.CleanOverlayEntries-1` (result record `ClientOverlayCleanResult`) |

The declared roles are the REST policy `IdentityTenantAdministrationWritePolicy` (`TenantManagement` or `UserManagement`); the handlers check
the same rule again on the validated principal (`IdentityMethodCallerRules.IsTenantAdministrator`). The REST bodies of the overlay endpoints
are rebuilt from the result records (same shape as before).

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, bodies, status codes of a success | `200` (overlay: result DTO) | unchanged |
| Client not found | `404` | unchanged (resolved in the controller) |
| SetRoles: unknown role id | `404`, nothing changed | unchanged |
| SetRoles / AddRole: a built-in role the caller does not hold, any role for the caller's own client | 403 problem `role-not-held` / `self-grant`, audited | unchanged (the method's `METHOD_FORBIDDEN` is mapped back), plus the `Identity.Method` event; the same refusal as `User.AddRole` |
| AddRole: role already held directly | `200`, nothing written | unchanged (the method succeeds without a write) |
| AddRole: unknown role | `404` | unchanged (`ROLE_NOT_FOUND`) |
| RemoveRole: unknown role / role not held | `200`, nothing changed | unchanged (`ROLE_NOT_FOUND` mapped to `200`; a role not held is a success) |
| Role the caller cannot read (only with an enforcing data policy on roles; open by default) | not checked: changed anyway | **intended REST change:** SetRoles / AddRole treat a named one as unknown (`404`); SetRoles dropping such a held role and RemoveRole of such a role the client **holds** are `403` problem `METHOD_FORBIDDEN` (`data-permission`) and change nothing (the client's role ids are visible); RemoveRole of one it does not hold answers as for an unknown role (`200`). REST ignoring an enforcing data policy was the gap the data-permission check closes |
| Overlay: invalid overlay name / no non-blank URI | `400` with the model state, before the client lookup | unchanged, same order (model validation and a read-only request check before the lookup; the method enforces the same rules, `INVALID_OVERLAY_NAME` / `NO_OVERLAY_URIS` map to the same body) |
| Overlay: dedupe, `overlay:<name>` source, no write when nothing is added, CORS refresh on every call | controller | unchanged, in the method |
| Overlay / clean: unresolved concurrent change | `409` problem | unchanged (`CONCURRENT_CHANGE`) |
| Overlay: the client id was taken over by another client between the lookup and the write | the other client was changed | `404`, neither client changed (the method writes only its target rtId) |
| Clean: conflict or another failure after some clients were cleaned | `409` / `400`, no CORS refresh | same status; the CORS refresh is published for the clients already cleaned |
| Unexpected failure | overlay / clean: `400` `InternalServerErrorDto(exception message)`; roles: unhandled `500` | same status codes; **intended body change:** a fixed message instead of the exception text (no internal detail leaves the service); roles: `500` problem `METHOD_HANDLER_FAILED` |
| Audit | none | one `Identity.Method` event per call (`clientId`, `rolesBefore`/`rolesAfter`; overlay `overlayName`, `added`, `skipped`; clean `overlayName`, `clientsAffected`, `removed`; never a URI) |
| `RoleEnforcement=Warn` (not the default) | caller without the role let through and logged | **intended REST change:** refused by the method (403 problem, `role-required`), as for the user facades - a method has no staged warn mode, and `Enforce` is the default |

Tests: `Api/TenantApi/ClientRestMethodFacadeTests` (per endpoint one `Identity.Method` event, in-process, no request state at handler entry;
REST and the dispatcher side by side per method - same direct roles, same URI lists and counts; the escalation guard answers exactly as
`User.AddRole`; a token of another tenant (`METHOD_FORBIDDEN` `tenant-not-allowed` / REST 403) and a caller without the declared role change
nothing), the controller unit tests `ClientsControllerOverlayUrisTests`, `ClientsControllerCleanOverlayEntriesTests` and
`ClientsControllerRoleGuardTests` (real handlers behind the controller through `HandlerBackedMethodFacade`), plus the unchanged
`ClientRoleChangeGuardTests`.

Both groups of endpoints carry no deprecation yet: the deprecation wave of identity wave 2 is its own story; REST is not removed and gets no
`Sunset` header.

## REST facades of the secret write endpoints (System.Identity 3.4.0)

The write endpoints of `ApiSecretsController` are **facades** of the secret methods; the controller resolves the route's OAuth client id or API resource
name to the method target (rtId) and maps the envelope, every rule lives in the handlers (`Methods/ClientSecretHandlers.cs`,
`SecretOwnerMethodHandlerBase<TOwner>`):

| REST endpoint | Method |
|---|---|
| `POST apiSecrets/client/{clientId}` | `Client.AddSecret-1` |
| `PUT apiSecrets/client/{clientId}` | `Client.UpdateSecret-1` (new) |
| `POST apiSecrets/client/{clientId}/delete`, deprecated `DELETE apiSecrets/client/{clientId}/{secretValue}` | `Client.RemoveSecret-1` |
| `POST apiSecrets/apiResource/{name}` | `ApiResource.AddSecret-1` (new) |
| `PUT apiSecrets/apiResource/{name}` | `ApiResource.UpdateSecret-1` (new) |
| `POST apiSecrets/apiResource/{name}/delete`, deprecated `DELETE apiSecrets/apiResource/{name}/{secretValue}` | `ApiResource.RemoveSecret-1` (new) |

The secret reads (`GET`, `POST …/lookup`, deprecated `GET …/{secretValue}`) stay REST reads: secrets are not exposed through GraphQL.

- **Switch.** All six rows carry `CarriesSecret = true` and `ServesRestFacade = true`: with `Methods:Identity:EnablePasswordMethods=false` they are registered
  local only (in-process, no queue, not announced), so the REST endpoints work on every cluster, GraphQL answers `METHOD_HANDLER_NOT_AVAILABLE` and no secret
  reaches the broker; with the switch on they are bus handlers and REST still calls in-process.
- **Caller.** The REST policy `IdentitySecretAdministrationPolicy` is unchanged; the handlers repeat it on the principal (`SecretManagementRoleEnforcement`
  staged the same way: `Warn` lets `TenantManagement`/`UserManagement` pass with the WARN inventory line, `Enforce` refuses them on both paths).
- **Body of an add.** The method returns the clear text once (the sensitive result); the facade answers the earlier `ApiSecretDto`: `valueClearText`,
  `valueEncrypted` = `OctoSecretHasher.HashSecret(clear text)` (the stored value), and the request's `expirationDate` and `description`. The clear text is read
  from the in-process envelope only and is logged nowhere.

Parity table (REST before -> facade; the method wins unless the REST contract would change):

| Point | REST before | Now |
|---|---|---|
| Routes, request and response bodies, status codes of a success | add `200` + `ApiSecretDto`, update / delete `200` empty | unchanged |
| Owner not found | `404` (delete client: `NotFoundErrorDto` "Client with id … does not exist.") | unchanged (resolved in the controller; `METHOD_TARGET_NOT_FOUND` of a race maps to the same answer) |
| Update without `valueEncrypted` | `400` with the model state | unchanged (checked before the call) |
| Unknown secret value (update, delete) | `404` "The secret does not exist." (no echo) | unchanged (`SECRET_NOT_FOUND`) |
| Secret named by its clear text (update, delete) | not found (`404`) | found (the method hashes it like the token endpoint); the stored value still works |
| Duplicate records with one value | delete removes all, update the first | unchanged |
| Expiration in the past on update | accepted | unchanged (retires the secret) |
| Update: secret `Type` | cleared (`null`) | kept (`SharedSecret`) |
| Add to a public client (`RequireClientSecret` false) | `200`, a secret that is never used | **intended REST change:** `400` with the model state, nothing stored (`CLIENT_SECRET_NOT_REQUIRED`) |
| Add with an expiration in the past | `200`, a secret that can never be used | **intended REST change:** `400` (`expirationDate`), nothing stored |
| Add / update with the description `octo:mirror-own-secret`, update of a mirror's own secret (the record carries that description) | stored / overwritten | **intended REST change:** `400` (`description`): the mirror sync tells a mirror's own credential by that marker |
| Owner the caller cannot read / write (only with an enforcing data policy on clients or API resources; open by default) | not checked: changed anyway | **intended REST change:** cannot read = `404` (existence not told), read but not write = `403` problem `METHOD_FORBIDDEN` (`data-permission`); nothing changes (CWE-863: REST ignored the data policy) |
| Lost concurrent write (20 attempts) | `409` problem | unchanged for update and the API resource methods (`CONCURRENT_CHANGE`); `Client.AddSecret` / `RemoveSecret`: `400` fixed message (`METHOD_HANDLER_FAILED`; a new error code on those methods would be a Major, row M8) |
| Unexpected failure | `400` `InternalServerErrorDto(exception message)` | `400`, **intended body change:** a fixed message, no exception text leaves the service |
| Audit | none | one `Identity.Method` event per call (`clientId` / `apiResourceName`, `secretCount`, `removedCount`); never a secret, hash or description |
| `EnablePasswordMethods=false` | own code, worked | works: handlers local only, in-process, nothing on the broker |

Tests: `Api/TenantApi/SecretRestMethodFacadeTests` (both switch values and both owners: every write endpoint runs its method in-process outside the request,
one event each, no `CkMethodRequest` on the event hub, clear text in no log, audit or trace tag, hash in no log at Information or above; REST and the dispatcher
side by side for add, update to an expired date, unknown value, duplicate records, unknown owner; a REST-added client secret authenticates and stops after the
REST delete; public client and past expiration; `Enforce` on both paths; another tenant's token; a caller without the role; owner not readable / not
writable), `Api/Methods/ClientSecretMethodTests`, the unchanged REST suite `Api/TenantApi/ApiSecretsControllerTests`, `CredentialsNotInUrlTests`,
`IdentityMethodDeclarationsIntegrationTests`.

## REST facades of the data-permission grants and the enforcement switch (System.Identity 3.4.0)

| REST endpoint | Method |
|---|---|
| `POST dataPermissions/{permissionId}/roles/{roleName}` | `DataPermission.GrantToRole-1` |
| `DELETE dataPermissions/{permissionId}/roles/{roleName}` | `DataPermission.RevokeFromRole-1` |
| `PUT dataPermissions/policies/{policyRtId}/enforcementMode` (body `"Enforce"` / `"AuditOnly"`) | `DataPolicy.SetEnforcementMode-1` (new) |

Same path as the other facades (`IIdentityMethodFacade`, in-process, outside the request, one `Identity.Method` event per call). The controller resolves the
permission id to the permission's rtId; the policy rtId is the target as it is. Create and delete of permissions and policies stay REST (generic CRUD story of
Feature F5.2).

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, bodies, status codes of a success | `200` empty | unchanged |
| Grant twice / revoke without a grant | `200`, nothing changed | unchanged (`PERMISSION_ALREADY_GRANTED` / `PERMISSION_NOT_GRANTED` map to `200`) |
| Invalid enforcement mode | `400` "EnforcementMode must be Enforce\|AuditOnly." | unchanged (checked before the call) |
| Unknown permission, unknown role, unknown policy, policy id that is no object id | unhandled exception, `500` | **intended REST change:** `404` `NotFoundErrorDto` - the `500` was a bug |
| Role, permission or policy the caller cannot read / write (only with an enforcing data policy on those types; open by default) | not checked: changed anyway | **intended REST change:** cannot read = `404`; may read but not write = `403` problem `METHOD_FORBIDDEN` (`data-permission`); the enforcement switch also needs `Write` on the policy's data permission (the mode decides whether that permission is enforced at all); **revoking from a role the caller cannot read while it holds the permission** = `403`, nothing changed (the grant is visible through the permission; CWE-863) |
| Enforcement mode already set | `200`, written again | `200`, nothing written |
| Effect of the enforcement switch | every service after its policy cache TTL (60 s) | at once in the identity replica that served the call (the handler invalidates its policy table); other identity replicas and every other service (asset repository, mesh adapter, report, bot) still after their TTL of 60 s, no invalidation event - they may apply the old mode for up to one minute |
| Audit | none | one `Identity.Method` event per call (`permissionId`, `roleName`; switch: `enforcementModeBefore`, `enforcementModeAfter`) |
| Unexpected failure | unhandled `500` | `500` problem `METHOD_HANDLER_FAILED` (same status, no exception text) |
| `RoleEnforcement=Warn` (not the default) | caller without `UserManagement` let through and logged | **intended REST change:** refused by the method (403 problem, `role-required`), as for the other facades |

Tests: `Api/TenantApi/DataPermissionRestMethodFacadeTests` (one event per endpoint, in-process, no request state at handler entry; switching to Enforce over REST
and over the method gives the same fail-closed read verdict of the engine for a caller without the grant; the REST answers above; another tenant's token, a caller
without the role; revoke of a granted unreadable role; policy and permission not readable), `Api/Methods/DataPermissionMethodTests`.

Neither group of endpoints carries a deprecation yet (deprecation wave of identity wave 2 is its own story); REST is not removed and gets no `Sunset` header.

## The target's data permission on every facade (transport-independent verdict)

The GraphQL gateway evaluates the declared `dataAccess: Write` of a method on its **target** before it dispatches; a REST facade dispatches
in-process (`IIdentityMethodFacade`), where no gateway runs. So every handler that serves a REST facade evaluates its target itself, with the
gateway's answers: a target the caller cannot read = `METHOD_TARGET_NOT_FOUND`, one it may read but not write = `METHOD_FORBIDDEN` with
`reason = data-permission`, nothing changed. One place for the instance methods of `IdentityAdminMethodHandlerBase` (the target's CK type
comes from the method id the handler is registered for, never from the request): `Group.*`, `Client.SetRoles/AddRole/RemoveRole`,
`DataPermission.*`, `DataPolicy.SetEnforcementMode`, `User.Merge`, `User.DisableTwoFactor`; plus `UserRoleMethodHandlerBase`
(`User.SetRoles/AddRole/RemoveRole`), `User.ResetPassword` and `Client.ApplyOverlayUris`. The secret methods
(`SecretOwnerMethodHandlerBase`) and the client mirror methods (`ClientMirrorMethodHandlerBase`) use the same check
(`IdentityMethodCall.CheckTargetWritableAsync`). On the GraphQL path nothing changes: the gateway refuses first with the same codes.

Static methods have no target entity; the gateway checks the caller's `Write` permission on the declaring type instead. Their handlers check the
same (`IdentityMethodCall.CheckTypeWritableAsync`, after the tenant bind): the five `ExternalTenantUserMapping` methods, `User.CreateUser` and
`Client.CleanOverlayEntries`. A type the caller cannot see answers `METHOD_TARGET_NOT_FOUND` (`404`), a type they may read but not write
`METHOD_FORBIDDEN` (`data-permission`, `403`). Not affected: the account-owner methods (`User.ChangePassword`, `User.SetPassword`: `allowSelf` on the caller's own
user through the account pages).

Changed REST answers - only with an **enforcing data policy on the target type** (open by default); **intended change**, reason: the verdict no
longer depends on the transport (REST wrote a target that GraphQL refused, CWE-863):

| REST endpoint | Target type | Before | Now: target not readable / readable but not writable |
|---|---|---|---|
| `PUT groups/{group}/roles` | Group | `200`, written | `404` / `403` problem `METHOD_FORBIDDEN` (`data-permission`), nothing changed |
| `PUT` / `DELETE groups/{group}/members/users/{user}`, `…/members/clients/{client}` | Group | `200`, written | `404` / `403`, nothing changed |
| `PUT` / `DELETE groups/{group}/members/groups/{child}` | Group | `200`, written | `404` / `403`, nothing changed |
| `PUT clients/{client}/roles`, `PUT` / `DELETE clients/{client}/roles/{role}` | Client | `200`, written | `404` / `403`, nothing changed |
| `POST clients/{client}/overlayUris` | Client | `200`, written | `404` / `403`, nothing changed |
| `PUT users/{user}/roles`, `PUT` / `DELETE users/{user}/roles/{role}` | User | `200`, written | `404` / `403`, nothing changed |
| `POST users/{user}/merge` (the target user; the source was already checked) | User | `200`, merged | `404` / `403`, nothing merged |
| `POST users/ResetPassword` | User | `200`, password reset | `404` / `403`, password unchanged |
| `POST users` (static `User.CreateUser`: the declaring type) | User | `200`, created | `404` / `403`, no user created |
| `DELETE clients/cleanOverlayEntries` (static `Client.CleanOverlayEntries`: the declaring type) | Client | `200`, cleaned | `404` / `403`, nothing removed |

Unchanged: the secret writes, the data-permission grants and the enforcement switch (they checked their target already) and the client mirror
endpoints (their parent client is checked from the start). The admin provisioning endpoints and `POST externalTenantUserMappings` answer the same
`404` / `403` under an enforcing data policy on `ExternalTenantUserMapping` that denies the caller `Write` (before: `200`/`201`, written); their
target-tenant rule is unchanged. Each refusal writes the usual `Identity.Method` event with the code (and `reason`).

Tests: `Api/TenantApi/TargetDataPermissionRestParityTests` (every row above that writes a role, member, overlay URI or password, both decisions: the REST
answer and the dispatcher's answer agree, one event each, nothing changed; without an enforcing policy REST still writes).

## REST facades of the client mirror endpoints (System.Identity 3.5.0)

The write endpoints of `ClientMirrorController` and `ClientAutoProvisionFlagController` are **facades** of the client mirror methods on the parent
client; the controller resolves the route's OAuth client id to the method target (rtId) and maps the envelope, every rule lives in the handlers
(`Methods/ClientMirrorHandlers.cs`). The method runs in the parent tenant; the handler writes into the child tenant through
`IClientMirrorProvisioningService`.

| REST endpoint | Method |
|---|---|
| `POST clients/{clientId}/mirrors/provisionInExistingTenants` | `Client.ProvisionMirrors-1` |
| `POST clients/{clientId}/mirrors/provisionInTenant?childTenantId=` | `Client.ProvisionMirrorInTenant-1` |
| `POST clients/{clientId}/mirrors/{childTenantId}/secret` | `Client.RotateMirrorSecret-1` (result `sensitive`) |
| `DELETE clients/{clientId}/mirrors/{childTenantId}` | `Client.RemoveMirror-1` |
| `PATCH clients/{clientId}/autoProvisionInChildTenants` | `Client.SetMirrorAutoProvision-1` |

`GET clients/{clientId}/mirrors` stays a REST read.

- **Switch.** Only the rotation carries a secret (its result): `CarriesSecret = true`, `ServesRestFacade = true`, so it is local only while
  `Methods:Identity:EnablePasswordMethods` is off (the REST endpoint keeps working, GraphQL answers `METHOD_HANDLER_NOT_AVAILABLE`, the secret never
  reaches the broker). The other four are bus handlers whatever the switch says.
- **Caller.** The REST policies are unchanged (`IdentityTenantAdministrationWritePolicy`; the rotation `IdentitySecretAdministrationPolicy`, staged by
  `SecretManagementRoleEnforcement`); the handlers repeat them on the validated principal.
- **Child tenant, two checks before any write.** The handler checks the child against the caller's token tenant (the `tenant_id` the token was
  issued for, also on the bus path; `AdminProvisioningTargetScope`, the rule of `AdminProvisioningTargetScopeFilter`; `RoleEnforcement=Warn` stages it
  only for REST calls, a bus or GraphQL call is refused in either mode), and the mirror service checks it against the parent tenant's subtree.
  Either refusal is `METHOD_FORBIDDEN` with `reason = tenant-out-of-scope`; nothing is written in the child tenant. REST still runs the filter first
  and answers the empty `403`.
- **Parent client.** CWE-863: the handler checks that the caller may read and write the parent client (`IRtDataPermissionEvaluator`) before
  anything changes in either tenant.
- **Secret.** The rotated secret is minted, hashed and marked as the mirror's own secret by `RotateMirrorSecretAsync` (the mirror sync keeps
  it); the clear text is only the sensitive result and the one-time REST body, never in a log line, audit detail or trace.

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, bodies, status codes of a success | backfill / provision `200` + counts, rotation `200` + `MirrorSecretResponseDto`, delete / flag `204` | unchanged |
| Unknown client | `404` (`NotFoundErrorDto`; rotation and delete: "No mirror tracked for client … in child tenant …") | unchanged (resolved in the controller) |
| Client not flagged (backfill, provision) | `400` "… is not flagged AutoProvisionInChildTenants. Set the flag first." | unchanged (`AUTO_PROVISION_DISABLED`) |
| Untracked pair (rotation, delete) | `404` | unchanged (`MIRROR_NOT_FOUND`) |
| Public client (rotation) | `400` | unchanged (`CLIENT_SECRET_NOT_REQUIRED`) |
| Child outside the caller's or the parent's subtree | empty `403` (filter, service) | unchanged; the same rule now also holds for a GraphQL / bus caller. Under `RoleEnforcement=Warn` (not the default) a REST call is logged and allowed by the filter and the handler (staging, as before); a GraphQL / bus call is refused: a new path without existing callers |
| Lost concurrent write of the flag | `409` problem | unchanged (`CONCURRENT_CHANGE`) |
| Tracking row whose parent client no longer exists (rotation, delete) | delete `204` (row removed), rotation `404` | **intended REST change:** `404` for both: the method target is the parent client. The reconciliation job removes such rows after two passes |
| Parent client the caller cannot read / write (only with an enforcing data policy on clients; open by default) | not checked: changed anyway | **intended REST change:** cannot read = `404`, read but not write = `403` problem `METHOD_FORBIDDEN` (`data-permission`); nothing changes in either tenant (CWE-863) |
| Other flagged clients of the parent (provision, backfill) | the service mirrors **every** flagged client of the parent, not only the named one | unchanged, also under an enforcing client data policy for flagged clients the caller cannot read: their own flag asks for the mirrors (the same sync the tenant setup and the reconciliation run). The answer and the audit carry only counts and the named client's id, never another client's id, name or secret |
| Backfill duration | no limit | the method's timeout of 300 s (`execution.timeoutSeconds`); a longer backfill answers `504` (`METHOD_TIMEOUT`), the provisioning already done stays (idempotent, re-run to finish) |
| Unexpected failure | unhandled `500` | `500` problem `METHOD_HANDLER_FAILED` (same status, no exception text) |
| `RoleEnforcement=Warn` (not the default) | caller without the role let through and logged | **intended REST change:** refused by the method (403 problem, `role-required`), as for the other facades |
| Audit | none | one `Identity.Method` event per call (`clientId`, `childTenantId`, `enabled`, `newlyProvisioned`); never a secret or hash |

Tests: `Api/TenantApi/ClientMirrorRestMethodFacadeTests` (both switch values: every write endpoint runs its method in-process outside the request, one
event each, nothing on the broker; REST and the dispatcher leave the same tracking rows and child clients; a rotated secret authenticates in its child
tenant only and is in no log, audit or trace; a child outside the caller's subtree and outside the parent's subtree is refused and nothing is written
there; another tenant's token; a caller without the role; an unreadable parent client; the rotation under `SecretManagementRoleEnforcement=Enforce`),
`Controllers/ClientMirrorControllerTests` (unit, real handlers), `Authorization/ClientMirrorScopePipelineTests`.

## REST facades of admin provisioning and the mapping create (System.Identity 3.5.0)

The writes of `AdminProvisioningController` and the create of `ExternalTenantUserMappingsController` are **facades** of static methods on
`System.Identity/ExternalTenantUserMapping` (`Methods/AdminProvisioningHandlers.cs`; the provisioning logic itself is `AdminProvisioning/AdminProvisioningService.cs`).
They are the Feature's `Tenant.ProvisionAdmin`: the host type is `ExternalTenantUserMapping` because every one of them creates, repairs or removes such a
mapping, and a static method needs no target entity in the caller's tenant.

| REST endpoint | Method |
|---|---|
| `POST adminProvisioning/{targetTenantId}` | `ExternalTenantUserMapping.ProvisionAdmin-1` |
| `POST adminProvisioning/{targetTenantId}/withGroups` | `ExternalTenantUserMapping.ProvisionAdminWithGroups-1` |
| `POST adminProvisioning/{targetTenantId}/provisionCurrentUser` | `ExternalTenantUserMapping.ProvisionCurrentUser-1` (result `outcome`: `created`, `repaired`, `already-provisioned`) |
| `DELETE adminProvisioning/{targetTenantId}/{mappingRtId}` | `ExternalTenantUserMapping.RemoveAdminProvisioning-1` |
| `POST externalTenantUserMappings` | `ExternalTenantUserMapping.CreateMapping-1` |

The reads (`GET adminProvisioning/{target}`, `sourceUsers`, `roles`, `groups`, `externalTenantUserMappings` and `sourceUserLookup`) stay REST reads.
Update and delete of `externalTenantUserMappings` stay REST (generic CRUD story of the Feature).

- **Caller.** `ProvisionAdmin*`, `ProvisionCurrentUser`, `RemoveAdminProvisioning`: `TenantManagement` or `UserManagement` (`IdentityTenantAdministrationWritePolicy`);
  `CreateMapping`: `UserManagement` (`IdentityUserAdministrationWritePolicy`); repeated in the handlers on the validated principal.
- **Target tenant.** The provisioning methods run in the caller's tenant and write into `targetTenantId`, which must be the caller's token tenant or lie
  in its subtree (`AdminProvisioningTargetScope`, the rule of `AdminProvisioningTargetScopeFilter`; `RoleEnforcement=Warn` stages it only for REST
  calls, a bus or GraphQL call is refused in either mode) - before any lookup or
  write; refused = `METHOD_FORBIDDEN`, `reason = tenant-out-of-scope`. Then: the target exists (`TENANT_NOT_FOUND`), the source tenant is a registry
  ancestor of the target (`SOURCE_TENANT_NOT_ANCESTOR`), no mapping exists for the source user (`MAPPING_ALREADY_EXISTS`, parameter `existingMappingId`).
  Data access beyond the call's tenant: the mapping, its `TenantOwners` / group membership and the `OctoTenantIdentityProvider` in the target tenant,
  written through the system context as before; the target-tenant rule is the access rule for them (no data permission of the target tenant is evaluated,
  as before).
- **The caller of `ProvisionCurrentUser`** is the validated principal: its subject and the tenant its token was issued for; a service caller or a token
  without a tenant is `CALLER_NOT_A_USER` (parameter `missing` = `subject` / `tenant`).
- **`CreateMapping`** keeps the cross-tenant checks of the REST create: `SOURCE_TENANT_NOT_PERMITTED` (one answer for every refused source),
  `MAPPING_ALREADY_EXISTS`, `UNKNOWN_GROUP` (parameter `unknownGroupIds`), the role change guard (`METHOD_FORBIDDEN` + `reason`). It does **not** set
  `replacesGenericCreate`: on the existing type `ExternalTenantUserMapping` the flag is a Major (row M16 of the CK SemVer rules). Since System.Identity
  3.6.0 the generic create is refused anyway: the type carries `writeAccess` (only system sessions write it, engine message 144 for every caller-scoped
  write; `docs/ck-model.md`), so the cross-tenant checks cannot be bypassed through GraphQL or a caller `ImportRt`.

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, bodies, status codes of a success | create `201` + `ExternalTenantUserMappingDto`, `provisionCurrentUser` `201` / `200` + `X-Provisioning-Outcome`, delete `200`, mapping create `201` with the relative `Location` | unchanged |
| Target outside the caller's subtree | empty `403` (filter) | unchanged; the same rule now also holds for a GraphQL / bus caller. Under `RoleEnforcement=Warn` (not the default) a REST call is logged and allowed (staging, as before); a GraphQL / bus call is refused: a new path without existing callers |
| Unknown target tenant | `404` "Tenant '…' not found." | unchanged (`TENANT_NOT_FOUND`) |
| Source tenant not an ancestor | `403` problem `SourceTenantNotAncestor` | unchanged (`SOURCE_TENANT_NOT_ANCESTOR`) |
| Mapping exists for the source user | `409` problem with `existingMappingId` | unchanged (`MAPPING_ALREADY_EXISTS`) |
| `provisionCurrentUser` without `sub` / `tenant_id` in the token | `400` "Cannot determine user identity / source tenant from token." | unchanged (`CALLER_NOT_A_USER`); now checked after the target-tenant rule and before the tenant lookup, so such a token on an unknown target gets the `400` instead of the `404` |
| `provisionCurrentUser`: shadow user without a resolvable home identity | `409` problem | unchanged (`HOME_IDENTITY_UNRESOLVED`); the caller named in `detail` comes from the token's name claims (the stored name before) |
| `provisionCurrentUser`: target still initializing | `503` after the retries | unchanged (`TENANT_INITIALIZING`, retries in the handler) |
| `provisionCurrentUser`: user name written to the mapping | the token's `preferred_username` / `name` claim, else the stored name | **intended change:** the user name stored in the caller's tenant (the method caller carries no profile claims; the stored name is the one the token exchange matches) |
| `withGroups`: a group id that is no object id | unhandled `500` | **intended REST change:** skipped like an unknown group id - the `500` was a bug |
| Delete: unknown mapping | `404` "Mapping '…' not found in tenant '…'." | unchanged (`MAPPING_NOT_FOUND`) |
| Mapping create: refused source, duplicate, unknown group, guard refusal | `403` / `409` / `400` problems, guard `403` / `409` with WARN and `Identity.RoleChangeRefused` | unchanged |
| Cross-tenant grant audit events (`Identity.CrossTenantGrant*`), `actorName` | the token's name claim (`name` / `preferred_username`), a service caller its `client_id`, else `sub` | **intended change:** the user name stored for the caller's subject in its token tenant (the name the identity service writes into the tokens it issues), a service caller its client id; no stored user (a deleted user, a token of another issuer) = the subject with a WARN line that names no user. Reason: the method caller carries no profile claims, and a name parameter would be caller-controlled |
| Unexpected failure | unhandled `500` | `500` problem `METHOD_HANDLER_FAILED` (same status, no exception text) |
| `RoleEnforcement=Warn` (not the default) | caller without the role let through and logged | **intended REST change:** refused by the method (403 problem, `role-required`), as for the other facades |
| Audit | grant events only | plus one `Identity.Method` event per call (`targetTenantId`, `sourceTenantId`, `mappingRtId`, `provisioningOutcome`) |

Generic create callers of `ExternalTenantUserMapping` (first party): none in this repository (the identity service writes mappings through its stores and
these methods; the token exchange creates bare mappings through the store, not through GraphQL).

Tests: `Api/TenantApi/AdminProvisioningRestMethodFacadeTests` (every write endpoint runs its method in-process outside the request, one event each, nothing on
the broker; REST and the dispatcher leave the same mapping, roles and groups; `ProvisionCurrentUser` created / already-provisioned and the service caller;
the handler's tenant lookup for an unknown target; a target outside the caller's subtree refused on every method with nothing written; another tenant's
token; a caller without the role; the cross-tenant checks of `CreateMapping`), the controller-level suites through `ProvisioningMethodTestFacade`
(`DuplicateExternalTenantUserMappingIntegrationTests`, `CrossTenantAncestryIntegrationTests`, `AdminProvisioningSourceUsersIntegrationTests`,
`TenantExchangeIntegrationTests`), `Authorization/AdminProvisioningPipelineTests`.

Neither group carries a deprecation (deprecation wave of identity wave 2 is its own story); REST is not removed and gets no `Sunset` header.

## REST facades of the role, group, API scope and API resource CRUD (System.Identity 3.7.0)

Since System.Identity 3.6.0 every caller-scoped generic write of these types is refused (`writeAccess`, `docs/ck-model.md`), so create, update and
delete run as CK methods; generic GraphQL reads stay. The REST write endpoints are **facades** of them: the controller resolves the route's name to the
rtId (roles by role name, scopes and resources by name, groups by rtId) and maps the envelope; every rule lives in the handlers
(`Methods/RoleCrudHandlers.cs`, `GroupCrudHandlers.cs`, `ResourceCrudHandlers.cs`; the static creates share `IdentityCreateMethodHandlerBase`).

| REST endpoint | Method | Roles (REST policy) |
|---|---|---|
| `POST roles` / `PUT roles/{roleName}` / `DELETE roles/{roleName}` | static `Role.CreateRole-1` / `Role.UpdateRole-1` / `Role.DeleteRole-1` | `UserManagement` (`IdentityUserAdministrationWritePolicy`) |
| `POST groups` / `PUT groups/{rtId}` / `DELETE groups/{rtId}` | static `Group.CreateGroup-1` / `Group.UpdateGroup-1` / `Group.DeleteGroup-1` | `UserManagement` |
| `POST apiScopes` / `PUT apiScopes/{name}` / `DELETE apiScopes/{name}` | static `ApiScope.CreateApiScope-1` / `ApiScope.UpdateApiScope-1` / `ApiScope.DeleteApiScope-1` | `TenantManagement` or `UserManagement` (`IdentityTenantAdministrationWritePolicy`) |
| `POST apiResources` / `PUT apiResources/{name}` / `DELETE apiResources/{name}` | static `ApiResource.CreateApiResource-1` / `ApiResource.UpdateApiResource-1` / `ApiResource.DeleteApiResource-1` | `TenantManagement` or `UserManagement` |

- **Same path as the other facades:** `IIdentityMethodFacade`, in-process, outside the request (no Mongo session or transaction of the request around
  the call), caller from the bearer token, one `Identity.Method` event per call (details `name`, `nameBefore`; group create `rolesAfter`; never a
  secret). The handlers repeat the declared roles on the validated principal.
- **Derived fields are never parameters.** The role manager derives `Role.NormalizedName`, the group handlers `Group.NormalizedGroupName`
  (upper-invariant, as before). API resource secrets are no parameter: they change only through the secret methods, and an update keeps them (one
  version-checked read-modify-write, `CONCURRENT_CHANGE` when it loses).
- **Data permission.** The static creates check the caller's `Write` permission on the declaring type (`CheckTypeWritableAsync`), the instance methods
  the target (`CheckTargetWritableAsync`), with the gateway's answers: not visible = `METHOD_TARGET_NOT_FOUND` (`404`), visible but not writable =
  `METHOD_FORBIDDEN` (`data-permission`, `403`).
- **Guard.** `Role.UpdateRole` / `DeleteRole` refuse a built-in role (`built-in-role`), `Group.DeleteGroup` the removal of the last user administrator,
  `Group.CreateGroup` an initial built-in role the caller does not hold (`role-not-held`, the grant rule of `Group.SetRoles`; `docs/role-guards.md`).
  REST turns the refusal back into the audited problem answer (`RoleChangeProblems.RefusalOf`, WARN log, `Identity.RoleChangeRefused`).
- **Caches.** The API scope and resource methods publish `CorsClientsUpdate` after every write, as REST did. A role rename needs no refresh: holders
  keep the role by id, the next token and role check read the new name.
- **Names.** `Create`, `Update` and `Delete` are reserved method names (compiler error 102), hence `CreateRole`, `UpdateGroup`, ... No method sets
  `replacesGenericCreate`: on these existing types the flag is a Major (row M16), and `writeAccess` already refuses the generic create.

Parity table (REST before -> facade):

| Point | REST before | Now |
|---|---|---|
| Routes, bodies, status codes of a success | roles, scopes, resources `200` empty; group create `201` + `GroupDto`, update `200` + `GroupDto`, delete `200` | unchanged (the group DTO is read after the method) |
| Unknown role / scope / resource name, unknown group | `404` (`NotFoundErrorDto`; group: empty) | unchanged (resolved in the controller; `METHOD_TARGET_NOT_FOUND` of a race maps to the same answer) |
| Role: duplicate or invalid name | `400` `OperationFailedErrorDto`, role manager code + description | unchanged (`ROLE_ALREADY_EXISTS` / validation failure, description rebuilt with the role manager's describer) |
| Role: rename or delete of a built-in role | `409` problem `built-in-role`, audited | unchanged, plus the `Identity.Method` event |
| Group: duplicate name (create, rename) | `409` text `A group with name '…' already exists.` | unchanged (`GROUP_ALREADY_EXISTS`) |
| Group create: unknown role id | group stored, then the role write failed with an unhandled `500` | **intended REST change:** `404` `Role with id '…' not found.`, nothing created - the `500` and the half-created group were a bug |
| Group create: initial built-in role the caller does not hold | created with the role, no guard | **intended REST change:** `403` problem `role-not-held`, audited, nothing created. Reason: a caller could create a group with a role it does not hold and join it later (escalation gap); the same rule as `PUT groups/{g}/roles` |
| Group create: initial role the caller cannot read (only with an enforcing data policy on roles) | written | **intended REST change:** `404` as for an unknown role id |
| Group delete of the last user administrator | `409` problem, audited | unchanged |
| API scope / resource: duplicate name on create | `409` text | unchanged (`API_SCOPE_ALREADY_EXISTS` / `API_RESOURCE_ALREADY_EXISTS`) |
| API scope / resource: rename onto the name of another one | stored a second entry with the same name | **intended REST change:** `409` with the create's text, nothing changed - two scopes or resources with one name were a bug |
| API scope: blank name (create, update) | unhandled `500` (the check threw outside the error handling) | **intended REST change:** `400` `InternalServerErrorDto("Scope name cannot be null or empty.")` |
| API resource: blank name | `500` `InternalServerErrorDto("API Resource name cannot be null or empty.")` | unchanged |
| API resource update: lost concurrent write | `409` problem | unchanged (`CONCURRENT_CHANGE`) |
| Omitted user claims / scopes on update | kept | unchanged |
| Unexpected failure | the exception text (`400` scopes, `500` roles, groups and resources) | same status; **intended body change:** a fixed message (`Creation of role failed.`, `Deletion of the API scope failed.`, ...), no exception text leaves the service; group update / delete `500` problem `METHOD_HANDLER_FAILED` |
| Role: a role manager error other than a duplicate or invalid name (store failure) | `400` `OperationFailedErrorDto` with the store's errors | **intended REST change:** `500` with the fixed message - such an error is a failure of the service, not of the request |
| Type or target the caller cannot read / write (only with an enforcing data policy on the type; open by default) | not checked: written anyway | **intended REST change:** `404` / `403` problem `METHOD_FORBIDDEN` (`data-permission`), nothing written (CWE-863, as for the other facades) |
| `RoleEnforcement=Warn` (not the default) | caller without the role let through and logged | **intended REST change:** refused by the method (`403` problem, `role-required`), as for the other facades |
| Audit | none | one `Identity.Method` event per call |

**Known limitation:** the stored secret values of an API resource (`ApiResource.ApiSecrets`, hashes of the generated secrets, never the clear text) stay
readable through generic GraphQL reads. Hiding them (`access: Hidden`) is a Major of System.Identity (row T7) and waits for the next major, like the
other secret attributes.

Tests: `Api/TenantApi/IdentityCrudRestMethodFacadeTests` (every endpoint runs its method in-process outside the request with one event; the REST policy;
REST and the dispatcher side by side per type - stored state with derived names, duplicates, renames, deletes, unknown targets; the built-in role; a group
create with an initial built-in role the caller does not hold, and with an unknown role id; a renamed role in the next role lookup without a restart; an
update that keeps the API resource secrets; another tenant's token; a caller who may not write the type or the target), `Persistence/IdentityMethodDeclarationsIntegrationTests`,
`Methods/IdentityMethodHostTests`, plus the unchanged REST suites (`RoleChangeGuardTests`, `GroupRoleChangeGuardTests`, `TenantApiRoleAuthorizationTests`).

No deprecation yet (deprecation wave of identity wave 2 is its own story); REST is not removed and gets no `Sunset` header.
