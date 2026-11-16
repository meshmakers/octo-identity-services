---
description: "REST facades of the role, merge, create-user and password methods, deprecation waves, account pages running the password methods"
applies_to: "{IdentityMethodFacade,IdentityRestDeprecation,UsersController,ManageApiController,RoleChangeProblems,ResetUserPasswordRequestDto}.cs"
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
| `RoleEnforcement=Warn` (not the default) | caller without `UserManagement` let through and logged | refused by the method (403 problem, `role-required`) |
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
