---
description: User.CreateUser, User.Merge and the administrator second-factor reset: the only ways to create, merge and reset a user
applies_to: User{CreateUser,Merge,DisableTwoFactor}Handler.cs, User{Creation,Merge,TwoFactorAdministration,Management}Service.cs, UserEmailUniqueness.cs
---

# User create, merge and second-factor methods

## Administrator switches off a user's second factor (System.Identity 2.30.0)

The recovery path (option a). `IUserTwoFactorAdministrationService` (`Services/UserTwoFactorAdministrationService.cs`, scoped) is
the one implementation; two transports call it:

| Transport | Caller rule | Answer |
|---|---|---|
| CK method `User.DisableTwoFactor-1` (`UserDisableTwoFactorHandler`, one row in `IdentityMethodHost.Handlers`, `CarriesSecret = false`: hosted whatever `EnablePasswordMethods` says) | `IdentityAdminMethodHandlerBase`: scope `octo_api` + `UserManagement` on the validated principal, `METHOD_FORBIDDEN` / `role-required` before the target is read | success; `METHOD_TARGET_NOT_FOUND`; `METHOD_HANDLER_FAILED` when a write or the revocation fails |
| REST `POST {tenant}/v1/users/{userName}/disableTwoFactor` | `IdentityUserAdministrationWritePolicy` | `200 { twoFactorWasEnabled }`, 404 unknown user |

Effect, in this order, all through `UserManager` (guarded, versioned store writes, never the entity): remove the authenticator
key and the recovery codes (`[AspNetUserStore]` tokens `AuthenticatorKey`, `RecoveryCodes`), `TwoFactorEnabled = false`, then
`IUserCredentialChangeService.OnSecondFactorDisabledAsync` (the password-change helper: security stamp, revocation of every refresh token and
authorization of the user in this tenant, one `Information` audit line `Second factor switched off by an administrator: tenant, subject,
acting user, path (AdminRest|MethodDisableTwoFactor), two-factor was enabled`). Idempotent (a user without 2FA gets the same treatment).
Any failure throws: never a success while the key or old refresh tokens survive. The method writes the `Identity.Method` event with the
extra detail `twoFactorWasEnabled`. No key, code or token value is logged or audited. The user's own `POST api/manage/2fa/disable`
(with a verification code) is unchanged. No self rule: an administrator may switch off their own second factor (the REST endpoint never
had one either). Tests: `Api/Methods/UserDisableTwoFactorMethodTests` (method and REST on real MongoDB: end to end with sign-in by password
and a new enrolment over HTTP, idempotent, service token, caller theory for existing and missing target, unknown target, failing revocation,
forged caller, REST 404/403, no authenticator material in audit or logs).

## `User.CreateUser` and the only ways to create a user

A user is created only by this service: the static CK method `User.CreateUser-1` (REST `POST {tenant}/v1/users` is its facade)
(`UserCreateUserHandler`, one row in `IdentityMethodHost.Handlers`, `CarriesSecret = true` because of the optional `sensitive`
`password`: **offered on the bus only with `Methods:Identity:EnablePasswordMethods`**, also for invitations without a password - the
switch is per method; off = `METHOD_HANDLER_NOT_AVAILABLE` for the gateway, while the handler is hosted local only for the REST facade,
the REST facade). Both share `IUserCreationService` (`Services/UserCreationService.cs`, scoped):
`UserManager.CreateAsync` with or without the password (user validators, password policy before the user is stored, normalised name
and e-mail, security stamp), then the welcome notification (with password: e-mail confirmation; without: the invitation to set a
password). The service also refuses an e-mail address another user of the tenant already has (see the table).

| Rule | REST | Method |
|---|---|---|
| Caller | `IdentityUserAdministrationWritePolicy` | `IdentityMethodCallerRules.IsAdministrator` on the validated principal (scope `octo_api` + `UserManagement`), `METHOD_FORBIDDEN` / `role-required`; the gateway refuses a caller without the declared role first; a forged bus caller is rejected by the host |
| `xt_` user name | 400 | `USER_NAME_RESERVED` |
| Duplicate user name (case-insensitive; also `PUT users/{userName}` when it renames) | `409 application/problem+json`, `code: USER_ALREADY_EXISTS`, `field: userName` (`UserCreationProblems.DuplicateUserName`; the name is not echoed or logged) | `USER_ALREADY_EXISTS`, parameter `field=userName` |
| Duplicate e-mail (normalised = case-insensitive; blank e-mail not checked) | `409 application/problem+json`, `code: USER_ALREADY_EXISTS`, `field: email` (`UserCreationProblems`; the address is not echoed or logged) | `USER_ALREADY_EXISTS`, `field=email` |
| Password policy | 400 with the identity errors | `PASSWORD_POLICY_VIOLATION`, details = rule codes only |
| Missing / invalid user name or e-mail | 400 | `METHOD_VALIDATION_FAILED` (`field`) |
| Result | `200` (empty) | rtId of the new user (`UserCreateUserResult.Value`); on the wire `resultJson` is the bare JSON string `"<rtId>"` (host of octo-common-services), so the GraphQL `result` is the rtId itself |

**Duplicate e-mail: only new conflicts are refused (create and change).** The rule lives in `UserEmailUniqueness`
(`Services/UserEmailUniqueness.cs`); `UserCreationService` uses it (`IdentityResult.Failed(DuplicateEmail)`), so REST and method cannot drift. A taken user name wins (the check runs only when the name is
free), so creating the same user twice answers `409` with `field=userName` on REST (earlier: `400 DuplicateUserName`). The controller maps the identity error `DuplicateUserName` (create and rename; the user validator raises it on update too). `IdentityOptions.User.RequireUniqueEmail` stays **off** on
purpose: the user validator runs on every `UserManager.UpdateAsync` / `SetEmailAsync` / `SetUserNameAsync` too, and in a tenant that
already holds two users with one address `FindByEmailAsync` returns one of them, so the other could no longer be updated (profile edit,
role change, security-stamp write, password change). Existing duplicates are not migrated; updates and sign-in of those users are
unchanged (`FindByEmailAsync` returns the first match, as before).

**E-mail change.** `PUT users/{userName}` refuses a **change** of the address to one another user has with the same
`409` (`UserCreationProblems.DuplicateEmail`, logged without the address), before anything is written. `UserEmailUniqueness.ChangesAddress`
decides what a change is: the new address is not blank and differs normalised from the stored `Email` (not from `NormalizedEmail`,
which a stale write could leave behind); keeping the address, changing only its casing and clearing it are not checked, so users
that already share an address stay editable. The owner found by `FindByEmailAsync` must be another `RtId`. Other e-mail write paths,
checked for this story: no CK method changes the e-mail (System.Identity 2.30.0), `Email` is `MethodOnly` (generic GraphQL, `ImportRt`,
blueprint seeds and pipelines cannot write it), `ManageApiController` has no e-mail change, the self-service e-mail enrolment
(`SelfServiceIdentifierService`) writes a verified identifier, not `RtUser.Email`.

**Deliberately not checked (existing decisions, product decision needed to change them):**

| Path | Behaviour | Why |
|---|---|---|
| External-login and LDAP auto-provisioning (`AuthApiController.CreateUserFromExternalProvider`) | creates a separate `{Provider}_{email}` user even when a local user has the address | no automatic account linking (`docs/authentication.md` § External Login Security Model): never link by e-mail (privilege escalation); refusing would lock the external user out |
| Cross-tenant shadow users (`CrossTenantUserProvisioningService`) | created with, and synced on every login to, the home user's address | a dedicated account of the home identity (excluded from tenant discovery); refusing locks the person out of the child tenant, linking would hand a local user's roles to the home identity |
| Tenant admin bootstrap (`UserManagementService`) | not checked | runs only in a tenant without users |

Pinned by `CrossTenantUserProvisioningServiceTests.FindOrCreate_LocalUserWithTheSameEmail_*` / `…_SyncsAnEmailAnotherUserHas` and
`ExternalLoginDeduplicationTests`. Check and write are not atomic (no unique index on runtime entities). Tests:
`Api/TenantApi/UsersCreateTests` (409 also in other casing, name keeps 400, no e-mail not checked, legacy duplicates update and sign in),
`Api/TenantApi/UsersUpdateEmailTests` (change to a taken address 409 also in other casing and from no address, nothing written; free
address, clearing, legacy duplicates keep / re-case their address, a sharing user cannot move to another taken address) and
`Api/Methods/UserCreateUserMethodTests`.

Audit: one `Identity.Method` event per call (success, every refusal, `METHOD_HANDLER_FAILED`), `targetRtId` = the new user (success
only), details `userName`, `withPassword`. The password reaches only the user manager - never a log, audit record or error parameter.
`ResetPasswordOnLogin` is `false` (REST default).

**The generic paths refuse a new user** (engine `GenericCreateReplacement`, driven by `replacesGenericCreate` of `User.CreateUser-1` since System.Identity 3.0.0; a runtime rule was used until 2.30.0):
GraphQL generic/typed/query-row create, MCP create, mesh-adapter inserts, caller `ImportRt` and blueprint seeds answer
`GENERIC_CREATE_REPLACED_BY_METHOD` naming `System.Identity/User.CreateUser-1`; an existing user (rtId stored) is updated as before.
Nothing in this service is affected (repository writes are not generic paths). Tests:
`Api/Methods/UserCreateUserMethodTests` (real MongoDB, host with the switch on: password user signs in, normalised fields and stamp,
invitation without password, duplicate name (also other casing) and e-mail, policy, reserved name, validation, caller theory, service
token, forged caller, audit, welcome notification, no password in audit or logs), `Methods/IdentityMethodHostTests`,
`IdentityMethodDeclarationsIntegrationTests` (declared role `UserManagement`, flag still off), `Api/Methods/UserCreateUserWireFormTests` (the envelope through the real host core, in-process transport, carries the bare rtId string, not `{"value": ...}`).

## `User.Merge` and the one merge of a duplicate user

REST `POST {tenant}/v1/users/{userName}/merge` and the CK method `User.Merge-1` (`UserMergeHandler`, one row in
`IdentityMethodHost.Handlers`, `CarriesSecret = false`: hosted whatever `EnablePasswordMethods` says) share `IUserMergeService`
(`Services/UserMergeService.cs`, scoped). The model declares the method since 2.29.0; no CK change.

Steps of the service, in this order: same user = `SameUser` (nothing written); role change guard on the **deletion** of the source user
(`RoleChangeRequest(caller, source, directRoles, null)`, role change guard: `last-administrator`); every external login removed from the source and
added to the target (remove first: `AddLoginAsync` refuses a login another user still owns); `IUserSessionRevocationService.RevokeAsync(source)`
(security stamp, refresh tokens, authorizations, server-side sessions of the source in this tenant; new for REST too); `DeleteAsync(source)`.
**Nothing else moves**: roles, group memberships, claims and cross-tenant mappings of the source go away with it, so a merge never grants
the target a role and the guard only has to judge the deletion.

| Rule | REST | Method |
|---|---|---|
| Caller | `IdentityUserAdministrationWritePolicy` | `IdentityAdminMethodHandlerBase` (scope `octo_api` + `UserManagement` on the validated principal, `role-required` before the target is read); forged bus caller rejected by the host |
| Target | by name, 404 | target rtId, `METHOD_TARGET_NOT_FOUND` |
| Source | by name, 404 | `SOURCE_USER_NOT_FOUND`; missing `sourceUserName` = `METHOD_VALIDATION_FAILED` |
| Source data permission | none | `IRtDataPermissionEvaluator` on the source user: not readable = `SOURCE_USER_NOT_FOUND`, not writable = `METHOD_FORBIDDEN` / `data-permission` (stricter, never looser; open without enforcing policies) |
| Same user | 400 | `CANNOT_MERGE_INTO_ITSELF` |
| Guard | 409 problem `last-administrator` + `Identity.RoleChangeRefused` | `METHOD_FORBIDDEN` / `reason` |
| Login or delete failure | 400 with the identity errors | `MERGE_FAILED`, parameters `step` (`removeLogin` / `addLogin` / `deleteSource`) and `loginProvider`, details = error codes |

Audit: one `Identity.Method` event per call with `sourceUserName`, `sourceRtId`, `transferredLogins`, `revokedTokens` (and `reason` for
a refusal); the revocation writes its own log line with the acting user. A failing revocation throws (REST 500, method
`METHOD_HANDLER_FAILED`) before the source is deleted. Tests: `Api/Methods/UserMergeMethodTests` (REST and method on identical fixtures
compared state by state, audit, every refusal, data permission, last administrator, forged caller, `MERGE_FAILED` mapping),
`Api/TenantApi/UsersMergeTests` (REST), `RoleChangeGuardTests` (REST guard). Since this handler every declared System.Identity method has
one; `UserChangePasswordMethodTests.AMethodWithoutHandler_…` uses an undeclared id.
