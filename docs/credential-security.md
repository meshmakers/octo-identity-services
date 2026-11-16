---
description: Credentials never in logs or URLs, REST secret delete, session revocation, second-factor guard, user store concurrency
applies_to: src/IdentityServices/{Logging,TenantApi,Controllers/Api}/**, {OctoUser*,*Revocation*,SecondFactorEvidence,*UserCredentialChangeService}.cs
---

# Credential handling, sessions and logging

## Logging: credentials never reach a log property

`nlog.config` renders JSON with `includeEventProperties="true"`, which serializes every message-template
argument **by reflection over its public properties** — bypassing any redacting `ToString()`. Two leaks
followed from that, both closed:

- **OpenIddict messages (INFO).** `OpenIddictServerDispatcher` logs `{Response}` / `{Request}`; the message
  text was redacted, but the JSON property carried `AccessToken`, `IdToken`, `RefreshToken`, `client_secret`
  and `code` in clear text. `Program.cs` calls `RegisterSecretRedaction()` (`Logging/LogSecretRedaction.cs`)
  **before** `LoadConfigurationFromFile`: an NLog object transformation renders `OpenIddictMessage`,
  `OpenIddictRequest` and `OpenIddictResponse` through their own redacting `ToString()` in every layout.
  Register new secret-bearing library types there, not in the layout.
- **API DTOs (TRACE).** ASP.NET Core logs action arguments through `ToString()`; the compiler-generated
  record `ToString()` printed `Password`, 2FA `Code`, `RecoveryCode`, `Token`, `SharedKey`. Every DTO in
  `Controllers/Api` with such a string member overrides
  `protected virtual bool PrintMembers(StringBuilder) => RedactingDtoPrinter.Print(this, builder)`, which
  prints `[REDACTED]` for any member whose name matches `Password|Code|Secret|Token|SharedKey`.
  🔴 **A new DTO with such a member needs that one line** — `SensitiveDtoToStringTests` scans the whole
  namespace by reflection and fails for a DTO that renders the value.

Tests: `tests/IdentityServices.UnitTests/Logging/LogSecretRedactionTests.cs` runs the **real**
`nlog.config` (Console target swapped for a memory target) and includes a control that proves the leak
without the registration; `tests/IdentityServices.UnitTests/Controllers/SensitiveDtoToStringTests.cs`.
🔴 The DTO mechanism protects `ToString()` output only (the text ASP.NET Core logs), **not** NLog event
properties: a credential-bearing DTO passed as a message-template argument (`{Dto}` / `{@Dto}`) is still
reflected by the JSON layout. Never do that unless an NLog object transformation in
`LogSecretRedaction` covers the type; log selected non-secret members instead.

**Token values (Security).** OpenIddict logs issued tokens as plain string arguments at Trace/Debug
(EventId 6013 `A new '{Type}' JSON Web Token was successfully created: {Payload}.` = the complete signed access
token; also `{Token}`, `{ReferenceId}`), which the object transformation above never sees. `CredentialLogRedaction`
(the `ILoggerFactory` decorator) therefore also masks, for every provider and level: JWT-shaped values
(JWS/JWE, `eyJ…`) and Data Protection payloads (`CfDJ8…`) in every string value and in the formatted message of any
state; every value whose argument name is in `CredentialLogRedaction.TokenValueNames` (opaque reference tokens;
not `Code`, the dev OTP stub logs its code on purpose); `Payload` in `OpenIddict.*` categories only. The line stays
with `***`. Not covered: exception texts (IdentityModel hides token content unless `ShowPII`, Development only).
🔴 A new log line that carries a token must use one of those argument names or rely on the shape rule; never log a
token under another name in a non-JWT shape. Tests: `Logging/TokenLogRedactionTests` (shapes, names, OpenIddict
templates, non-list state, real `nlog.config` JSON record at Trace) and
`Api/Protocol/TokenValuesNotInLogTests` (real token endpoint at Trace: the issued access token, its signature and
the client secret are in no line; the 6013 line is present and masked).

## REST secret delete removes by predicate (Security)

`ApiSecretsController.DeleteSecretOfClient` / `DeleteSecretOfApiResource` (`DELETE {tenant}/v1/apiSecrets/client|apiResource/{id}/{base64(hash)}`)
answered 200 but removed nothing for an entity read from MongoDB: the `AttributeRecordValueList` of such an entity holds plain `RtRecord`s and
hands out **new** `RtSecretRecord` wrappers on every enumeration, so `Remove(wrapper)` found nothing and returned `false` silently; a revoked
client secret kept authenticating. Both endpoints now call `RemoveAll(predicate)` (as the `Client.RemoveSecret` method does) and
answer 404 when nothing matched. **Every REST secret write** (POST, PUT, DELETE for clients and API resources) is now a version-checked
read-modify-write (`IOctoClientStore.MutateAsync`, `IOctoResourceStore.MutateApiResourceAsync`, helper `GuardedEntityMutation`: read in a transaction,
change, replace with the `rtVersion` that was read, re-read and re-apply on `RtVersionConflictException`, 20 attempts, then `409` problem). Before,
`UpdateAsync` replaced the snapshot unversioned, so two overlapping secret writes could bring a deleted secret back or drop an added one
(review finding on PR #225). **The full updates followed:** the client `PUT` (and the overlay URI endpoints and the flag `PATCH`) and the API
resource `PUT` applied their DTO to an entity read before and replaced it without an expected version, so a full update that overlapped a secret
delete wrote the deleted secret back. They now run as `MutateAsync` / `MutateApiResourceAsync` too (the DTO is applied to the fresh read, again on a
conflict; `409` problem after 20 attempts); `ClientStore.UpdateAsync` and `ResourceStore.UpdateApiResourceAsync` were removed, so no unversioned
client or API resource replace is left (`FullUpdates_ConcurrentWithSecretDeletes_NeverBringADeletedSecretBack`: six deletes and six full updates
at once, red on the old code: deleted secrets came back and the overlapping updates answered 400/500). 🔴 **Rule for every record list of a stored entity:** never `Remove(item)` / `Contains(item)` / `IndexOf(item)` with
an instance you enumerated; use `RemoveAll` / `FindIndex` with a predicate, and write a changed record back through the indexer (as
`ReplaceSecret` in the PUT endpoints does; the PUT endpoints were not affected). No 404 of the controller echoes the secret value (the stored hash)
any more. octo-cli (`DeleteApiSecretClient` / `DeleteApiSecretApiResource`, SDK `IdentityServicesClient`) is unchanged; Studio does not call
these endpoints. API resource secrets authenticate nothing since the OpenIddict migration, so only the client case has a token-endpoint
test. Tests: `ApiSecretsControllerTests` (`DeleteClientSecret_*` with the token endpoint, `DeleteApiResourceSecret_*`, unknown secret / owner,
403, PUT of an API resource secret persisted, no hash in the logs at the deployed levels, `ConcurrentSecretWrites_*`: four deletes and six creates at
once lose nothing and bring nothing back, red with the unversioned write).

## No credential values in request URLs (Security)

Found while verifying the password-change session rule: the admin reset took the new password as a query parameter, and the ASP.NET Core request
log (INFO, `Microsoft.AspNetCore.Hosting.Diagnostics`) plus the TRACE argument log of `ControllerActionInvoker` wrote it into
the log file; ingress access logs and traces would capture such URLs too. The REST secret delete/get carried the stored hash
in the path. Decided by Gerald 2026-11-01:

- **Admin reset** `POST {tenant}/v1/users/ResetPassword`: body `ResetUserPasswordRequestDto { userName, password }` only.
  `[RefuseCredentialInQuery("password")]` (resource filter, `TenantApi/v1/Controllers/RefuseCredentialInQueryAttribute.cs`,
  the single place of the refusal) answers `400` problem details with an update hint when the query carries `password` - after
  authorization (an unauthorized caller still gets 401/403), before model binding, so the action and its TRACE argument log
  never run. Hard refusal, no fallback: octo-cli, the SDK (`IdentityServicesClient.ResetPassword`) and Refinery Studio
  (`@meshmakers/octo-services` `IdentityService.resetPassword`) send the body; release identity only together with
  or after them.
- **Audit actor:** `UsersController.ResetPassword` passes `AuditActor.FromPrincipal(User).Actor` (user name, else `client <id>`),
  not `User.Identity?.Name` (always null under `MapInboundClaims = false`, hence the former `(anonymous reset token)`).
- **Secrets:** `POST apiSecrets/{client|apiResource}/{id}/delete` and `.../lookup` with body `ApiSecretValueRequestDto { valueEncrypted }`
  (POST sub-resource, not DELETE with a body: no defined DELETE body semantics, proxies/clients may drop it, the API already uses POST
  action sub-resources). The path variants `DELETE`/`GET .../{secretValue}` stay **for one release** (removal is the follow-up of
  the no-credentials-in-URLs rule); they no longer bind the value as an action argument (read from `RouteData` in `TakeLegacySecretValue`, the single place
  of the deprecated path), log one WARN `Deprecated API secret request: {Operation} for {OwnerKind} '{Owner}' ...` without the
  value, and overwrite the trace tag `url.path` with the masked path. `PUT` already carried the hash in the body.
- **Log redaction:** `Logging/CredentialLogRedaction.cs` - `AddCredentialLogRedaction()` (Program.cs, after `UseNLog()`) replaces the
  `ILoggerFactory` with a decorator whose loggers mask, in the structured values (`string`, `PathString`, `QueryString`, `Uri`) of every
  log line **and every scope** (the hosting scope carries `RequestPath`, and `nlog.config` renders scope properties into each record), the query parameters `password|newPassword|secret|secretValue|clientSecret` and the value segment of
  `/apiSecrets/{client|apiResource}/{id}/{value}` (not the `delete`/`lookup` action segments) with `***`; `{OriginalFormat}` is kept, so
  NLog renders the template with the masked values. A factory decorator, not a provider decorator: provider-specific filter rules keep
  working and providers added later (test hosts, `AddProvider`) are covered. A line without a match passes unchanged (same state
  instance). OpenTelemetry's ASP.NET Core instrumentation already redacts query values (`url.query`).
- Request DTOs are classes with a `ToString()` that never prints the value (a record's generated `ToString()` would print the password into
  the TRACE argument log).
- **Tests:** `Api/TenantApi/CredentialsNotInUrlTests` (a host logging everything at TRACE into a capturing provider: body reset works and
  the password is in no line; query reset 400 with hint, nothing changed, `password=***` in the request log; body + query refused; 403 before
  the hint for a caller without the role; audit `acting user 'client <id>'` and user name; secret lookup/delete by body for client and API
  resource with neither hash nor Base64 hash in any line and no deprecation WARN; body without value 400; reader 403; deprecated path variants
  work, WARN twice without value, path masked), `Logging/CredentialLogRedactionTests` (patterns, decorator, later providers, the real
  `nlog.config` JSON record), and the reset tests moved to the body form.

## Credential guard regression tests of the REST API

`tests/IdentityServices.IntegrationTests/Api/TenantApi/IdentityCredentialGuardRestTests` pins that the tenant API v1 never returns
or accepts a credential: a user whose `PasswordHash`, `SecurityStamp`, authenticator key and recovery codes hold fixed dummy values
(written through `UserManager` and the user store, as the service does) is read through `users`, `users/GetPaged`, `users/{name|email|rtId}`,
`users/directory`, `users/{name}/roles|directRoles`, `groups` (all reads, the user as a member); `PUT users/{name}` and `POST users` with
`passwordHash` / `securityStamp` / `userTokens` / `password` in the body change no credential; `GET clients` (all reads) carries neither
the clear text nor the stored hash of a client secret, a secret record in a client body is not bound and `clientSecret` is stored hashed;
`apiSecrets/client/{id}` and its `lookup` return the stored hash (the handle, by design) but never the clear text. A capturing log provider
at Debug (the MongoDB command log of every store write included) must carry no dummy value, and must contain the rendered command of the
seed write (non-vacuous). There is no export endpoint in this service. Path table of all repositories: `octo-documentation/src/octo-mesh-documentation/docs/technologyGuide/constructionKits/ckLanguage2/accessModifiers.md` § Regression tests.

## Administrator revokes all sessions of a user

`POST {tenant}/v1/users/{userName}/revokeSessions` and the bulk `POST {tenant}/v1/users/revokeSessions?scope=shadowUsers`
(dry run unless `dryRun=false`) rotate the security stamp, revoke OAuth tokens and authorizations and delete the
`RtServerSideSession` records of the subject in the current tenant (`IUserSessionRevocationService`, policy
`IdentityUserAdministrationWritePolicy`). Issued JWT access tokens stay valid until expiry. Details:
`docs/authentication.md` § Administrator Revokes All Sessions of a User; tests `UserSessionRevocationTests`.

## Password change ends the user's sessions

Redeeming a refresh token checks only `CanSignInAsync`, never the security stamp, so a password change
revokes explicitly. **Every** REST password path calls `IUserCredentialChangeService.OnPasswordChangedAsync`
(`Services/UserCredentialChangeService.cs`, scoped) after the new password is persisted:
`POST {tenant}/api/manage/change-password`, `.../set-password` (through `User.ChangePassword` / `User.SetPassword` since
the account-page change), admin `POST system/v1/users/ResetPassword` (through `User.ResetPassword`)
and the anonymous `POST {tenant}/api/auth/reset-password`. The helper (1) rotates the security stamp,
(2) revokes every token and authorization of the user's subject (`RtId`) through the OpenIddict stores of
the **current tenant** (other users and the same user in another tenant are untouched; the old refresh
token answers `invalid_grant`), (3) writes one `Information` audit log line naming tenant, subject, acting
user (`(anonymous reset token)` for the token reset; the admin REST reset passes `AuditActor.FromPrincipal(User).Actor`
since that rule, i.e. the user name or `client <id>` for a client-credentials caller) and path - never a password, hash or token value.
A failing revocation throws, so the endpoint never reports success while old refresh tokens still work;
the caller keeps a new sign-in via `RefreshSignInAsync` (change/set-password). A new password path - REST or
CK method handler - must call the same helper. Tests:
`UserCredentialChangeServiceTests`, `Api/Manage/PasswordChangeRevokesSessionsTests` (all four paths against the
real token endpoint), `Persistence/PasswordChangeRevocationTenantIsolationIntegrationTests`.

**Revoke before and after the password write (Security; decision OD-6: ordering, no outbox).** The user store and
the token/authorization stores are separate writes without a shared transaction (each store opens its own session), so a
stop between the password write and the helper above left old refresh tokens redeemable. `OctoUserManager` overrides
`ChangePasswordAsync`, `ResetPasswordAsync` and `AddPasswordAsync` (bodies follow the framework step by step) and calls
`IUserTokenRevocation.RevokeAllAsync` (`IdentityServerPersistence/Services/UserTokenRevocation.cs`, registered in `Program.cs`,
optional constructor parameter of the manager) between the in-memory hash update and `UpdateUserAsync`: only after the current
password / reset token was verified and the policy passed, so a request refused before the write (or a forged one) revokes
nothing; a store write that fails after the revocation (`ConcurrencyFailure`, a user validator) keeps the old password with the
sessions ended (accepted, safe direction; review finding on #234). A failing revocation
throws before the password is stored. `UserCredentialChangeService` uses the same `IUserTokenRevocation` for the second
revocation. 🔴 A new password write must go through these `UserManager` methods (or call `IUserTokenRevocation` before its own
write); the manager built by `CrossTenantSecondFactorVerifier` has no revocation and must never write a password. Tests:
`IdentityServerPersistence.UnitTests/Stores/OctoUserManagerPasswordWriteTests` (order, refusals, failing revocation) and the
`CrashAfterPasswordWrite_*` tests in `PasswordChangeRevokesSessionsTests` (six paths: REST change/set/admin reset/token reset,
methods `User.ChangePassword`/`User.ResetPassword`; the post-write helper is replaced by a failing one, the new password works and
the old refresh token answers `invalid_grant`; red without the pre-write revocation) plus `FailedPasswordChange_RevokesNothing`.

## Two-factor enabled without a usable second factor is refused

ASP.NET Core Identity challenges only when `TwoFactorEnabled` is set **and** a provider is valid, so a user with
`TwoFactorEnabled = true` but no authenticator key would sign in with the password alone. That state arises in a
tenant cloned with ExportRt/ImportRt under System.Identity 2.27.0 (`UserTokens` is `Secret`, `TwoFactorEnabled`
was exported; since 2.28.0 `ImportRt` refuses users), after a restore from another environment (key ring), after an
import of edited user data, or when an admin deletes `UserTokens`. Rule (decided by Gerald 2026-10-30, option a, fails closed):
`POST {tenant}/api/auth/login` verifies the password with `CheckPasswordSignInAsync` (no cookie) for such a user and,
if it is correct, answers `200 { success: false, secondFactorSetupRequired: true, errorMessage: "Your second factor must be
set up again. Please contact your administrator." }`, writes a warning log + `User Login Failure` audit entry (user name
only) and issues no cookie. A wrong password follows the normal failure path (lockout counted once; the answer does not
confirm the password). The login UI shows the translated text (`LOGIN.ERROR_SECOND_FACTOR_SETUP_REQUIRED`).
*Usable* means an authenticator key only: the confirmed-e-mail provider is valid for ASP.NET Identity but its code is
not delivered (tracked as its own bug), recovery codes only work after a challenge. Recovery: an admin switches
the second factor off with `User.DisableTwoFactor-1` or `POST {tenant}/v1/users/{userName}/disableTwoFactor` (section
below; a generic GraphQL/ImportRt write of `TwoFactorEnabled` is refused); the user signs in and enrols again. The cross-tenant password login refuses the
same state on top: when `ICrossTenantSecondFactorVerifier.GetOptionsAsync` reports
`CanUseAuthenticator = false` for the source user, `Login` answers `secondFactorSetupRequired` instead of issuing
a challenge. Tests: `Api/Auth/TwoFactorUnusableLoginTests` (with and without confirmed e-mail, wrong password,
recovery after 2FA off), `CrossTenantSecondFactorTests.PasswordLogin_SourceUserWithTwoFactorButNoAuthenticator_*`.

## User store concurrency: every user write advances `rtVersion`

`OctoUserStore` writes users with the expected `rtVersion` (engine guard). The rules:

- **`UpdateAsync`** replaces the user with the `RtVersion` the instance was read with. A concurrent change of the same
  user (profile, password, lockout, counter, token) returns `IdentityResult.Failed(ConcurrencyFailure)` instead of
  last-writer-wins; the caller (REST `PUT users/{name}`, self-service) shows the error and the user retries from a fresh
  read. The instance's `RtVersion` is left unchanged on a conflict.
- **One read-modify-write, `MutateUserGuardedAsync` (`OctoUserStore.Atomic.cs`).** Every other write of a stored user goes
  through it: read the user in a transaction, change it, replace it with the read version (so `rtVersion` advances), re-read
  and re-apply on `RtVersionConflictException` (at most `MaxConcurrencyAttempts` = 40), MongoDB write conflicts are retried
  inside by `MongoWriteRetry`. Callers: `RecordAccessFailureAsync` / `ResetAccessFailedCountAtomicallyAsync` (the
  `IAtomicUserLockoutStore` that **production** uses through `OctoUserManager`), the static cross-tenant variants
  (`RecordAccessFailureAsync(ITenantRepository, …)`, `ResetAccessFailedCountAsync(ITenantRepository, …)`), recovery-code
  redemption, `SetTokenAsync` / `RemoveTokenAsync` and the `IUserLockoutStore` members below.
  🔴 The atomic lockout store used to replace *without* an expected version and kept the old `rtVersion`, so a stale
  `UpdateAsync` (profile edit, admin edit, password rehash) that read the user before a failure/lockout/reset succeeded and
  wrote the pre-lockout counter and lockout end back. Never write a stored user without the version it was read with.
- **`IUserLockoutStore` members** `IncrementAccessFailedCountAsync`, `ResetAccessFailedCountAsync`,
  `SetLockoutEndDateAsync` are kept (the interface requires them) as guarded read-modify-writes through the same helper. They
  are **not** reached in production, because `OctoUserManager` bypasses them for failure counting and reset; they stay
  covered by `PlainUserManager_ParallelFailedSignIns_AreAllCounted` and `ParallelFailedSignIns_ReturnDistinctCounts` so a plain
  `UserManager<RtUser>` over the store (tests, tools) is also correct.
- **Version follow-up.** After such a write the caller's instance takes over the new `RtVersion` only if the stored user was
  still the version the instance holds (nothing else changed): the `UpdateAsync` that `UserManager` calls right after stays
  valid. If another writer was in between (including a failed sign-in or reset by another request), the instance keeps its old
  version, so its `UpdateAsync` reports the conflict and never overwrites the other writer's fields.
  `OctoUserManager.AccessFailedAsync` itself always returns `Succeeded`: the failure is counted regardless of the caller's
  copy.
- A write that must detect concurrent changes passes the expected version; never combine it with `AttributeNewerThanGuard`,
  atomic RecordArray item updates or linked binaries in the same update (the engine rule throws).
- The counter restarts at 0 when the lockout triggers (ASP.NET Core Identity behaviour). Tests:
  `UserStoreConcurrencyIntegrationTests` (real MongoDB, **`OctoUserManager` as in production**; 10 parallel failures x 20
  rounds, threshold lockout, reset after a successful sign-in, parallel reset + profile update, concurrent profile updates,
  a stale `UpdateAsync` after a counted failure / threshold lockout / reset returns `ConcurrencyFailure` and keeps the
  lockout). They assert the final state, never the number of retries.
