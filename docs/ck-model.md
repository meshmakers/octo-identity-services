---
description: "Embedded CK models, run-once data migrations, tenant-owned and secret attributes, access modifiers, blueprint-owned opt-in"
applies_to: "src/Persistence.IdentityCkModel/**, src/IdentityServerPersistence/Services/Migrations/**, CkModelCompatibility.cs"
---

# CK model, ownership and data migrations

## CK Model Data Migrations Run Once per Tenant Setup (CK v2 D8/N2)

`DefaultConfigurationCreatorService.SetupTenantAsync` captures the tenant's schema versions **before** the
CK model imports, imports System.Identity / System.Notification, and then runs its own data-migration pass
(`RunCkModelMigrationsAsync` → `ICkModelUpgradeService.UpgradeModelsAsync`). The engine already migrates
every model it imports or updates (`TenantContext.RunCkModelMigrationsForImportAsync`) and records
`MigrationHistory` at the new version. Handing the stale pre-import versions to the second pass made the
upgrade service read "schema older than MigrationHistory", assume a manual downgrade and run the same
migration again (D8: every upgraded model was migrated twice per tenant, with a WARN each time). This was
not concurrent setup: both runs are sequential inside one `SetupTenantAsync`.

`MergeSchemaVersionsAfterImport(preImport, postImport, migrationHistory)` decides what the second pass sees:

| Situation | Version handed over | Effect |
|---|---|---|
| Import changed the model **and** the latest successful `MigrationHistory` entry equals the post-import version | post-import | upgrade service finds the target → skip (no double run, no WARN) |
| Import changed the model, but history is missing or behind (the engine's import-time migration failed; it only logs) | pre-import | migration is retried (N2: with the post-import version and no history row, the upgrade service would record "already at target" and silently skip it) |
| Import did not change the model (already current, or skipped by the engine's downgrade guard because the tenant has a newer version) | pre-import | unchanged behaviour |

History comes from `ICkModelUpgradeService.GetInstalledVersionsAsync` (latest successful row per model),
the same source the upgrade service uses. Tests:
`tests/IdentityServerPersistence.UnitTests/Services/DefaultConfigurationCreatorServiceSchemaVersionMergeTests.cs`.

## Embedded CK Models: "Embedded or Newer" (CK v2 Phase 1 G-H2 / R-L4)

Since the engine's downgrade guard (engine-mongodb) a tenant may keep a **newer** System /
System.Identity / System.Notification than this service embeds (rollback, an old replica during a
rolling update). Never decide with `ITenantContext.IsCkModelExistingAsync(SystemIdentityCkIds.CkModelId)`:
it matches the **exact** version `[x.y.z]`. Use `CkModelCompatibility`
(`src/IdentityServerPersistence/Services/CkModelCompatibility.cs`), which looks the model up **by name**
(highest `Available` version) and classifies it. `IsSatisfied` = embedded version or newer, **any
major** — the same rule as the engine's `IsCkModelSatisfiedAsync`.

**Platform rule R-L4 (one rule everywhere):** if a tenant has a **higher major** than this service
embeds, the service is too old for the tenant: skip the import (never downgrade), log **WARN** "service is
too old for the tenant", and keep running. No tenant-setup failure, and no host-startup failure for the
system tenant. Identity has no meter of its own for this; the WARN is the signal.

| Installed vs. embedded | State | Identity behaviour |
|---|---|---|
| none / only `ResolveFailed` / `Importing` | `NotInstalled` | tenant setup imports the embedded model; `CreateIdentityData` answers `FailedTenantHasNoIdentityCk` |
| older | `Older` | tenant setup imports (upgrade) |
| same | `Same` | nothing to import |
| newer, same major | `NewerSameMajor` | no import (INFO); identity data creation works |
| newer major | `NewerMajor` | no import, WARN "service is too old for the tenant"; setup continues; identity data creation proceeds with the same WARN |

The post-import migration run (`RunCkModelMigrationsAsync`) passes `[embedded, nextMajor)` ranges
(`EmbeddedOrNewerSameMajor`) instead of exact `[x.y.z]` ranges, so a newer same-major model is kept with
an INFO instead of a "newer than the declared compatibility range" WARN on every setup. A higher major
stays outside that range: the upgrade service keeps it (never downgrades) and WARNs, which is the R-L4
rule. `SystemContext.IsSystemTenantExistingAsync` (System model in the system DB) is an engine-mongodb
check (`IsCkModelSatisfiedAsync`, any major). Tests: `CkModelCompatibilityTests` (unit) and
`tests/IdentityServices.IntegrationTests/Persistence/CkModelCompatibilityIntegrationTests.cs`, which
re-key the tenant's System.Identity `CkModel` row to a newer version.

## Tenant-owned attributes: a blueprint update never reverts an administrator's decision (System.Identity 2.23.0)

A blueprint update imports its seed with `ImportStrategy.Upsert` (a full ReplaceOne); the engine keeps an attribute only when its
ownership is not seed-owned. An audit found decisions an administrator takes in the product that were
seed-owned, so an update silently undid them. System.Identity 2.23.0 (minor, `ownership` change per `ck-semver-rules`; attribute ids,
types and defaults unchanged, no migration entry) marks them:

| Entity | Attribute | Ownership | Why |
|--------|-----------|-----------|-----|
| `DataPolicy` | `PolicyEnforcementMode`, `PolicyScope` | `TenantOwned` | Seeds ship AuditOnly / All; the administrator flips to Enforce / narrows to OwnedOnly. Reverting would silently switch authorization enforcement off. Not a credential, part of the tenant's definition, so an `ExportRt` carries it |
| `Client` (assignment overrides) | `System/Enabled`, `AllowedGrantTypes`, `AllowedScopes`, `AutoProvisionInChildTenants` | `TenantOwned` | An update must not re-enable a disabled client or widen narrowed access. `System/Enabled` is shared, hence an override, not a definition change |
| `Client` (assignment override) | `Secrets` | `Secret` | Credential hashes: kept on a re-apply, left out of an `ExportRt` |
| `ApiResource` (assignment override) | `Secrets` (`ApiSecrets`) | `Secret` | Introspection secret hashes, same decision as `Client.Secrets`. The Identity.Bootstrap seed writes the attribute (empty) on both seeded API resources, so it was seed-owned in effect (System.Identity 2.24.0) |
| `Resource` (inherited by `ApiResource`, `ApiScope`, `IdentityResource`) | `System/Enabled` | `TenantOwned` | Same as the client switch |

A fresh tenant still gets the seed values. **Consequence for blueprint authors:** a seed initialises these values on a new entity but can
no longer change them on an existing one (not even tighten a policy or a client) — ship a CK migration step or a documented manual step.
`ClientMirrorProvisioningService` writes mirrors with insert/replace, not `ImportRt`, so mirroring is unaffected. Regression tests:
`BlueprintOwnershipIntegrationTests` (real MongoDB; compiled ownership, shipped policy seed, Enforce over an AuditOnly seed, client,
secrets, resources).

## Credential material of a user is `Secret`: never exported, kept on a re-apply (System.Identity 2.27.0)

Audit finding H3: `User.PasswordHash`, `User.SecurityStamp` and `User.UserTokens` (the `UserToken` record holds the TOTP key and the
recovery codes in `Value`) were `SeedOwned`, so an `ExportRt` (export as template, tenant clone) carried them. They are now
`ownership: Secret` (definition level, `User` is their only assignment) and so is the `UserToken.Value` record member
(assignment override). The engine skips `Secret` in `RtEntityToTcDtoConverter` (shared by `ExportRtModelByQueryCommand` and
`ExportRtModelByDeepGraphCommand`) and keeps it on an Upsert. SeedOwned -> Secret is an ownership change: `octo-ckc ValidateVersion`
rates it **Minor**, ids, types and defaults are unchanged, no migration entry, still ckLanguage 1 (the access modifiers followed with 2.28.0, below).
**Consequence (only up to 2.27.0):** a tenant cloned with ExportRt/ImportRt under 2.27.0 carried its users without password and 2FA
material; they reset the password in the target tenant. **Since 2.28.0 `ImportRt` refuses users altogether** — there is no user
export/import any more; the supported ways are listed in `octo-documentation/src/octo-mesh-documentation/docs/technologyGuide/identityService/users-and-roles.md`
§ *Moving Users to Another Tenant* (`#moving-users-to-another-tenant`): repository dump/restore, creating the users again, a
cross-tenant user mapping, external sign-in with self-registration. No blueprint seeds `System.Identity/User` (`BootstrapBlueprintSeed_DoesNotSeedUsers` guards it). A repository
dump is unaffected. Tests: `CredentialMaterialExportIntegrationTests` (real MongoDB; compiled ownership, converter output of a user
with hash/stamp/tokens, Upsert of a seed-shaped user keeps all three).

## Identity method declarations (System.Identity 2.29.0)

`User`, `Group`, `Client` and `DataPermission` declare their identity operations as CK methods (declarations only; the handlers and the
method host follow with the handler stories, the typed GraphQL mutations with F3.7). Until a handler is registered the gateway
answers `METHOD_HANDLER_NOT_AVAILABLE`; the REST API is unchanged. **Release the identity service with this model only when the handler
stories are merged.**

| Type | Methods (`-1`) | Roles |
|------|----------------|-------|
| `User` | `ChangePassword` (instance, `allowSelf`, no role), `ResetPassword`, `SetRoles`, `AddRole`, `RemoveRole`, `Merge` (own handler), static `CreateUser` (own handler); `DisableTwoFactor` since 2.30.0 | `UserManagement` |
| `Group` | `AddMember`, `RemoveMember` (`memberKind` enum `GroupMemberKind` = `User`/`Client`, `memberId`), `SetRoles` | `UserManagement` |
| `Client` | `AddSecret` (result `sensitive`: the generated secret, shown once), `RemoveSecret` (by `secretValue`, REST parity) | `TenantManagement`, `UserManagement` |
| `DataPermission` | `GrantToRole`, `RevokeFromRole` | `UserManagement` |

Rules behind the shape (do not change them without reading this):
- **Roles = REST parity** (`IdentityApiAuthorizationPolicies`: `UserAdministrationRoles`, `TenantAdministrationRoles`). Every method declares
  `authorization.dataAccess: Write` explicitly (the effective default, so no SemVer change; it raises the model's `minEngineVersion`).
- **`sensitive` on every password or secret parameter** (`currentPassword`, `newPassword`, `password`, `secretValue`) and on the `AddSecret`
  result; such a method can never have a pipeline handler (compiler messages 132/134). Pinned by `IdentityMethodDeclarationsIntegrationTests`.
- **`Create` is a reserved method name** (compiler error 102: `Create`, `Update`, `Delete` belong to the generic mutations) - the static user
  method is `CreateUser-1`.
- **`replacesGenericCreate` only on `User.CreateUser-1` (3.0.0).** Group, Client and DataPermission are seeded by
  `System.Identity.Bootstrap` (the flag would make the engine refuse every new tenant), so they do not carry it. On `User` the flag is a
  **MAJOR** change of the model (row M16 of `octo-construction-kit-engine/docs/ck-semver-rules.md`: a new method with the flag on an
  existing type, decision 2026-10-19) and shipped with System.Identity 3.0.0; until 2.30.0 the engine stood in for it with a runtime rule,
 which was removed. No blueprint seeds a User.
- **No `LAST_ADMIN_PROTECTED`**: the REST API has no last-admin rule (refuses it with `METHOD_FORBIDDEN` / `last-administrator`). `User.DisableTwoFactor-1` followed in 2.30.0 (section below).
- `compatibility.acknowledge` of 2.28.0 is gone (an acknowledgement is valid for one release, OCTO-CK204). `octo-ckc ValidateVersion`
  against the published 2.28.0: **MINOR** (15 additions, no Major row).
- Tests: `IdentityMethodDeclarationsIntegrationTests` (compiled model from the CK cache of a real tenant: method set, roles, sensitive
  parameters and result, write access, no replacesGenericCreate). Docs: `octo-documentation/src/octo-mesh-documentation/docs/technologyGuide/identityService/methods.md` (en + de).

## Access modifiers on `RtUser`, first ckLanguage 2 release (System.Identity 2.28.0)

Closes accepted risk R13 (password hashes and security fields readable through generic GraphQL). `ckModel.yaml` is `ckLanguage: 2`; the
`User` assignments carry `access`:

| Access | Attributes |
|--------|------------|
| `Hidden` | `PasswordHash`, `SecurityStamp`, `UserTokens` (never in GraphQL output or input, never in an ExportRt; an import refuses them) |
| `MethodOnly` | `UserName`, `Email` (readable, changed only by a type method) |
| `ReadOnly` | `AccessFailedCount`, `LockoutEnd` (readable; importable; written by the identity service) |

`ConcurrencyStamp` does not exist in this model. All seven attribute definitions are `securitySensitive: true`, so the tightening is **Minor +
acknowledge** (row T7a of `octo-construction-kit-engine/docs/ck-semver-rules.md`: the one release that moves a classic model to
ckLanguage 2, once per model; entries in `compatibility.acknowledge`). The next release follows the normal rule (T7) again: loosening is Minor,
tightening another attribute is Major. Every existing type and record declares `derivable: Any` (the ckLanguage 2 default is `Model`; the flip
would be a Major of its own) - **declare it on every new type/record that should stay derivable elsewhere**.

**Identity's own writes are unaffected**: the access modifiers guard the generic GraphQL path and the *import-like* paths (ImportRt, blueprint
seed/update, migration Add/Update/Transform: `OCTO-CK139` for Hidden/MethodOnly). `OctoUserStore`, the cross-tenant provisioning and the
password/2FA flows write through `ITenantRepository` (`InsertOneRtEntityAsync`, `ReplaceOneRtEntityByIdAsync`), which is not guarded. No
identity seed, blueprint or migration writes these attributes (`BootstrapBlueprintSeed_DoesNotSeedUsers`). Code that must set one of them from
an import (a test seed, a tool) creates the user through the repository instead. Tests: `CredentialMaterialExportIntegrationTests` (compiled
access values, `OCTO-CK139` refusal per attribute, ReadOnly import still possible, repository writes of all seven attributes still work).

## Blueprint-owned opt-in: `DataPolicy.ProtectBlueprintLocked` (System.Identity 2.24.0)

`ProtectBlueprintLocked` (optional Boolean, default `false`) is the opt-in of the engine's blueprint-lock write guard
(`DataPermissionWriteGuard` in `octo-construction-kit-engine`, message number 6384, `octo-construction-kit-engine/docs/blueprints.md`). It is a
**restriction, not a grant**: for the policy's target CK types (derived types inherit) a non-system caller can no longer update or delete an
entity whose stored `RtBlueprintLocked` is `true`, nor set or change `RtBlueprintLocked`, `RtBlueprintSource` and `RtBlueprintAppliedAt`. The policy's own
`PolicyEnforcementMode` decides between refusal (`Enforce`) and audit only (`AuditOnly`).

- **Ownership: `SeedOwned`** (blueprint-owned) - the opposite of `PolicyEnforcementMode` / `PolicyScope`. The blueprint author decides which
  types are protected; every blueprint update or forced re-apply puts the product's value back, so a user with write access to `DataPolicy`
  cannot switch the protection off for good, and a later blueprint version can tighten or loosen it. A policy without the attribute reads as
  `false`. A seed that merely *omits* it does not switch a stored `true` off (the import's blanking guard keeps the value): ship an explicit
  `false` to take a protection back.
- **Default `false`**; an engine or tenant on an older System.Identity reads the attribute as `false`: existing policies and tenants are
  unaffected. The shipped `System.Identity.Bootstrap` policies do not opt in.
- **Blueprint authors:** ship one `DataPolicy` per opted-in type in a policy group of its own (never on shared master-data policies), with
  `ProtectBlueprintLocked: true`, the actions the roles need and a `PolicyPermission` granted to those roles - a policy with the flag still
  counts as a normal policy for the grant logic (only the listed roles get access). Raise the blueprint's `ckModelDependencies` floor to
  `System.Identity-[2.24.0,3.0)` (otherwise an older Identity silently drops the attribute). The policy table is cached per tenant for 60 s.
- Regression tests: `BlueprintLockProtectionIntegrationTests` (real MongoDB: compiled ownership, fresh install, update re-applies, missing
  attribute = false, bootstrap policies do not opt in, and an end-to-end check that a policy with the flag makes the engine guard refuse a user
  write on a locked entity while an unlocked one and the system stay writable).
- CK dependents: no CK model depends on `System.Identity`; blueprints pin it by ranges (`[2.11,3.0)` up to `[2.14.0,3.0)`), which 2.24.0 satisfied, so
  no dependent needed a rebuild. Only a blueprint that uses the flag needs the raised floor. **Since 3.0.0 every `[2.x,3.0)` range is
  unsatisfied** (a range stays inside one major): each dependent blueprint needs a new version with `System.Identity-[3.0.0,4.0)`.

## Every attribute declares its ownership; the build enforces it

`Persistence.IdentityCkModel.csproj` sets `OctoEnforceRuntimeStateMarkers=true`: the `CkLintRuntimeStateMarkers` task of
`Meshmakers.Octo.ConstructionKit.MsBuildTasks` fails the build with `OCTO-CK001` when an attribute in
`ConstructionKit/attributes/*.yaml` declares neither `ownership` nor the deprecated `isRuntimeState` (`OCTO-CK003` for
both, `OCTO-CK004` for an unknown value). The ownership rule made the existing behaviour explicit: 151 attributes got
`ownership: SeedOwned` (a restatement - the same resolved ownership, so `octo-ckc ValidateVersion` reports "no bump
required" and System.Identity stayed 2.24.0 at the time); the `TenantOwned` / `Secret` decisions of the table in "Tenant-owned attributes" above
and the four `isRuntimeState: true` URI lists are unchanged. Assignment overrides on types (`Client`, `Resource`,
`ApiResource`) are not linted; they still win over the definition. **Review question for every new attribute:** could an
operator or user type this value in the product? Yes → `TenantOwned` (or `Secret` for a credential); a service writes it
→ `RuntimeState`; the product ships and corrects it → `SeedOwned`.

## System.Identity 2.x -> 3.x needs migration entries

The CK engine refuses a schema-only bridge across a major (`CkMigrationMajorVersionGuard`) as soon as the target model ships
a `migration-meta.yaml`, which System.Identity does. System.Identity 3.0.0 shipped without an entry from 2.x: every tenant upgrade failed with
"No migration path found from System.Identity-2.30.0 to System.Identity-3.0.0" and the identity service stopped (test-2 outage). 3.0.1 adds
one entry per 2.x minor from 2.9.0 to 2.30.0, all pointing at the empty script `2.x-to-3.0.1.yaml` (`steps: []`; nothing is migrated - the
3.0.0 change is access modifiers only); tenants below 2.9.0 take the 2.8.0 -> 2.9.0 data migration first. **Whoever publishes another 2.x
on a release line must extend the list.** Test: `SystemIdentityMajorUpgradeIntegrationTests` (the real published 2.30.0 imported into a tenant
and upgraded through `SetupAsync`; the path finder for every 2.x minor from 2.0.0). The earlier asset-repo `IdentityMajorUpgradeFlowTests`
missed the outage because its embedded 3.0.0 snapshot carries no migration-meta (no-migrations bridge).

## Identity-owned User fields are refused on the generic paths

Generic writes of the identity-owned User fields are refused by the model since System.Identity 3.0.0: `NormalizedUserName`,
`NormalizedEmail`, `EmailConfirmed`, `PhoneNumberConfirmed`, `TwoFactorEnabled`, `LockoutEnabled`, `LockoutEnd`, `AccessFailedCount`,
`ResetPasswordOnLogin`, `Claims` (`UserClaims`), `UserLogins` and `PreferredChannelBindingId` are `access: MethodOnly` in `ck-user.yaml`
(with `UserName` and `Email` from 2.28.0), and their definitions are `securitySensitive: true`. The generic access guards enforce it for
every caller: asset-repo GraphQL (`ATTRIBUTE_NOT_WRITABLE`), `ImportRt` and blueprint seeds (OCTO-CK139), the mesh-adapter write nodes. The
engine keeps only the **associations** in a list (`IdentityOwnedWrites.AssociationRoleIds`: `AssignedRole`, `GroupMember`, `ChildGroup`,
`MayActAs`, `GrantsPermission`; asset-repo GraphQL, mesh-adapter write nodes, caller `ImportRt`, message 140) because the CK access model
cannot restrict association writes. In 2.x the attributes were a runtime list, because tightening attributes that were never
`securitySensitive` is a Major (row T7). **Nothing in this service is affected**: every identity write (stores, REST, methods,
provisioning, migrations, the bus consumer's `MayActAs`/`AssignedRole` edges, the preferred-channel self-service) goes through
`ITenantRepository`, which the guards do not touch, and the Bootstrap seed (TenantOwners `AssignedRole` edges) is a system import.
