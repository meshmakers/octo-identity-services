# Pilot runbook: SECRET phase 3 for identity on test-2 (AB#5528 / AB#5540 / AB#5544)

Identity is the phase-3 pilot (decision D3): the external identity providers' `ClientSecret` (Google,
Microsoft, Facebook, Azure Entra ID) becomes a CK `Secret` attribute (`System.Identity-2.25.0`), and
the tenant role `SecretManagement` is seeded (`System.Identity.Bootstrap-1.7.0`). Both ship inside
the identity image: the service imports its embedded CK model and applies the embedded blueprint
per tenant at startup, so there is no catalog step. Behaviour details: `authentication.md`
§ Client Secrets of External Providers, `persistence.md` (SecretManagement grant).

Order: **test-2 only** for the pilot. Other environments follow the release plan.

## What changes at rollout

| Step at identity startup, per tenant | Effect |
|---|---|
| CK import `System.Identity-2.25.0` | `ClientSecret` String → Secret (Minor, no data migration). Stored strings stay as they are and are read as **legacy clear text** (counted, warned once per type without the value). |
| Blueprint `System.Identity.Bootstrap-1.7.0` | Creates role `SecretManagement` (rtId `660…60`); not assigned to `TenantOwners` (human administrators only). |
| `SecretManagementAdminGrant` (once, marker in tenant config) | Grants `SecretManagement` directly to local users holding **both** `AdminPanelManagement` and `TenantManagement` (also via groups); never to groups, clients or `xt_` shadow users. Additive only; failures are logged and do not fail tenant setup. |
| REST API identity providers | Responses never contain the secret (`clientSecretIsSet`, `clientSecretKeyMissing`, `clientSecretSetAt` instead). A new secret is encrypted on write (`enc:v2:k1:…`); saving a new secret without key ring answers **503** `SecretEncryptionNotConfigured`. |

Legacy clear text is converted to `enc:v2` only by (a) the bot encrypt sweep, or (b) **any** write of
that provider while a key ring is configured (also an edit that leaves the secret unchanged). Until
then the value stays a plain string in MongoDB.

## 1. Preconditions

- **Key ring present on identity.** test-2 derives the ring from `secrets.communicationInstanceSecretKey`
  (chart `octo-mesh`, `OCTO_SECRETENCRYPTION__KEYS__k1` / `__ACTIVEKEYID` / `__LEGACYV1KEY` in the shared
  system-env block, so identity gets the same ring as bot). Read-only check:
  `octo-cli -c SecretStatus -j` (context `test-2_*`) → `KeyRingConfigured: true`, `ActiveKeyId: k1`,
  `StrictMode: false` (state 2026-10-08: met).
- **Strict mode stays off** (`SecretEncryption:StrictMode=false`) until phase 5 — with strict mode on,
  legacy clear-text provider secrets are rejected and those providers are skipped.
- AB#5859 role enforcement rollout (`rollout-identity-rest-role-enforcement.md`) is understood: the
  identity-provider endpoints need `TenantManagement` or `UserManagement`.
- Backup: tenant dumps of the tenants with external providers (or a MongoDB snapshot) taken before the
  rollout — needed only for the rollback path below.
- Inventory (write down, without values): per tenant the external providers and whether they are used
  for sign-in (Studio → Identity providers, or `octo-cli -c GetIdentityProviders`). Note: **before** the
  rollout this GET still returns the clear-text secret — do not paste its output anywhere.

## 2. Rollout

1. Deploy the identity image built from main (containing this change) to test-2 via the usual
   pipeline. No catalog, blueprint or CK command is needed.
2. Watch the identity startup log (Loki / Dash0, namespace `octo`, container identity):
   - per tenant: CK import `System.Identity-2.25.0` and blueprint `System.Identity.Bootstrap-1.7.0`
     applied, no `ImportCkModelFailed`;
   - `SecretManagement granted to existing administrators of tenant ...` (once per tenant; a warning
     `SecretManagement role not found` means the blueprint did not apply — retried next setup);
   - expected warning (once per type): `Secret attribute ClientSecret of System.Identity/... is still
     stored as clear text; run the secret encrypt sweep`;
   - **not expected**: `Skipped auth scheme '...'` (would mean a provider cannot be read).

## 3. Verification

- Sign in to each tenant with an external provider (at least one Google/Microsoft/Entra tenant) and
  once with a local account; Studio loads.
- `octo-cli -c GetIdentityProviders` (octo-cli from wave 1 or later): no `clientSecret` value; `clientSecretIsSet: true`
  for configured OAuth/OIDC providers, `clientSecretKeyMissing: false`.
- `octo-cli -c GetRoles` shows `SecretManagement`; `GetGroup` of `TenantOwners` does **not** list it; a local tenant
  administrator (AdminPanelManagement + TenantManagement) has it as a direct role after a re-login, a pipeline service
  account and a provisioned parent-tenant administrator (`xt_…`) do not.
- `octo-cli -c LibraryStatus --installed-only`: `System.Identity` 2.25.0 Available in every tenant.
- Optional, after the observation window (decide with the PO, it removes the cheap rollback): run the
  encrypt sweep for the pilot tenants (bot, needs `SecretManagement`), then `SecretStatus` shows
  `Plaintext: 0` and `EncV2ByKeyId: { k1: n }`; sign in again with the external providers.

## 4. Without a key ring (other clusters, or ring lost)

Login keeps working: legacy clear-text secrets are readable without keys, edits that leave the secret
unchanged keep the stored string, only saving a **new** secret answers 503. An `enc:v2` value whose key
id is unknown (restore from another environment, ring removed) is kept and reads as "not set": that one
provider is skipped at scheme registration (error log with key id, never the value); local login and
the tenant's other providers keep working. Fix: restore the key into the ring, or re-enter the secret.

## 5. Rollback

- **Preferred: roll forward** (fix and redeploy) — the change is additive and login-safe.
- Rolling back to the previous identity image is cheap **only while no provider secret has been
  encrypted** (no encrypt sweep, no provider edits since the rollout): the values are still plain
  strings the old code reads. The tenants keep CK `System.Identity` 2.25.0 and blueprint 1.7.0
  installed; the old image embeds 2.22.0 / 1.3.1 — the downgrade behaviour of the startup import has
  **not been verified**; check `LibraryStatus` and sign-in right after a rollback.
- Once secrets are encrypted, the old image cannot read them (sub-document instead of string): affected
  providers must be re-entered after the rollback, or the tenant restored from the pre-rollout dump.
- The `SecretManagement` role and its grants are harmless for the old image (unused role); no cleanup
  needed.
