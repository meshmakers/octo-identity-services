# Rollout: Data Protection key ring encrypted at rest (AB#5530)

The ASP.NET Data Protection key ring of identity services (cookies, antiforgery tokens, cross-tenant tokens
`auth/cross-tenant-token`, everything protected with `IDataProtector`) is stored in the system MongoDB database
(`RtDataProtectionKey`). Before AB#5530 the key material was stored as plain XML, so a database dump contained
usable keys. Now the secret part of each key is wrapped with the **platform key ring** `SecretEncryption` — the
same AES-256 key ring as `Secret` attributes (AB#5528/AB#5536). No certificate and no new secret are needed.

Key ids, creation/activation/expiration dates and key material stay the same: **nobody is logged out** by the
encryption or by the migration of existing keys. Details: `persistence.md` § Encryption at Rest.

## Behaviour by flag

`Identity:DataProtection:EncryptExistingKeys` — env `OCTO_IDENTITY__DATAPROTECTION__ENCRYPTEXISTINGKEYS`,
helm value proposal `services.identity.dataProtection.encryptExistingKeys` (octo-helm-core, Heimdall's lane).

| | `false` (default, release 1) | `true` (step 2, per cluster) |
|---|---|---|
| Stored plain keys | read unchanged | rewritten encrypted at startup (in place, idempotent, every pod) |
| Stored encrypted keys | read | read |
| New keys (every ~90 days, `RevokeAllKeys`) | **plain** while the store holds keys; encrypted in an empty store (fresh install) | encrypted |
| Legacy file seed (`DataProtectionKeysPath`) | imported plain | imported encrypted |
| No `SecretEncryption` key configured | starts, warning: keys stored unencrypted | **refuses to start** |
| A stored key wrapped with a key id that is not configured | **refuses to start** (names key and key id) | **refuses to start** |
| Keys wrapped with a non-active key id (rotation) | re-wrapped with the active key at startup | re-wrapped with the active key at startup |

Startup log line (Dash0, service identity):
`Data Protection key ring checked: N keys, E encrypted now, R re-wrapped with platform key id 'k1', P still unencrypted`.
No key material is logged.

## Why two steps

ASP.NET reads plain and encrypted keys, but an image **without** the decryptor cannot read an encrypted key: it
ignores the key, creates a new one and every protected payload of the old key (all sessions, cookies, cross-tenant
tokens) becomes invalid. Therefore:

1. **Release 1** ships reader and writer with the flag `false` on every cluster. During the rolling update old
   and new pods run side by side; new keys stay plain, so old pods keep working. Clusters keep their plain keys.
2. **Step 2**: once every identity pod of a cluster runs release 1 or later, and nobody plans a rollback to an
   image older than release 1, set the flag `true` for that cluster. Order: **test-2 → prod-2 → prod-1**
   (staging-1 together with or before prod-2). Each cluster needs the developer's go.

## Preconditions per cluster

- Identity carries the key ring: `OCTO_SECRETENCRYPTION__KEYS__k1` and `OCTO_SECRETENCRYPTION__ACTIVEKEYID` (shared
  system-env block of chart `octo-mesh` since SECRET phase 3). Read-only check: `octo-cli -c SecretStatus -j`
  → `KeyRingConfigured: true`, `ActiveKeyId: k1`.
- All identity pods run release 1 or later (image tag).

## Step 2 on a cluster

1. Set `OCTO_IDENTITY__DATAPROTECTION__ENCRYPTEXISTINGKEYS=true` for identity (helm value, then the regular deploy).
2. Watch the startup log of the first new pod: `E encrypted now` equals the number of plain keys, `P still
   unencrypted` is `0`. A second pod reports `0 encrypted now, 0 re-wrapped, 0 still unencrypted`.
3. Verification (test-2 before prod): sign in to Refinery Studio with an existing session (no re-login), run a
   cross-tenant login, and confirm that the stored keys contain no plain key material: either from the startup log
   (`P still unencrypted = 0`) or with a read-only query by Odysseus on the system database: no
   `RtDataProtectionKey` document whose `XmlData` contains `masterKey`. The test
   `RawDatabaseDump_ContainsNoUsableKeyMaterial` proves the same on a local database.
4. Fresh installations (empty key store) need no step: their first key is already encrypted.

## Platform key rotation

1. Add the new key and make it active: `KEYS__k2=…`, `ACTIVEKEYID=k2`, **keep `KEYS__k1`**.
2. Restart identity: the startup step re-wraps every Data Protection key with `k2` (`R re-wrapped`). This is
   identity's own step — the octo-cli `ReprotectSecrets` sweep covers `Secret` attributes, not the Data Protection
   key ring.
3. Remove `k1` only after every identity pod logged the re-wrap **and** every other consumer of `k1` (secret sweep,
   encrypted dumps) is done with it. Removing `k1` too early makes identity refuse to start (it names the keys
   wrapped with `k1`); add `k1` back to recover — nothing is lost.

## Rollback

| Situation | Rollback | Effect |
|---|---|---|
| Release 1 deployed, flag still `false`, cluster had keys before | previous image | none: all keys are still plain |
| Flag `true` was set | set flag `false` | **does not decrypt** — keys stay encrypted; release 1+ keeps reading them. Only stops encrypting new keys. |
| Flag `true` was set (or fresh install on release 1) and the image is rolled back to one **without** the decryptor | previous image | **all users are logged out**, protected payloads (cookies, cross-tenant tokens in flight) become invalid; the old image creates a new plain key and continues. No outage, no data loss. |

Guard: never roll identity back past release 1 once a cluster has encrypted keys — release notes of release 1
carry this warning, and step 2 is only done when release 1 is the oldest image a cluster may roll back to.
If a rollback is unavoidable: accept the one-time re-login, or roll forward again (the encrypted keys are still in
the database; after the roll-forward they are readable again, payloads protected with the temporary plain key
are lost).

## Missing key ring

- Flag `true` without `SecretEncryption` key: identity does not start (`DataProtectionKeyRingException`, message names
  `OCTO_SECRETENCRYPTION__KEYS__<id>`). Configure the key ring or set the flag `false`.
- Encrypted keys and the key id missing from the ring (e.g. database restored into another environment): identity does
  not start. Configure the original key id.
