# Identity API Reference

## Overview

The Identity API provides RESTful endpoints for managing identity resources including users, clients, roles, API resources, and identity providers.

**Base Path:** `{tenantId}/v1` (e.g., `octosystem/v1` for the default system tenant, `MyTenant/v1` for a specific tenant)

**API Version:** 1.0

**Authentication:** Bearer Token (OIDC Authorization Header)

All endpoints are tenant-scoped via the `{tenantId}` route parameter. The system tenant ID defaults to `OctoSystem` (normalized to `octosystem` in URLs) and is configurable via `OctoSystemConfiguration.SystemTenantId`. For system-level resources (clients, API resources, scopes, secrets, diagnostics, setup, tools), use the system tenant ID (e.g., `octosystem/v1/clients`).

## Authorization Policies

Every administration endpoint requires **both** an `octo_api` scope and a **tenant role** (AB#5859).
Before AB#5859 the API checked the scope only — which every interactive client requests — so every
signed-in user of a tenant could administer its identity. The role rule matches the GraphQL side
(built-in data policy `IdentityAdministrationPolicy` grants the identity entities to `UserManagement`).

Roles are read from the token's `role` claims (user tokens: the user's effective roles; client-credentials
tokens: the client's effective roles, AB#4183). The check probes the raw `role` claim and
`ClaimTypes.Role`, because the identity's `RoleClaimType` does not match the unmapped JWT claim
(AB#4969 / AB#5539).

| Policy | Scope | Roles (any of) | Applied to |
|--------|-------|----------------|------------|
| `IdentityUserAdministrationReadPolicy` / `…WritePolicy` | read: `octo_api` or `octo_api.read_only`; write: `octo_api` | `UserManagement` | users, roles (writes), groups, external tenant user mappings, e-mail identifier bindings, data permissions |
| `IdentityTenantAdministrationReadPolicy` / `…WritePolicy` | as above | `TenantManagement`, `UserManagement` | clients, client mirrors, API resources, API scopes, reading API secret metadata (list, lookup), identity providers, e-mail domain group rules, admin provisioning |
| `IdentitySecretAdministrationPolicy` (AB#5861) | `octo_api` | `SecretManagement` (staged, see below) | creating, rotating (`PUT`) and deleting API secrets of clients and API resources; a `clientSecret` in `POST clients` / `PUT clients/{id}` (checked in the action, only when the body carries a secret); issuing a mirror secret `POST clients/{clientId}/mirrors/{childTenantId}/secret` |
| `IdentityDirectoryReadPolicy` | `octo_api` or `octo_api.read_only` | `UserManagement`, `TenantManagement`, `AdminPanelManagement`, `CommunicationManagement` | `GET roles`, `GET roles/GetPaged`, `GET roles/names/{roleName}`, `GET clients/{id}`, `GET clients/{id}/roles`, `GET clients/{id}/actors` (service-account panels, communication controller) |
| `IdentityServiceAdministrationPolicy` | `octo_api` | `TenantManagement`, **system tenant route only** | `POST diagnostics/reconfigureLogLevel` (process-wide) |
| `IdentityUserDirectoryReadPolicy` | `octo_api` or `octo_api.read_only` | — (**token must be issued for the route tenant**, no Warn mode, no exemptions) | `GET users/directory` (id + display name only, for pickers) |
| `IdentityApiReadOnlyPolicy` | `octo_api` or `octo_api.read_only` | — | `GET tools/generatePassword` |

Open to every authenticated caller: `GET diagnostics` (the caller's own claims). `POST setup` is unchanged
(works only while the tenant has no user). Self-service lives outside this API
(`{tenantId}/api/manage/...`, cookie or bearer, current user only).

**Admin provisioning** (`{tenantId}/v1/adminProvisioning/{targetTenantId}`) reaches the target tenant
through the system context. Since AB#5859 the target must be the caller's own tenant (`tenant_id` of the
token) or one of its descendants in the tenant registry; a caller of the system tenant may address every
tenant (`AdminProvisioningTargetScopeFilter`).
A descendant counts only when it is registered as such (AB#6759, `TenantSubtreeWalker`): a row in a parent's own registry is followed only when the system registry holds the same tenant id with the same database and names that parent (or no parent, for legacy rows). A stale row left by a delete — or one whose id was later reused by a tenant below another parent — grants nothing and is not walked into. A tenant that lost its system registry row (AB#6941) therefore drops out of its ancestors' scopes until `ReconcileTenantRegistry` restores the row (fail closed).
Every route with `{targetTenantId}` must carry that filter; `AdminProvisioningRouteCoverageTests` enforces it by reflection and `AdminProvisioningPipelineTests` pins the 201/403 matrix (AB#4824).
The client mirror actions that name a child tenant (`provisionInTenant?childTenantId=`, `mirrors/{childTenantId}/secret`, `DELETE mirrors/{childTenantId}`) follow the same rule since AB#6758: a child outside the caller's subtree answers `403` with the same response for sibling, unrelated, system and unknown tenants.

**Transition switch:** `IdentityApiAuthorization:RoleEnforcement` (`OCTO_IDENTITYAPIAUTHORIZATION__ROLEENFORCEMENT`)
= `Enforce` (default) or `Warn`. `Warn` lets a caller without the role (or an admin-provisioning target
outside its subtree) through and logs `This would be denied with RoleEnforcement=Enforce (AB#5859)`. The
scope requirement and the system-tenant-only rule are enforced in both modes.

**SecretManagement switch (AB#5861):** `IdentityApiAuthorization:SecretManagementRoleEnforcement`
(`OCTO_IDENTITYAPIAUTHORIZATION__SECRETMANAGEMENTROLEENFORCEMENT`) = `Warn` (**default**) or `Enforce`. It stages
`IdentitySecretAdministrationPolicy` and the same rule in the client secret methods (`Client.AddSecret-1`,
`Client.RemoveSecret-1`). `Warn`: a caller without `SecretManagement` who holds `TenantManagement` or
`UserManagement` (the rule before AB#5861) is let through and logged
`This would be denied with SecretManagementRoleEnforcement=Enforce (AB#5861)`; a caller without any of these roles is
denied — `Warn` never allows less than before. `Enforce`: only `SecretManagement`. `RoleEnforcement=Warn` stays the
emergency exit and relaxes this policy too. The default is `Warn` because `SecretManagement` was granted only once,
to the local human administrators (AB#5544): cross-tenant administrators, clients and later administrators do not
hold it, and `TenantOwners` does not carry it. Rollout: `docs/rollout-identity-rest-role-enforcement.md` § AB#5861.

**403 reason (AB#5861):** a refused role requirement answers `403` with the body
`{"message": "Access is denied: this operation requires the role 'SecretManagement' in the tenant. ..."}` (AB#5227
shape, `IdentityApiForbiddenReasonResultHandler`), so Studio and octo-cli show which role is missing. Refusals for a
missing scope keep the empty `403`.

The `Policy` column in the endpoint tables below names the **scope level** (ReadOnly / ReadWrite); the
required role follows from the table above.

## Endpoints

### Users (`/{tenantId}/v1/users`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/users` | ReadOnly | Get all users |
| GET | `/users/GetPaged` | ReadOnly | Get paginated users |
| GET | `/users/directory?skip=&take=&search=` | ReadOnly (no role) | Slim user directory for pickers: `userId` + `displayName` ("First Last", else user name) of the tenant's users, sorted by display name; `search` matches the display name only (case-insensitive substring); `take` 1..500, default 100. No e-mail, roles, groups or logins. |
| GET | `/users/{userName}` | ReadOnly | Get user by name, email, or ID |
| GET | `/users/{userName}/roles` | ReadOnly | Get user's roles (direct + group-inherited) |
| GET | `/users/{userName}/directRoles` | ReadOnly | Get user's directly assigned roles only |
| POST | `/users` | ReadWrite | Create new user (with `password`: e-mail confirmation mail; without: invitation to set a password). Same creation as the CK method `User.CreateUser-1` (AB#7777, shared `IUserCreationService`). Users are created only here or through that method: GraphQL create, `ImportRt` and blueprint seeds refuse a new user (`GENERIC_CREATE_REPLACED_BY_METHOD`). An e-mail address another user of the tenant already has (case-insensitive) is refused with `409`, `application/problem+json`, `code: USER_ALREADY_EXISTS`, `field: email` (AB#8064; `PUT /users/{userName}` applies the same rule to a change of the address, AB#8084). A user name another user already has (case-insensitive) is refused the same way with `field: userName` (AB#8083; before: `400`); `PUT /users/{userName}` answers it for a rename |
| POST | `/users/ResetPassword` | ReadWrite | Reset user password; body `{ "userName": "…", "password": "…" }`. The former query form (`?userName=…&password=…`) is refused with `400` and an update hint (AB#8008): a password never travels in a URL |
| POST | `/users/{userName}/revokeSessions` | ReadWrite | Revoke all sessions and tokens of a user (AB#7899) |
| POST | `/users/{userName}/disableTwoFactor` | ReadWrite | Switch off the user's second factor: authenticator key and recovery codes removed, security stamp rotated, refresh tokens revoked; `200 { twoFactorWasEnabled }` (AB#7879, same as the method `User.DisableTwoFactor-1`) |
| POST | `/users/revokeSessions?scope=shadowUsers&dryRun=true` | ReadWrite | Same for all xt_* shadow users of the tenant; dry run by default (AB#7899) |
| PUT | `/users/{userName}` | ReadWrite | Update user. Changing the e-mail address to one another user of the tenant already has (case-insensitive) is refused with `409`, `application/problem+json`, `code: USER_ALREADY_EXISTS`, `field: email` (AB#8084); keeping the current address (also in another casing) or clearing it is not checked |
| PUT | `/users/{userName}/roles` | ReadWrite | Replace user's direct role assignments |
| PUT | `/users/{userName}/roles/{roleName}` | ReadWrite | Add role to user |
| POST | `/users/{userName}/merge` | ReadWrite | Merge source user into target user |
| DELETE | `/users/{userName}` | ReadWrite | Delete user |
| DELETE | `/users/{userName}/roles/{roleName}` | ReadWrite | Remove role from user |

**Role change rules (AB#7914).** The role endpoints above, `DELETE /users/{userName}` and `POST /users/{userName}/merge` (the source user is deleted) run `IRoleChangeGuard`: no
self-grant (`403`, `code: self-grant`), no granting of a built-in role (stored `rtWellKnownName`) the caller does not hold (`403`, `code: role-not-held`, `roleNames`), and no
removal of the last user that effectively holds `UserManagement` (`409`, `code: last-administrator`; direct, via groups, via mappings of `xt_` users; clients do not count). Answers are
`application/problem+json` with the `code` extension and a readable `title`. `PUT /users/{userName}/roles` validates all role ids first (unknown id: `404`, nothing changed) and writes only the
difference. Every refusal is audited as `Identity.RoleChangeRefused`. The same rules apply to the methods `User.SetRoles/AddRole/RemoveRole` (see CLAUDE.md).

**Role change rules for groups, mappings and role definitions (AB#7927).** The same guard judges `PUT /groups/{id}/roles`, `PUT`/`DELETE /groups/{id}/members/users|groups/{id}`,
`PUT /groups/{id}/members/clients/{id}`, `DELETE /groups/{id}` and create/update/delete of external tenant user mappings: `403 self-grant`, `403 role-not-held` (built-in roles the caller does not hold,
also through nested groups), `409 last-administrator` (nobody effectively holds `UserManagement` afterwards). `PUT /roles/{roleName}` with another name and `DELETE /roles/{roleName}` of a built-in
role (stored `rtWellKnownName`) answer `409` with `code: built-in-role`. Same problem+json shape and audit event as above; details in CLAUDE.md.

**Request/Response DTOs:**

```typescript
// RegisterUserDto (POST /users)
{
  "firstName": "string",
  "lastName": "string",
  "email": "string",
  "name": "string",           // Display name
  "password": "string",       // Optional; omit or leave empty to create an invite-style user with no password set
  "resetPasswordOnLogin": true
}

// UserDto (Response)
{
  "userId": "string",
  "firstName": "string",
  "lastName": "string",
  "email": "string",
  "name": "string",
  "resetPasswordOnLogin": true
}

// MergeUsersRequestDto (POST /users/{userName}/merge)
{
  "sourceUserName": "string"  // User whose external logins will be transferred
}
```

**Create User:**

> User creation is atomic: when a password is supplied it is validated against the
> password policy **before** the user record is created (`UserManager.CreateAsync(user, password)`).
> A password that fails the policy returns `400 Bad Request` and persists no user
> (AB#4503 - previously a rejected password left an orphaned account).
>
> The `password` field is optional. When it is omitted or empty the user is created
> without a password (`UserManager.CreateAsync(user)`) as an invite-style account and a
> welcome notification is sent so the user can set their own password; such an account
> cannot be used to log in until a password is set.

**Merge Users:**

Transfers all external logins (e.g., Google, Microsoft) from the source user to the target user, then deletes the source user. This is useful for consolidating duplicate accounts created by external identity providers.

- `{userName}` in the URL is the **target** user (kept after merge)
- `sourceUserName` in the body is the user whose logins are transferred and who is deleted
- Returns 404 if either user does not exist
- Returns 400 if attempting to merge a user into itself
- Returns 409 (`last-administrator`) when the source user is the last user that holds `UserManagement` (AB#7914)
- Before the source user is deleted, every refresh token, authorization and browser session of the source user in this tenant
  is revoked (`IUserSessionRevocationService`, AB#7778)
- Roles, group memberships, claims and cross-tenant mappings of the source user are **not** transferred
- The CK method `User.Merge-1` runs the same code (`IUserMergeService`, see `CLAUDE.md` § `User.Merge`)

### Clients (`/{tenantId}/v1/clients`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/clients` | ReadOnly | Get all clients |
| GET | `/clients/GetPaged` | ReadOnly | Get paginated clients |
| GET | `/clients/{id}` | ReadOnly | Get client by ID |
| POST | `/clients` | ReadWrite | Create new client |
| PUT | `/clients/{id}` | ReadWrite | Update client |
| DELETE | `/clients/{id}` | ReadWrite | Delete client |
| GET | `/clients/{id}/roles` | DirectoryRead | Role ids directly assigned to the client |
| PUT | `/clients/{id}/roles` | ReadWrite | Replace the client's direct roles (body: role ids) |
| PUT | `/clients/{id}/roles/{roleName}` | ReadWrite | Assign one role by name |
| DELETE | `/clients/{id}/roles/{roleName}` | ReadWrite | Remove one role by name |

**Client role rules (AB#7928).** `PUT /clients/{id}/roles` and `PUT /clients/{id}/roles/{roleName}` refuse to give a client a built-in role
(stored `rtWellKnownName`) the caller does not hold: `403`, `application/problem+json`, `code: role-not-held`, `roleNames`. Custom roles are
free, only the added roles are judged (a role the client already holds and any removal pass), and `PUT /clients/{id}/roles` validates every
role id first (unknown or malformed id: `404`, nothing written) and writes only the difference (kept roles are not written again). Every refusal is audited as `Identity.RoleChangeRefused`. Service-internal
client provisioning over the bus (service accounts, client mirroring) is not affected.

**Concurrent updates (AB#8015).** `PUT /clients/{id}`, the overlay URI endpoints and `PATCH .../autoProvisionInChildTenants` change the
client as one version-checked read-modify-write: the DTO is applied to the stored client and written with the version that was read; when
another request changed the client in between, the change is applied again to a fresh read. An update therefore never writes back a secret
that a concurrent secret delete removed. After repeated conflicts the endpoint answers `409` (`application/problem+json`); retry the request.

**Request/Response DTO:**

```typescript
// ClientDto
{
  "isEnabled": true,
  "clientId": "string",       // Unique identifier
  "clientSecret": "string",   // Optional
  "clientName": "string",
  "clientUri": "string",
  "allowedGrantTypes": ["authorization_code", "client_credentials"],
  "redirectUris": ["https://app.example.com/callback"],
  "postLogoutRedirectUris": ["https://app.example.com/logout"],
  "allowedCorsOrigins": ["https://app.example.com"],
  "allowedScopes": ["openid", "profile", "api"],
  "isOfflineAccessEnabled": true
}
```

### Roles (`/{tenantId}/v1/roles`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/roles` | ReadOnly | Get all roles |
| GET | `/roles/GetPaged` | ReadOnly | Get paginated roles |
| GET | `/roles/names/{roleName}` | ReadOnly | Get role by name |
| POST | `/roles` | ReadWrite | Create role |
| PUT | `/roles/{roleName}` | ReadWrite | Update role |
| DELETE | `/roles/{roleName}` | ReadWrite | Delete role |

**Request/Response DTO:**

```typescript
// RoleDto
{
  "id": "string",
  "name": "string"
}
```

### API Resources (`/{tenantId}/v1/apiResources`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiResources` | ReadOnly | Get all API resources |
| GET | `/apiResources/GetPaged` | ReadOnly | Get paginated resources |
| GET | `/apiResources/{name}` | ReadOnly | Get resource by name |
| POST | `/apiResources` | ReadWrite | Create resource |
| PUT | `/apiResources/{name}` | ReadWrite | Update resource |
| DELETE | `/apiResources/{name}` | ReadWrite | Delete resource |

`PUT /apiResources/{name}` is a version-checked read-modify-write like the client update (AB#8015): the stored secrets are never replaced by
an older copy; `409` after repeated conflicts.

**Request/Response DTO:**

```typescript
// ApiResourceDto
{
  "isEnabled": true,
  "name": "string",
  "displayName": "string",
  "description": "string",
  "showInDiscoveryDocument": true,
  "userClaims": ["sub", "name"],
  "requireResourceIndicator": false,
  "scopes": ["api.read", "api.write"],
  "allowedAccessTokenSigningAlgorithms": ["RS256"]
}
```

### API Scopes (`/{tenantId}/v1/apiScopes`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiScopes` | ReadOnly | Get all scopes |
| GET | `/apiScopes/GetPaged` | ReadOnly | Get paginated scopes |
| GET | `/apiScopes/{name}` | ReadOnly | Get scope by name |
| POST | `/apiScopes` | ReadWrite | Create scope |
| PUT | `/apiScopes/{name}` | ReadWrite | Update scope |
| DELETE | `/apiScopes/{name}` | ReadWrite | Delete scope |

**Request/Response DTO:**

```typescript
// ApiScopeDto
{
  "isEnabled": true,
  "name": "string",
  "displayName": "string",
  "description": "string",
  "showInDiscoveryDocument": true,
  "userClaims": ["sub"],
  "isRequired": false,
  "isEmphasize": false
}
```

### API Secrets (`/{tenantId}/v1/apiSecrets`)

#### Client Secrets

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiSecrets/client/{clientId}` | ReadOnly | Get client's secrets |
| POST | `/apiSecrets/client/{clientId}/lookup` | ReadOnly | Get specific secret; body `{ "valueEncrypted": "<stored hash>" }` (AB#8008) |
| POST | `/apiSecrets/client/{clientId}` | ReadWrite + `SecretManagement` | Create client secret |
| PUT | `/apiSecrets/client/{clientId}` | ReadWrite + `SecretManagement` | Update client secret (stored hash in the body) |
| POST | `/apiSecrets/client/{clientId}/delete` | ReadWrite + `SecretManagement` | Delete secret; body `{ "valueEncrypted": "<stored hash>" }` (AB#8008) |
| GET | `/apiSecrets/client/{clientId}/{secretValue}` | ReadOnly | **Deprecated** (stored hash in the path), kept for one release; use `…/lookup` |
| DELETE | `/apiSecrets/client/{clientId}/{secretValue}` | ReadWrite + `SecretManagement` | **Deprecated** (stored hash in the path), kept for one release; use `…/delete` |

The same operations exist as CK methods on the client entity (AB#7780): `System.Identity/Client.AddSecret-1` (result = the generated
secret, shown once, `sensitive`) and `Client.RemoveSecret-1` (`secretValue` = stored value or clear text). They are hosted only with
`Methods:Identity:EnablePasswordMethods=true`; rules and differences to REST: `CLAUDE.md`, section "Client secret methods".

#### API Resource Secrets

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/apiSecrets/apiResource/{name}` | ReadOnly | Get resource's secrets |
| POST | `/apiSecrets/apiResource/{name}/lookup` | ReadOnly | Get specific secret; body `{ "valueEncrypted": "<stored hash>" }` (AB#8008) |
| POST | `/apiSecrets/apiResource/{name}` | ReadWrite + `SecretManagement` | Create resource secret |
| PUT | `/apiSecrets/apiResource/{name}` | ReadWrite + `SecretManagement` | Update resource secret (stored hash in the body) |
| POST | `/apiSecrets/apiResource/{name}/delete` | ReadWrite + `SecretManagement` | Delete secret; body `{ "valueEncrypted": "<stored hash>" }` (AB#8008) |
| GET | `/apiSecrets/apiResource/{name}/{secretValue}` | ReadOnly | **Deprecated** (stored hash in the path), kept for one release; use `…/lookup` |
| DELETE | `/apiSecrets/apiResource/{name}/{secretValue}` | ReadWrite + `SecretManagement` | **Deprecated** (stored hash in the path), kept for one release; use `…/delete` |

**Create (POST)** — the server generates the secret; the request carries only the metadata (AB#6258):

```typescript
// request body (CreateApiSecretRequestDto)
{
  "expirationDate": "2025-12-31T00:00:00Z",   // optional
  "description": "string"                      // optional
}
```

Any other field in the body (for example the `valueEncrypted` / `valueClearText` the shipped octo-cli
serialises from `ApiSecretDto`) is ignored: it is never stored and never echoed.

**Response / list / update (`ApiSecretDto`):**

```typescript
{
  "valueEncrypted": "string",   // Base64(SHA-256) of the secret; identifies the secret for PUT/DELETE
  "valueClearText": "string",   // Only in the creation response
  "expirationDate": "2025-12-31T00:00:00Z",
  "description": "string"
}
```

**Note:** Secrets are 256 bit from the CSPRNG (32 random bytes, URL-safe Base64 without padding, 43
characters) and stored as Base64(SHA-256); stored SHA-256 and SHA-512 hashes keep validating. The clear text
is returned only once, in the creation response; neither it nor a hash is logged. PUT requires
`valueEncrypted` of an existing secret (400 when missing, 404 when no such secret exists).

**Delete (`POST …/delete`)** — the body names the stored hash: `{ "valueEncrypted": "<stored hash>" }` (what
octo-cli `DeleteApiSecretClient` / `DeleteApiSecretApiResource` send since AB#8008). A POST sub-resource and not a
DELETE with a body, because a DELETE body has no defined semantics (RFC 9110) and proxies and HTTP client
libraries may drop it; the API uses POST sub-resources for actions already (`users/{userName}/revokeSessions`).
The stored hash is a credential-equivalent value: in a URL path it would reach request logs, traces (`url.path`)
and proxy access logs. `POST …/lookup` reads one secret the same way. The deprecated path variants
(`DELETE` / `GET …/{secretValue}`, `{secretValue}` = the stored hash, Base64-encoded again) still work for one
release for older octo-cli/SDK versions; each call writes a WARN `Deprecated API secret request …` naming the
operation and the client / API resource, never the value, and the value is masked (`***`) in the request log
and in the trace attribute `url.path`. The call removes every
stored secret with that hash and answers 200; a deleted client secret no longer authenticates at the token
endpoint (the cache event `CorsClientsUpdate` is published as for every secret write). It answers 404 when
the client / API resource or the secret does not exist. No 404 answer echoes the secret value. Every secret write (POST, PUT,
DELETE) is version-checked against concurrent secret writes of the same client / API resource; after repeated concurrent changes
it answers `409` (`application/problem+json`), retry the call. Before
AB#7989 the endpoint answered 200 for a client or API resource read from the database but removed nothing.
API resource secrets authenticate nothing since the OpenIddict migration (introspection authenticates
clients); the endpoints only manage the stored data.

### Identity Providers (`/{tenantId}/v1/identityProviders`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/identityProviders` | ReadOnly | Get all providers |
| GET | `/identityProviders/{rtId}` | ReadOnly | Get provider by ID |
| POST | `/identityProviders` | ReadWrite | Add new provider |
| PUT | `/identityProviders/{rtId}` | ReadWrite | Replace provider |
| DELETE | `/identityProviders/{rtId}` | ReadWrite | Delete provider |

**Response Format:**

```typescript
// IdentityProvidersResult
{
  "identityProviders": [
    {
      "name": "string",
      "displayName": "string",
      "isEnabled": true,
      "allowSelfRegistration": true,  // Controls if new users can self-register via this provider
      "defaultGroupRtId": "string",   // Optional: Group to auto-assign on first login
      // Provider-specific fields...
    }
  ]
}
```

**Client secret of the external providers is write-only (AB#5540).** Google, Microsoft, Facebook and
Azure Entra ID providers carry a `clientSecret` (CK value type `Secret`, stored encrypted):

- `GET` responses (list and by id) and the `POST` / `PUT` responses **never** contain it —
  `clientSecret` is always `null`. The `PUT` response is mapped from the stored entity, it no longer
  echoes the request body.
- `POST` requires a non-empty `clientSecret`.
- `PUT`: a non-empty `clientSecret` replaces the stored secret; `null`, `""` or an omitted field
  keeps it unchanged. There is no clear operation (the secret is required on these provider types).
- There are no placeholder semantics: a value such as `<...>` or `TODO_SET_*` is an ordinary
  secret and is stored encrypted like any other.
- Every response of these provider types carries `clientSecretIsSet` (`true` when a readable secret
  is stored — encrypted with a key of this host's key ring, or legacy clear text before the encrypt
  sweep; computed from the stored form, never by decrypting). A secret encrypted with a key id that
  is not in the key ring (e.g. restored from another environment) is kept stored but reported as
  `false` until the key is added to the ring or the secret is re-entered. Other provider types omit
  the field. It is ignored on input.
- They also carry `clientSecretKeyMissing` (`true` when the stored secret is encrypted with a key id
  that is not in this host's key ring — the case above) and `clientSecretSetAt` (UTC time the current
  encrypted secret was written; `null` for legacy clear text and when no secret is set). Both are
  computed from the stored form and ignored on input.
- With `SecretEncryption:StrictMode` on, a secret still stored as legacy clear text is reported as
  `clientSecretIsSet: true` but cannot be read, so the provider is skipped at sign-in until the encrypt
  sweep has run or the secret is re-entered (strict mode is enabled only after the sweep reports zero
  clear-text values).
- `POST` / `PUT` with a new `clientSecret` on a host without a key ring answer **503** with
  `application/problem+json`, `code: "SecretEncryptionNotConfigured"` (nothing is stored). A `PUT`
  without a new secret still works there and keeps the stored value.

### Email Domain Group Rules (`/{tenantId}/v1/emailDomainGroupRules`)

Manages email domain to group mapping rules. When a new user logs in, their email domain is matched against these rules, and they are automatically added to the target group.

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/emailDomainGroupRules` | ReadOnly | Get all rules |
| GET | `/emailDomainGroupRules/{rtId}` | ReadOnly | Get rule by ID |
| POST | `/emailDomainGroupRules` | ReadWrite | Create new rule |
| PUT | `/emailDomainGroupRules/{rtId}` | ReadWrite | Replace rule |
| DELETE | `/emailDomainGroupRules/{rtId}` | ReadWrite | Delete rule |

**Request/Response DTOs:**

```typescript
// EmailDomainGroupRuleDto
{
  "rtId": "string",               // Auto-generated on create
  "emailDomainPattern": "string", // Required: e.g., "meshmakers.com"
  "targetGroupRtId": "string",    // Required: RtId of the target group
  "description": "string"         // Optional
}

// EmailDomainGroupRulesResult (GET all)
{
  "emailDomainGroupRules": [EmailDomainGroupRuleDto]
}
```

### External Tenant User Mappings (`/{tenantId}/v1/externalTenantUserMappings`)

Manages cross-tenant user role mappings. Each mapping links a user from a parent (source) tenant to roles in the current (child) tenant.

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/externalTenantUserMappings` | ReadOnly | Get all mappings (supports `skip`, `take`, `sourceTenantId` filter) |
| GET | `/externalTenantUserMappings/{rtId}` | ReadOnly | Get mapping by ID |
| POST | `/externalTenantUserMappings` | ReadWrite | Create new mapping |
| POST | `/externalTenantUserMappings/sourceUserLookup` | ReadWrite | Find one user of a source tenant by exact user name or e-mail (AB#8341); every negative case `404 SourceUserNotFound`, limited per caller → `429` with `retryAfterSeconds`. Contract: `CONCEPT-SIBLING-TENANT-GRANTS.md` |
| PUT | `/externalTenantUserMappings/{rtId}` | ReadWrite | Update mapping (change roles) |
| DELETE | `/externalTenantUserMappings/{rtId}` | ReadWrite | Delete mapping |

**Request/Response DTOs:**

```typescript
// ExternalTenantUserMappingDto (Response)
{
  "id": "string",
  "sourceTenantId": "string",
  "sourceUserId": "string",
  "sourceUserName": "string",
  "roleIds": ["string"]
}

// CreateExternalTenantUserMappingDto (POST)
{
  "sourceTenantId": "string",  // Required
  "sourceUserId": "string",    // Required
  "sourceUserName": "string",  // Required
  "roleIds": ["string"]        // Optional
}

// UpdateExternalTenantUserMappingDto (PUT)
{
  "roleIds": ["string"]  // New role assignments
}

// SourceUserLookupRequestDto (POST sourceUserLookup)
{
  "sourceTenantId": "string",  // registry ancestor, or a tenant that permits this one (AB#8345)
  "identifier": "string"       // exact user name or exact e-mail, case-insensitive
}

// SourceUserLookupResultDto (200; no e-mail, no phone)
{
  "sourceTenantId": "string",
  "userId": "string",
  "userName": "string",
  "displayName": "string | null"
}
```

### Groups (`/{tenantId}/v1/groups`)

Manages groups with role assignments. Users and other groups can be members. Group members inherit all roles assigned to their groups (including nested groups).

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/groups` | ReadOnly | Get all groups |
| GET | `/groups/GetPaged` | ReadOnly | Get groups with pagination (`skip`, `take`) |
| GET | `/groups/{rtId}` | ReadOnly | Get group by ID |
| GET | `/groups/names/{groupName}` | ReadOnly | Get group by name |
| POST | `/groups` | ReadWrite | Create new group |
| PUT | `/groups/{rtId}` | ReadWrite | Update group name/description |
| DELETE | `/groups/{rtId}` | ReadWrite | Delete group |
| GET | `/groups/{rtId}/roles` | ReadOnly | Get assigned role IDs |
| PUT | `/groups/{rtId}/roles` | ReadWrite | Replace role assignments |
| GET | `/groups/{rtId}/members/users` | ReadOnly | Get user member IDs |
| PUT | `/groups/{rtId}/members/users/{userId}` | ReadWrite | Add user to group |
| DELETE | `/groups/{rtId}/members/users/{userId}` | ReadWrite | Remove user from group |
| GET | `/groups/{rtId}/members/groups` | ReadOnly | Get nested group IDs |
| PUT | `/groups/{rtId}/members/groups/{childGroupId}` | ReadWrite | Add nested group (rejects cycles) |
| DELETE | `/groups/{rtId}/members/groups/{childGroupId}` | ReadWrite | Remove nested group |

**Request/Response DTOs:**

```typescript
// GroupDto (Response)
{
  "id": "string",
  "groupName": "string",
  "groupDescription": "string",
  "roleIds": ["string"],
  "memberUserIds": ["string"],
  "memberExternalUserIds": ["string"],
  "memberGroupIds": ["string"]
}

// CreateGroupDto (POST)
{
  "groupName": "string",      // Required
  "groupDescription": "string", // Optional
  "roleIds": ["string"]       // Optional
}

// UpdateGroupDto (PUT)
{
  "groupName": "string",      // Required
  "groupDescription": "string" // Optional
}
```

**Default Groups:**

Every tenant is provisioned with a `TenantOwners` group that has all default roles assigned. Adding a user to the `TenantOwners` group grants them all tenant permissions via group role inheritance.

**Internal Storage:**

Group relationships (role assignments, user members, external user members, nested groups) are stored as CK associations internally. The REST API shape is unchanged — `GroupDto` still returns `roleIds`, `memberUserIds`, `memberExternalUserIds`, and `memberGroupIds` arrays assembled from association queries.

**Circular Group Prevention:**

Adding a nested group (PUT `/{rtId}/members/groups/{childGroupId}`) validates that the operation would not create a cycle. If it would, the request is rejected with HTTP 400.

### Admin Provisioning (`/{tenantId}/v1/adminProvisioning/{targetTenantId}`)

Cross-tenant provisioning controller routed via the system tenant. Allows users with TenantManagement role to pre-provision ExternalTenantUserMappings in a target tenant without needing `allowed_tenants` for that tenant.

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/adminProvisioning/{targetTenantId}` | ReadWrite | List all mappings in target tenant |
| POST | `/adminProvisioning/{targetTenantId}` | ReadWrite | Create new mapping in target tenant |
| POST | `/adminProvisioning/{targetTenantId}/provisionCurrentUser` | ReadWrite | Provision current user with all roles |
| DELETE | `/adminProvisioning/{targetTenantId}/{mappingRtId}` | ReadWrite | Delete mapping in target tenant |

**`provisionCurrentUser` endpoint:**

Extracts `sub`, `preferred_username`, and `tenant_id` from the JWT, fetches all roles from the target tenant, and creates an `RtExternalTenantUserMapping` with all role IDs. The response header `X-Provisioning-Outcome` says what the call did (AB#7088): `created` (201; a new mapping with all roles, member of `TenantOwners`), `repaired` (200; a mapping existed but granted no effective role — no existing role in `MappedRoleIds`, none through a group — or carried a wrong `SourceUserName`; it is filled with all roles, added to `TenantOwners` and/or given the right name, never duplicated) or `already-provisioned` (200; nothing changed — a mapping that already grants a role is never widened). The token exchange resolves roles by source tenant + user **name**, the lookup here by user **id**, hence the name check. Role grants through nested child groups are not looked at; the user can be repaired once more, which is what the command promises anyway.

When the caller is a cross-tenant shadow user (`xt_…`; e.g. a session scoped to an intermediate tenant that provisions into a grandchild), the mapping is written for the caller's **home identity** — the root of its `xt_` chain — not for the shadow user (AB#8017). The response body (`sourceTenantId`, `sourceUserId`, `sourceUserName`) names that identity. Every exchange path of the person into the target then works: from the home tenant directly and from the intermediate tenant. A shadow user whose home identity cannot be resolved (ambiguous or broken chain, unregistered home tenant, missing home user) gets **409** (`application/problem+json`, names the caller and says to provision from the home tenant) and nothing is written. A mapping left keyed on a shadow user by an older version stays; calling `provisionCurrentUser` once from the home tenant adds the home mapping.

### Diagnostics (`/{tenantId}/v1/diagnostics`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/diagnostics` | Authenticated | Get current user's diagnostics |
| POST | `/diagnostics/reconfigureLogLevel` | ReadWrite | Change log level |

**Log Level Configuration:**

```typescript
// Query parameters
?minLogLevel=Debug&maxLogLevel=Error&loggerName=Meshmakers
```

### Setup (`/system/v1/setup`) — System API (Bearer Auth)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| POST | `/setup` | Authenticated | Configure initial admin user |

**Note:** Only available when no users exist in the system. Requires Bearer token authentication (used by `octo-cli`).

**Request DTO:**

```typescript
// AdminUserDto
{
  "email": "admin@example.com",
  "password": "SecurePassword123!"
}
```

### Setup (`/{tenantId}/api/setup`) — SPA API (Anonymous)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/{tenantId}/api/setup/status` | Anonymous | Check if initial setup is required |
| POST | `/{tenantId}/api/setup/create-admin` | Anonymous | Create initial admin user |

**Note:** Both endpoints return `404 Not Found` when users already exist, making the controller effectively invisible after setup is complete. This is the browser-facing counterpart of the System API setup endpoint.

**GET /status Response:**

```typescript
// SetupStatusDto (200 if setup needed, 404 if users exist)
{
  "setupRequired": true
}
```

**POST /create-admin Request:**

```typescript
// SetupAdminRequestDto
{
  "email": "admin@example.com",
  "password": "SecurePassword123!",
  "confirmPassword": "SecurePassword123!"
}
```

**POST /create-admin Response:**

```typescript
// SetupResultDto
{
  "success": true,
  "errorMessage": null
}
```

### Tools (`/{tenantId}/v1/tools`)

| Method | Endpoint | Policy | Description |
|--------|----------|--------|-------------|
| GET | `/tools/generatePassword` | ReadOnly | Generate random password |

**Response:**

```typescript
// GeneratedPasswordDto
{
  "password": "***REMOVED-DEMO-PASSWORD-AB3837***"  // 16-character alphanumeric
}
```

## Pagination

### Request Parameters

```
GET /{tenantId}/v1/users/GetPaged?skip=0&take=100
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skip` | int | 0 | Number of items to skip |
| `take` | int | 100 | Number of items to return |
| `filter` | string | null | Optional filter expression |

### Response Headers

```
X-Pagination: {"totalCount":250,"skip":0,"take":100}
```

### Response Format

```typescript
// PagedResult<T>
{
  "list": [...],
  "totalCount": 250,
  "skip": 0,
  "take": 100
}
```

## Error Responses

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing/invalid token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 500 | Internal Server Error |

### Error DTOs

```typescript
// NotFoundErrorDto
{
  "message": "Resource not found",
  "resourceType": "User",
  "resourceId": "john.doe"
}

// OperationFailedErrorDto
{
  "message": "Operation failed",
  "code": "VALIDATION_ERROR",
  "description": "Email is required"
}

// InternalServerErrorDto
{
  "message": "An unexpected error occurred",
  "correlationId": "abc-123-def"
}
```

## Cache Invalidation

Write operations on certain resources trigger distributed events:

| Resource | Event |
|----------|-------|
| Clients | `CorsClientsUpdate` |
| API Resources | `CorsClientsUpdate` |
| API Scopes | `CorsClientsUpdate` |
| Identity Providers | `IdentityProviderUpdate` |

These events ensure cache consistency across multiple service instances.

## Example Requests

All examples use `octosystem` as the tenant ID (the default system tenant ID). The system tenant ID is configurable via `OctoSystemConfiguration.SystemTenantId`. Replace with any tenant ID as needed.

### Create User

```http
POST /octosystem/v1/users HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

### Create OAuth Client

```http
POST /octosystem/v1/clients HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "isEnabled": true,
  "clientId": "my-web-app",
  "clientName": "My Web Application",
  "allowedGrantTypes": ["authorization_code"],
  "redirectUris": ["https://myapp.com/callback"],
  "postLogoutRedirectUris": ["https://myapp.com"],
  "allowedScopes": ["openid", "profile", "email", "api"]
}
```

### Get Paginated Users

```http
GET /octosystem/v1/users/GetPaged?skip=20&take=10 HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### Merge Users

```http
POST /octosystem/v1/users/john.doe/merge HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "sourceUserName": "Google_john.doe@example.com"
}
```

### Add Role to User

```http
PUT /octosystem/v1/users/john.doe/roles/Admin HTTP/1.1
Host: identity.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```
