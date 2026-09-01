# Discovery Document Diff: Duende IdentityServer 8.0.6 → OpenIddict 7.6.0

**Status:** verified against the golden baseline, 2026-09-01 · **Epic:** AB#4989 · **Work items:** AB#4990/AB#4996

This document lists every difference in `/.well-known/openid-configuration` between the
Duende-based identity service and the OpenIddict-based one, with the consumer impact
assessment. The authoritative machine-readable snapshot is
`tests/IdentityServices.IntegrationTests/GoldenFiles/discovery-document.json`
(golden-pinned — any future drift fails `TokenShapeGoldenTests.DiscoveryDocument_MatchesGoldenBaseline`).

Unchanged and load-bearing (pinned): `issuer`, `authorization_endpoint`, `token_endpoint`,
`end_session_endpoint` (`/connect/endsession`), `device_authorization_endpoint`
(`/connect/deviceauthorization`), `userinfo_endpoint`, `introspection_endpoint`,
`revocation_endpoint`, `pushed_authorization_request_endpoint` (`/connect/par`),
`jwks_uri` (`/.well-known/openid-configuration/jwks`), `registration_endpoint`
(`/connect/register`, custom DCR), `code_challenge_methods_supported` (S256),
`grant_types_supported` for every flow the platform uses (authorization_code,
client_credentials, refresh_token, device_code, token-exchange).

## Removed entries (features nobody on the platform used)

| Entry | Why it is gone | Impact |
|---|---|---|
| `backchannel_authentication_*` (CIBA) | Duende advertised CIBA; never enabled/used | none |
| `check_session_iframe`, `frontchannel_logout_supported`, `frontchannel_logout_session_supported`, `backchannel_logout_*` | OpenIddict does not advertise session-management/front-channel metadata. Front-channel logout itself STILL WORKS (own `/connect/endsession/callback` iframe page); it is just not advertised | none — no consumer reads these flags (the SPA drives logout through the API) |
| `grant_types_supported`: `implicit`, `password`, CIBA | Deliberately not enabled on OpenIddict — no client had them in `AllowedGrantTypes` | none; hardening |
| `response_types_supported`: everything except `code` | Only `authorization_code` + PKCE is used platform-wide; implicit/hybrid response types are gone | none; hardening |
| `dpop_signing_alg_values_supported` | DPoP not enabled (was never used; `RequireDPoP` is false everywhere) | none |
| `*_auth_signing_alg_values_supported`, `request_object_signing_alg_values_supported`, `userinfo_signing_alg_values_supported`, `introspection_signing_alg_values_supported` | Alg-advertisement entries for features not in use (JWT-secured requests/responses) | none |
| `request_parameter_supported` / `request_uri_parameter_supported` now `false` | JAR (request objects by value/reference) not enabled. NOTE: this is unrelated to PAR — RFC 9126 clients only check for `pushed_authorization_request_endpoint`, which is present. .NET 9+ OIDC clients keep auto-using PAR | none |

## Reduced entries (documented behavior difference)

| Entry | Duende | OpenIddict | Impact |
|---|---|---|---|
| `scopes_supported` | All identity resources + API scopes of the system tenant (dynamic) | Protocol scopes only (`openid`, `offline_access`) | Scope VALIDATION is unaffected — requested scopes are checked per tenant against the CK-backed scope store (identity resources included). Only the static advertisement is smaller. No platform consumer enumerates `scopes_supported`. |
| `claims_supported` | Standard profile claims + `role`, `allowed_tenants` | JWT-structural claims (`aud`, `exp`, `iat`, `iss`, `sub`) | Issued tokens carry the same claims as before (golden-pinned). Only the advertisement is smaller; no consumer reads it. |

## Added entries (informational)

`claims_parameter_supported: false`, `device_authorization_endpoint_auth_methods_supported`,
`pushed_authorization_request_endpoint_auth_methods_supported`,
`tls_client_certificate_bound_access_tokens: false` — standards-conform additions, no impact.

## Behavioral notes outside the discovery document

- `expires_in` in token responses may be reported as the remaining lifetime (e.g. 3599)
  instead of the configured lifetime (3600).
- A `client_credentials` request WITHOUT a `scope` parameter is granted no scopes by
  OpenIddict (Duende granted all allowed scopes of the client). All platform service
  accounts send an explicit `scope` — new integrations must do the same.
- Token introspection now authenticates CLIENTS; Duende's API-resource introspection
  (ApiSecrets) is not wired up. No platform service uses introspection (all validate JWTs
  locally); the ApiSecrets management endpoints remain for the stored data.
