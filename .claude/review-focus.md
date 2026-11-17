# Review focus: octo-identity-services

Check these points in addition to the general review. Each point names its source: a rule of `AGENTS.md`, a document
under `docs/`, or the pull request whose review found the problem.

## Public repository

- Changed docs, code comments and test names carry no work item IDs, internal hostnames, customer or tenant names or
  secrets (`AGENTS.md`, "Rules"; found again in PR #313 and PR #277).

## Authorization and role changes

- Every new or changed administration endpoint carries a policy of `IdentityApiAuthorizationPolicies`, and secret writes
  require `SecretManagement` (`AGENTS.md`, "Rules"; `docs/architecture.md`).
- Role, group and role-definition changes go through the role change guard (no escalation, the last administrator
  stays) (`AGENTS.md`, "Rules"; `docs/role-guards.md`).
- REST write endpoints for groups, clients, secrets and data permissions stay facades: the rule lives in the
  `Group.*` / `Client.*` / `DataPermission.*` handler, and the REST status code matches what the handler actually stored,
  with no `200` for a write that did not happen (`docs/identity-rest-facades.md`; PR #310, PR #269).

## Tokens and tenants

- Tokens stay bound to one tenant: every access token carries `tenant_id` and `tenant_gen`, exchanged tokens take the
  issued-token path, and a token from an earlier tenant with the same id is refused (`docs/openiddict-protocol.md`;
  PR #304).
- A cross-tenant exchange issues only the roles the shadow user resolves in the target tenant, checks the second factor
  and checks withdrawn grants for exactly the source it resolved (`docs/cross-tenant-authentication.md`; PR #282).

## Credentials and client mirroring

- Credentials never reach a log property, a request URL or a DTO `ToString()` (`docs/credential-security.md`).
- Client mirror provisioning removes or replaces clients only when they are marked as mirrors, selects the same surviving
  child client in cleanup and convergence, and rolls back its insert when the tracking row update fails
  (`docs/client-mirroring.md`; PR #311, PR #314).

## Caches and tests

- A successful write to policies, CORS origins or client overlays invalidates the matching cache on every path, including
  partial failures (PR #310, PR #313).
- Integration tests share no process-wide or machine-wide state, clean up what they change (policies, settings), and
  fail when a wait times out instead of passing silently (`docs/testing.md`; PR #313).
