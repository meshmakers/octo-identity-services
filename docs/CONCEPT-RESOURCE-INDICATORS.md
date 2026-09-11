# Concept — Resource indicators (RFC 8707) validated against the API resource store (AB#5193)

Restores the pre-migration behaviour of the `resource` request parameter. Under Duende it was
validated against the tenant's API resources; after the OpenIddict migration (AB#4989) it was
validated against an allow-list nothing fills, so **every** value was rejected with
`invalid_target` and no interactive MCP client (Claude Code) could log in on any environment.

## What broke

OpenIddict 7.6.0 checks the parameter in three places — `Authentication.ValidateResources`
(authorize), `Authentication.ValidatePushedResources` (PAR, which the .NET OIDC handler uses
automatically) and `Exchange.ValidateResources` (token, including refresh). All three are the same
six lines:

```csharp
var resources = context.Request.GetResources().ToHashSet(StringComparer.Ordinal);
resources.ExceptWith(context.Options.Resources.Select(static r => r.AbsoluteUri));
if (resources.Count is not 0) { context.Reject(Errors.InvalidTarget, …ID2190…); }
```

`OpenIddictServerOptions.Resources` has exactly one producer, `RegisterResources(...)` at
composition time, and this service never called it — grep the history: no branch ever did. A
static, process-wide list also could not express what we need, because API resources are
per-tenant CK entities created at runtime by the TenantApi and by blueprint seeding. So the
allow-list was empty, the set difference was never empty, and every indicator was refused.

Three things made it survive the migration unnoticed: the resource indicator is the one OAuth
parameter the golden baseline never exercised; no automated test covered it; and every flow
without a `resource` parameter — octo-cli device flow, Refinery Studio, `client_credentials`,
token exchange — was unaffected, so the platform looked healthy. The failure is visible only to
clients that follow RFC 9728 / RFC 8707, which today means interactive MCP clients.

A second gate sat right behind it: `ValidateResourcePermissions` (ID2192) asks the application
store for a `rsrc:{resource}` permission per client. `RtClient` carries `AllowedScopes` and no
allowed resources, so `ClientPermissionsMapper` can never emit one — that check could only ever
reject. It was invisible while nothing got past `ValidateResources`.

## The fix: a store, the same one OpenIddict 8.x introduces

The OpenIddict `dev` branch solves it with a store-backed fallback:

```csharp
if (resources.Count is not 0 && !context.Options.EnableDegradedMode)
{
    var manager = context.ServiceProvider.GetService<IOpenIddictResourceManager>() ?? throw …;
    await foreach (var resource in manager.FindByNamesAsync([.. resources], ct))
        resources.Remove(await manager.GetNameAsync(resource, ct));
}
```

`IOpenIddictResourceStore<TResource>` behind it has the same shape as the four stores this service
already replaces (application, scope, authorization, token). We port that shape ahead of time
rather than invent a different one:

| Piece | Where | Notes |
|---|---|---|
| `IOpenIddictResourceStore<TResource>` | `IdentityServerPersistence/SystemStores/OpenIddict/` | The subset of the 8.x interface the validation uses: `FindByNameAsync`, `FindByNamesAsync`, `GetNameAsync`. |
| `OpenIddictResourceStore` | same folder | Projects `RtApiResource` via `IOctoResourceStore.FindRtApiResourcesByNameAsync`. |
| `ResourceIdentifiers` | same folder | Trailing-slash tolerance (below). |
| `OctoResourceValidationHandlers.{Authorization,PushedAuthorization,Token}` | `IdentityServices/OpenIddict/` | Replace the three built-ins at the same descriptor order, same filter, same error contract. |

Tenant scoping is free: `IOctoResourceStore` resolves the repository of the request tenant, so a
resource registered in one tenant is invisible to every other one.

**No cache, deliberately.** Entity caching is off process-wide (`DisableEntityCaching()`, tenant
isolation), and the scope store already does a comparable per-request lookup for audience
resolution. A resource created, renamed or disabled — through the TenantApi, a blueprint apply or
a version-bump reseed — therefore takes effect on the next request, with no invalidation event to
publish and no path that could leave a stale entry behind. An earlier draft of this change carried
a `ConcurrentDictionary` registry invalidated by the existing `CorsClientsUpdate` broadcast; it was
dropped once the store shape made it unnecessary, and with it the gap that blueprint-driven writes
bypass the controllers that publish that event.

### What counts as a usable indicator

1. **Statically registered** — `context.Options.Resources` is still consulted first, so
   `RegisterResources(...)` keeps working as a fast path. It is empty today; keeping it means the
   built-in behaviour is a strict subset of ours.
2. **Registered and enabled for this tenant** — an `RtApiResource` with that name and
   `Enabled = true`. `FindRtApiResourcesByNameAsync` is a plain name query that returns disabled
   entities too, so the store filters them out (same rule as `OpenIddictScopeStore.FindByNameAsync`).
3. **Related to the requested scopes** — the resource has to carry at least one requested scope.
   This is the pre-migration rule and what replaces the `rsrc:` permission check. A request with
   **no** `scope` parameter — a refresh renewal, i.e. exactly the failure being fixed — cannot be
   judged that way: the granted scopes live in the refresh token and are not resolved yet at
   request validation, so registration alone decides there.

Anything else is rejected with OpenIddict's own wording — `invalid_target`, "One of the specified
'resource' parameters is invalid.", `https://documentation.openiddict.com/errors/ID2190` — so the
rejection is indistinguishable on the wire from the built-in one.

### Trailing slashes

A resource indicator is compared as a string, and the two spellings genuinely drift apart here:
`System.Identity.Bootstrap` seeds the MCP resource as `${octo.mcp.publicUrl}/` while the MCP
service advertises `https://localhost:5017` (no slash) in its RFC 9728 metadata
(`ConfigureMcpAuthenticationOptions`). `ResourceIdentifiers` therefore treats a trailing slash as
insignificant: the store queries both spellings in one round trip, and the handler matches the
stored name against the requested one slash-insensitively. **Nothing else is normalized** — host
case, port, path and query stay byte-exact, so an unregistered resource stays unregistered.

Neither the seed nor the MCP metadata was changed to match the other. Both are load-bearing
elsewhere (the seed is blueprint state that only a version bump can rewrite; the metadata is what
clients cache), and neither spelling affects the issued token: audiences come from the granted
scopes via `OctoTokenClaimsService.ResolveAudiencesAsync`, not from the indicator, and the MCP
service runs with `ValidateAudience = false`. Tolerating the difference is the smaller change and
the one that also survives a third-party client getting it "wrong".

### Resource permissions

`ValidateResourcePermissions` / `ValidatePushedResourcePermissions` /
`Exchange.ValidateResourcePermissions` are removed one by one, not switched off with
`IgnoreResourcePermissions()`. The option is a server-wide flag that would also silence a real
allow-list should the model ever grow one; three `RemoveEventHandler` lines sit next to the
handlers that took the rule over and are deleted again the moment there is something to enforce.

🔴 **If the resource indicator is ever made to shape the audience** — the RFC-correct behaviour,
which we deliberately do not implement (audiences are scope-derived, pre-migration format, pinned
by the golden baseline) — a per-client resource allow-list becomes load-bearing and this decision
has to be revisited.

## Upgrading to OpenIddict 8.x

8.0.0 is in preview (preview.4 as of 2026-09-06, `8.0.0-preview.5` milestone open, no announced
date); 7.x is maintained in parallel. When it lands:

1. Delete `OctoResourceValidationHandlers` and the six `RemoveEventHandler` / three
   `AddEventHandler` lines in `OpenIddictConfiguration`.
2. Delete the local `IOpenIddictResourceStore<TResource>` and let `OpenIddictResourceStore`
   implement OpenIddict's own, then register it with
   `ReplaceResourceStore<RtApiResource, OpenIddictResourceStore>()` next to the other four.
3. Re-check the two rules the built-in handler does **not** have — the enabled filter and the
   slash tolerance live in our store, the scope relation in our handler. The store keeps the first
   two; the third needs a new home, or the `rsrc:` permission question has to be answered.

The `dev` branch is still moving in this area, so do not pre-shape the code against a preview
signature.

## Coverage

- `tests/IdentityServerPersistence.UnitTests/Stores/OpenIddictResourceStoreTests.cs` — the store:
  exact name, either slash spelling, disabled resources invisible, both variants queried in one
  round trip, no query without a usable name; plus `ResourceIdentifiers` normalization.
- `tests/IdentityServices.IntegrationTests/Api/Protocol/ResourceIndicatorTests.cs` — over HTTP on
  all three endpoints: authorize issues a code for a registered resource in either spelling and
  refuses an unregistered one, a disabled one and one unrelated to the requested scopes; PAR
  accepts and refuses the same way; the authorization-code → refresh round trip carries the
  indicator on both requests (the renewal is what actually killed live MCP sessions); a request
  without the parameter is unaffected.

Measured baseline before the fix, same tests on stock `main`: a correctly registered resource is
answered with `invalid_target`.
