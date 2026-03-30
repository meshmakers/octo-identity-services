# TODO: Tenant Discovery Improvements

## Status: Planned

These improvements address security, usability, and scalability concerns with the current email-first tenant discovery flow (`/tenant-discovery`).

---

## 1. Security: Do Not Expose Tenant IDs to Unauthenticated Users

**Problem:** The `POST /api/tenant-discovery/lookup` endpoint returns raw `tenantId` strings (e.g., `meshtest`, `customer-prod`) to unauthenticated users. This enables tenant enumeration — an attacker can probe email addresses to discover which organizations use the platform and learn their internal tenant identifiers.

**Solution:** Return opaque, non-reversible identifiers instead of real tenant IDs. Map each tenant to a display-safe representation:

- Return a **display name** (e.g., "Meshmakers GmbH") and an **opaque token** (e.g., a short-lived encrypted reference) instead of the raw `tenantId`
- The frontend sends the opaque token back on tenant selection; the backend resolves it to the real `tenantId` server-side
- The `TenantDiscoveryResultDto` should include `displayName` and `token` instead of `tenantId`
- Opaque tokens should expire (e.g., 5 minutes) to prevent replay

**Affected files:**
- `TenantDiscoveryApiController.cs` — response DTO and token generation
- `TenantDiscoveryService.cs` — resolve tenant display names
- `tenant-discovery.component.ts` — use opaque tokens instead of tenant IDs
- `OidcTenantResolutionMiddleware.cs` — potentially add a token exchange endpoint

---

## 2. UX: Show Tenant Display Names Instead of Technical IDs

**Problem:** The tenant selection step shows raw technical tenant IDs (e.g., `meshtest`, `octosystem`) as radio button labels. These are meaningless to end users who think in terms of their organization name.

**Solution:** Enrich the discovery response with human-readable tenant information:

- Query the `RtTenant` entity for each discovered tenant to obtain `TenantName` or a display name
- Return `displayName` alongside (or instead of) `tenantId` in the API response
- Update the Angular component to show the display name as the primary label
- Optionally show a tenant icon/logo if available

**Affected files:**
- `TenantDiscoveryService.cs` — return display names from `RtTenant`
- `TenantDiscoveryApiController.cs` — extend `DiscoveredTenantDto` with `displayName`
- `tenant-discovery.component.ts/html` — render display names

---

## 3. Performance: Avoid Full Tenant Scan on Every Lookup

**Problem:** Every discovery request triggers a parallel search across **all** tenant databases (`FindUserInTenantAsync` for each tenant). With many tenants (e.g., 50+), this creates significant database load and latency, especially since each search opens a transaction.

**Solution:** Introduce an indexed lookup strategy to avoid the full scan:

- **Option A: Email domain → tenant mapping table.** Maintain a `TenantEmailDomain` entity (or use the existing `EmailDomainGroupRule`) that maps email domains to tenants. On lookup, first check the domain mapping; only fall back to full scan if no mapping exists. This is the approach described in the HRD concept (docs/CONCEPT-TENANT-SPECIFIC-OAUTH.md § 9).
- **Option B: Centralized user index.** Maintain a lightweight index in the system tenant that maps `(normalizedEmail, tenantId)` pairs. Updated on user creation/modification via event hub. Lookup becomes a single query.
- **Option C: Caching.** Cache discovery results per normalized email/username with a short TTL (e.g., 60 seconds). Helps with repeated lookups but doesn't solve the underlying scan issue.

**Recommended approach:** Option A (domain mapping) as the primary path, with full scan as fallback for users whose email domain has no mapping.

**Affected files:**
- `TenantDiscoveryService.cs` — add domain-based lookup path
- Possibly new CK type or reuse `EmailDomainGroupRule` for domain → tenant mapping
- `DefaultConfigurationCreatorService.cs` — seed domain mappings if derivable from existing data
