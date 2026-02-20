/**
 * Extract the tenant ID from the current browser URL.
 * URL pattern: /{tenantId}/login, /{tenantId}/logout, etc.
 * Falls back to 'System' if no tenant segment is found.
 */
export function getTenantIdFromUrl(): string {
  const segments = window.location.pathname.split('/').filter(s => s.length > 0);
  return segments.length > 0 ? segments[0] : 'System';
}
