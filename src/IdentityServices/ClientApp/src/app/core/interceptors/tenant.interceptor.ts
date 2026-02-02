import { HttpInterceptorFn } from '@angular/common/http';

/**
 * HTTP interceptor that prepends the tenant ID to API calls.
 * Transforms '/api/...' to '/{tenantId}/api/...'
 */
export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  // Only intercept API calls
  if (!req.url.startsWith('/api/')) {
    return next(req);
  }

  // Get tenant ID from the current URL path
  const tenantId = getTenantIdFromUrl();

  if (tenantId) {
    // Prepend tenant ID to the URL
    const modifiedUrl = `/${tenantId}${req.url}`;
    const modifiedReq = req.clone({ url: modifiedUrl });
    return next(modifiedReq);
  }

  return next(req);
};

/**
 * Extract tenant ID from the current browser URL.
 * URL pattern: /{tenantId}/login, /{tenantId}/logout, etc.
 */
function getTenantIdFromUrl(): string | null {
  const path = window.location.pathname;
  const segments = path.split('/').filter(s => s.length > 0);

  // First segment should be the tenant ID
  if (segments.length > 0) {
    return segments[0];
  }

  return 'System'; // Default fallback
}
