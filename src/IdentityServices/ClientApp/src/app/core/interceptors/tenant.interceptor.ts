import { HttpInterceptorFn } from '@angular/common/http';
import { getTenantIdFromUrl } from '../utils/tenant.utils';

/**
 * HTTP interceptor that prepends the tenant ID to API calls.
 * Transforms '/api/...' to '/{tenantId}/api/...'
 */
export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  // Only intercept API calls
  if (!req.url.startsWith('/api/')) {
    return next(req);
  }

  // Prepend tenant ID to the URL
  const tenantId = getTenantIdFromUrl();
  const modifiedUrl = `/${tenantId}${req.url}`;
  const modifiedReq = req.clone({ url: modifiedUrl });
  return next(modifiedReq);
};
