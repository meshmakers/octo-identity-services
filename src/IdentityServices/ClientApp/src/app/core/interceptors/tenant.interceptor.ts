import { HttpInterceptorFn } from '@angular/common/http';

export const tenantInterceptor: HttpInterceptorFn = (req, next) => {
  // Extract tenant ID from current URL path
  const pathSegments = window.location.pathname.split('/').filter(s => s);
  const tenantId = pathSegments[0] || 'System';

  // Only modify API calls
  if (req.url.startsWith('/api/')) {
    const tenantUrl = `/${tenantId}${req.url}`;
    const clonedReq = req.clone({ url: tenantUrl });
    return next(clonedReq);
  }

  return next(req);
};
