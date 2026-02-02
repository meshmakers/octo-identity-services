/**
 * Proxy configuration for Angular dev server.
 * Forwards API requests to the ASP.NET backend at https://localhost:5003
 */
const PROXY_CONFIG = [
  {
    // Match any path containing /api/ (handles tenant-prefixed routes like /System/api/...)
    context: (pathname) => {
      return pathname.includes('/api/') ||
             pathname.startsWith('/connect') ||
             pathname.startsWith('/.well-known') ||
             pathname.startsWith('/system/v');
    },
    target: "https://localhost:5003",
    secure: false,
    changeOrigin: true
  }
];

module.exports = PROXY_CONFIG;
