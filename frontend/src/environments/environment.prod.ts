/**
 * Production Environment Configuration
 */

export const environment = {
  production: true,
  apiUrl: '/api/v1',  // Relative URL for production (Nginx proxy)
  keycloakUrl: '/auth',  // Proxied through Nginx
  keycloakRealm: 'utip',
  keycloakClientId: 'utip-frontend',
  // Set to true to bypass authentication (backend must have AUTH_DISABLED=true)
  authDisabled: false,
};
