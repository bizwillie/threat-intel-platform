/**
 * Production Environment Configuration
 */

export const environment = {
  production: true,
  apiUrl: '/api/v1',  // Relative URL for production (Nginx proxy)
  keycloakUrl: '/auth',  // Proxied through Nginx
  keycloakRealm: 'utip',
  keycloakClientId: 'utip-frontend',
};
