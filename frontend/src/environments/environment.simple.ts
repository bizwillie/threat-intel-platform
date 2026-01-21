/**
 * Simplified Environment Configuration
 *
 * For use with docker-compose.simple.yml (NO Keycloak)
 * Authentication is disabled - backend returns mock user
 */

export const environment = {
  production: true,
  apiUrl: '/api/v1',  // Proxied through Nginx
  keycloakUrl: '',    // Not used when authDisabled=true
  keycloakRealm: '',
  keycloakClientId: '',
  // Authentication disabled - backend returns mock dev user
  authDisabled: true,
};
