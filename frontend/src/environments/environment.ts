/**
 * Development Environment Configuration
 */

export const environment = {
  production: false,
  apiUrl: 'http://localhost:8000/api/v1',
  keycloakUrl: 'http://localhost:8080',
  keycloakRealm: 'utip',
  keycloakClientId: 'utip-frontend',
  // Set to true to bypass authentication (backend must have AUTH_DISABLED=true)
  authDisabled: false,
};
