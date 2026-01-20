/**
 * UTIP Application Configuration
 *
 * SECURITY: Auth interceptor automatically attaches JWT tokens
 * and handles 401/403 errors with token refresh.
 */

import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { routes } from './app.routes';
import { authInterceptorProvider } from './interceptors/auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideHttpClient(withInterceptorsFromDi()),
    authInterceptorProvider,
  ]
};
