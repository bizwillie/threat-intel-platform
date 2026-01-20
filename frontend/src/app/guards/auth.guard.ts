/**
 * Authentication Guard
 *
 * Protects routes that require authentication.
 * Redirects unauthenticated users to the login page.
 */

import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from '../services/auth.service';

/**
 * Guard that checks if user is authenticated.
 * Redirects to /login if not authenticated.
 */
export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  // Store the attempted URL for redirecting after login
  const returnUrl = state.url;
  router.navigate(['/login'], { queryParams: { returnUrl } });
  return false;
};

/**
 * Guard that checks if user has a specific role.
 * Use with route data: { requiredRole: 'admin' }
 *
 * TODO: Currently unused - implement when role-based route protection is needed
 */
export const roleGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // First check authentication
  if (!authService.isAuthenticated()) {
    router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
    return false;
  }

  // Check for required role in route data
  const requiredRole = route.data?.['requiredRole'] as string;
  if (requiredRole && !authService.hasRole(requiredRole)) {
    // User doesn't have required role - redirect to dashboard with error
    router.navigate(['/dashboard'], {
      queryParams: { error: 'insufficient_permissions' }
    });
    return false;
  }

  return true;
};

/**
 * Guard for hunter-only routes (upload, layer generation)
 *
 * TODO: Apply to upload routes when file upload UI is implemented
 */
export const hunterGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (!authService.isAuthenticated()) {
    router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
    return false;
  }

  if (!authService.hasRole('hunter') && !authService.hasRole('admin')) {
    router.navigate(['/dashboard'], {
      queryParams: { error: 'hunter_required' }
    });
    return false;
  }

  return true;
};

/**
 * Guard for admin-only routes
 *
 * TODO: Currently unused - implement when admin-only routes are added
 */
export const adminGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (!authService.isAuthenticated()) {
    router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
    return false;
  }

  if (!authService.hasRole('admin')) {
    router.navigate(['/dashboard'], {
      queryParams: { error: 'admin_required' }
    });
    return false;
  }

  return true;
};
