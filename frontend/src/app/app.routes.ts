/**
 * UTIP Application Routes
 *
 * SECURITY: Protected routes use authGuard to prevent unauthorized access.
 * Role-based routes use hunterGuard or adminGuard for additional restrictions.
 */

import { Routes } from '@angular/router';
import { authGuard, hunterGuard } from './guards/auth.guard';

export const routes: Routes = [
  {
    path: '',
    redirectTo: '/dashboard',
    pathMatch: 'full'
  },
  {
    path: 'login',
    loadComponent: () => import('./components/login/login.component').then(m => m.LoginComponent)
  },
  {
    path: 'dashboard',
    loadComponent: () => import('./components/dashboard/dashboard.component').then(m => m.DashboardComponent),
    canActivate: [authGuard]
  },
  {
    path: 'navigator',
    loadComponent: () => import('./components/navigator/navigator.component').then(m => m.NavigatorComponent),
    canActivate: [authGuard]
  },
  {
    path: '**',
    redirectTo: '/dashboard'
  }
];
