/**
 * UTIP Application Routes
 */

import { Routes } from '@angular/router';

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
    loadComponent: () => import('./components/dashboard/dashboard.component').then(m => m.DashboardComponent)
  },
  {
    path: 'navigator',
    loadComponent: () => import('./components/navigator/navigator.component').then(m => m.NavigatorComponent)
  },
  {
    path: '**',
    redirectTo: '/dashboard'
  }
];
