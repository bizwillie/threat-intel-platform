/**
 * UTIP Application Routes
 */

import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    redirectTo: '/navigator',
    pathMatch: 'full'
  },
  {
    path: 'login',
    loadComponent: () => import('./components/login/login.component').then(m => m.LoginComponent)
  },
  {
    path: 'navigator',
    loadComponent: () => import('./components/navigator/navigator.component').then(m => m.NavigatorComponent)
  },
  {
    path: '**',
    redirectTo: '/navigator'
  }
];
