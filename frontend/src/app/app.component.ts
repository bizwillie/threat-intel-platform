/**
 * UTIP Root Component
 */

import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ToastComponent } from './components/shared/toast/toast.component';
import { ScrollToTopComponent } from './components/shared/scroll-to-top/scroll-to-top.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, ToastComponent, ScrollToTopComponent],
  template: `
    <router-outlet></router-outlet>
    <app-toast></app-toast>
    <app-scroll-to-top></app-scroll-to-top>
  `,
  styles: [`
    :host {
      display: block;
    }
  `]
})
export class AppComponent {
  title = 'UTIP - Unified Threat Intelligence Platform';
}
