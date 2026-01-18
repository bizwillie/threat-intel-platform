/**
 * UTIP Root Component
 */

import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet],
  template: `
    <div class="app-container">
      <router-outlet></router-outlet>
    </div>
  `,
  styles: [`
    .app-container {
      width: 100%;
      height: 100vh;
      overflow: hidden;
    }
  `]
})
export class AppComponent {
  title = 'UTIP - Unified Threat Intelligence Platform';
}
