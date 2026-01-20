/**
 * UTIP Navigator Component
 *
 * Main MITRE ATT&CK matrix visualization with integrated
 * attribution and remediation panels.
 *
 * SECURITY: Uses takeUntilDestroyed to prevent memory leaks
 * from unsubscribed observables.
 */

import { Component, OnInit, inject, DestroyRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AuthService } from '../../services/auth.service';
import { ApiService, LayerDetail } from '../../services/api.service';
import { AttributionPanelComponent } from '../attribution-panel/attribution-panel.component';
import { RemediationSidebarComponent } from '../remediation-sidebar/remediation-sidebar.component';
import { TacticMatrixComponent } from './tactic-matrix/tactic-matrix.component';

@Component({
  selector: 'app-navigator',
  standalone: true,
  imports: [
    CommonModule,
    AttributionPanelComponent,
    RemediationSidebarComponent,
    TacticMatrixComponent
  ],
  templateUrl: './navigator.component.html',
  styleUrls: ['./navigator.component.scss']
})
export class NavigatorComponent implements OnInit {
  private authService = inject(AuthService);
  private apiService = inject(ApiService);
  private router = inject(Router);
  private destroyRef = inject(DestroyRef);

  currentLayer: LayerDetail | null = null;
  selectedTechniqueId: string | null = null;
  showAttributionPanel = false;
  showRemediationSidebar = false;
  loading = false;
  error = '';

  ngOnInit(): void {
    // Check authentication
    if (!this.authService.isAuthenticated()) {
      this.router.navigate(['/login']);
      return;
    }

    // Load initial data
    this.loadLayers();
  }

  loadLayers(): void {
    this.loading = true;
    this.error = '';

    this.apiService.getLayers()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (layers) => {
          console.log('Loaded layers:', layers);
          // Load the first layer if available
          if (layers.length > 0) {
            this.loadLayer(layers[0].id);
          }
          this.loading = false;
        },
        error: (err) => {
          console.error('Error loading layers:', err);
          this.error = 'Failed to load layers';
          this.loading = false;
        }
      });
  }

  loadLayer(layerId: string): void {
    this.loading = true;

    this.apiService.getLayer(layerId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (layer) => {
          this.currentLayer = layer;
          console.log('Loaded layer:', layer);
          this.loading = false;
        },
        error: (err) => {
          console.error('Error loading layer:', err);
          this.error = 'Failed to load layer';
          this.loading = false;
        }
      });
  }

  toggleAttributionPanel(): void {
    this.showAttributionPanel = !this.showAttributionPanel;
    if (this.showAttributionPanel) {
      this.showRemediationSidebar = false;
    }
  }

  toggleRemediationSidebar(): void {
    this.showRemediationSidebar = !this.showRemediationSidebar;
    if (this.showRemediationSidebar) {
      this.showAttributionPanel = false;
    }
  }

  onTechniqueSelected(techniqueId: string): void {
    this.selectedTechniqueId = techniqueId;
    this.showRemediationSidebar = true;
    this.showAttributionPanel = false;
  }

  goToDashboard(): void {
    this.router.navigate(['/dashboard']);
  }

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/login']);
  }
}
