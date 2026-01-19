/**
 * UTIP Dashboard Component
 *
 * Main home page showing system overview and quick actions.
 */

import { Component, OnInit, inject, HostListener } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { ApiService } from '../../services/api.service';
import { SkeletonLoaderComponent } from '../shared/skeleton-loader.component';
import { firstValueFrom } from 'rxjs';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule, SkeletonLoaderComponent],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {
  private authService = inject(AuthService);
  private apiService = inject(ApiService);
  private router = inject(Router);

  currentUser$ = this.authService.currentUser$;
  stats = {
    totalLayers: 0,
    totalReports: 0,
    totalScans: 0,
    criticalTechniques: 0
  };

  recentLayers: any[] = [];
  loading = false;
  searchTerm = '';
  filterBy = 'all';
  sortBy = 'date-desc';

  // Keyboard shortcuts
  @HostListener('window:keydown', ['$event'])
  handleKeyboardEvent(event: KeyboardEvent) {
    // Ctrl+N: Open Navigator
    if (event.ctrlKey && event.key === 'n') {
      event.preventDefault();
      this.openNavigator();
    }
    // Ctrl+K: Focus search (for future command palette)
    if (event.ctrlKey && event.key === 'k') {
      event.preventDefault();
      // Will implement command palette later
    }
  }

  get filteredLayers() {
    let filtered = this.recentLayers;

    // Apply search
    if (this.searchTerm) {
      filtered = filtered.filter(layer =>
        layer.name.toLowerCase().includes(this.searchTerm.toLowerCase())
      );
    }

    // Apply filter
    if (this.filterBy === 'mine' && this.currentUser$) {
      // Filter by current user (would need user ID)
    }

    // Apply sort
    if (this.sortBy === 'date-desc') {
      filtered = [...filtered].sort((a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
    } else if (this.sortBy === 'date-asc') {
      filtered = [...filtered].sort((a, b) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
      );
    } else if (this.sortBy === 'name-asc') {
      filtered = [...filtered].sort((a, b) => a.name.localeCompare(b.name));
    }

    return filtered;
  }

  ngOnInit(): void {
    if (!this.authService.isAuthenticated()) {
      this.router.navigate(['/login']);
      return;
    }

    this.loadDashboardData();

    // Timeout failsafe - prevent infinite loading
    setTimeout(() => {
      if (this.loading) {
        console.warn('Dashboard load timeout - showing empty state');
        this.loading = false;
      }
    }, 10000);
  }

  private async loadDashboardData(): Promise<void> {
    this.loading = true;

    try {
      // Load all data in parallel, gracefully handle failures
      const results = await Promise.allSettled([
        firstValueFrom(this.apiService.getLayers()),
        firstValueFrom(this.apiService.getThreatReports()),
        firstValueFrom(this.apiService.getVulnerabilityScans())
      ]);

      // Extract successful results, default to empty arrays on failure
      const layers: any[] = results[0].status === 'fulfilled' ? results[0].value : [];
      const reports: any[] = results[1].status === 'fulfilled' ? results[1].value : [];
      const scans: any[] = results[2].status === 'fulfilled' ? results[2].value : [];

      // Log any failures for debugging
      results.forEach((result, index) => {
        if (result.status === 'rejected') {
          const names = ['layers', 'reports', 'scans'];
          console.warn(`Failed to load ${names[index]}:`, result.reason);
        }
      });

      // Update state
      this.recentLayers = layers;
      this.stats = {
        totalLayers: layers.length,
        totalReports: reports.length,
        totalScans: scans.length,
        criticalTechniques: 0  // TODO: Calculate from red techniques in layers
      };

    } catch (error) {
      console.error('Unexpected error loading dashboard:', error);
      // Show empty state instead of crashing
      this.recentLayers = [];
      this.stats = { totalLayers: 0, totalReports: 0, totalScans: 0, criticalTechniques: 0 };
    } finally {
      this.loading = false;
    }
  }

  openNavigator(): void {
    this.router.navigate(['/navigator']);
  }

  openLayer(layerId: string): void {
    this.router.navigate(['/navigator'], { queryParams: { layer: layerId } });
  }

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/login']);
  }
}
