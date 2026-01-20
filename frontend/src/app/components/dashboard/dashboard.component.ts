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
import { ToastService } from '../../services/toast.service';
import { SkeletonLoaderComponent } from '../shared/skeleton-loader.component';
import { SearchInputComponent } from '../shared/search-input/search-input.component';
import { firstValueFrom } from 'rxjs';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, FormsModule, SkeletonLoaderComponent, SearchInputComponent],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {
  private authService = inject(AuthService);
  private apiService = inject(ApiService);
  private toastService = inject(ToastService);
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

  /**
   * Trigger file selection for Intel Report upload
   */
  uploadIntelReport(): void {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.pdf,.json,.stix,.stix2,.txt';
    input.onchange = (event: Event) => {
      const file = (event.target as HTMLInputElement).files?.[0];
      if (file) {
        this.processIntelUpload(file);
      }
    };
    input.click();
  }

  /**
   * Process Intel Report file upload
   */
  private async processIntelUpload(file: File): Promise<void> {
    this.toastService.info(`Uploading ${file.name}...`);

    try {
      const response = await firstValueFrom(this.apiService.uploadIntelReport(file));
      this.toastService.success(`Intel report uploaded successfully. Processing...`);

      // Refresh dashboard data to show new report
      await this.loadDashboardData();
    } catch (error: any) {
      console.error('Failed to upload intel report:', error);
      const message = error?.error?.detail || error?.message || 'Failed to upload intel report';
      this.toastService.error(message);
    }
  }

  /**
   * Trigger file selection for Vulnerability Scan upload
   */
  uploadVulnScan(): void {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.nessus';
    input.onchange = (event: Event) => {
      const file = (event.target as HTMLInputElement).files?.[0];
      if (file) {
        this.processVulnUpload(file);
      }
    };
    input.click();
  }

  /**
   * Process Vulnerability Scan file upload
   */
  private async processVulnUpload(file: File): Promise<void> {
    this.toastService.info(`Uploading ${file.name}...`);

    try {
      const response = await firstValueFrom(this.apiService.uploadVulnerabilityScan(file));
      this.toastService.success(
        `Scan uploaded: ${response.vulnerabilities_found} vulnerabilities found`
      );

      // Refresh dashboard data to show new scan
      await this.loadDashboardData();
    } catch (error: any) {
      console.error('Failed to upload vulnerability scan:', error);
      const message = error?.error?.detail || error?.message || 'Failed to upload vulnerability scan';
      this.toastService.error(message);
    }
  }
}
