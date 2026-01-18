/**
 * UTIP Dashboard Component
 *
 * Main home page showing system overview and quick actions.
 */

import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
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

  ngOnInit(): void {
    if (!this.authService.isAuthenticated()) {
      this.router.navigate(['/login']);
      return;
    }

    this.loadDashboardData();
  }

  loadDashboardData(): void {
    this.loading = true;

    // Load layers
    this.apiService.getLayers().subscribe({
      next: (layers) => {
        this.stats.totalLayers = layers.length;
        this.recentLayers = layers.slice(0, 5); // Get 5 most recent
        this.loading = false;
      },
      error: (err) => {
        console.error('Error loading dashboard data:', err);
        this.loading = false;
      }
    });

    // Load threat reports
    this.apiService.getThreatReports().subscribe({
      next: (reports) => {
        this.stats.totalReports = reports.length;
      },
      error: (err) => {
        console.error('Error loading reports:', err);
      }
    });

    // Load vulnerability scans
    this.apiService.getVulnerabilityScans().subscribe({
      next: (scans) => {
        this.stats.totalScans = scans.length;
      },
      error: (err) => {
        console.error('Error loading scans:', err);
      }
    });
  }

  openNavigator(): void {
    // This will be triggered by the nav bar button
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
