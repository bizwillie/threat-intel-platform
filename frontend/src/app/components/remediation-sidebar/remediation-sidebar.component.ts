/**
 * UTIP Remediation Sidebar Component
 *
 * Displays actionable remediation guidance for a selected technique
 * including MITRE Mitigations, CIS Controls, Detection Rules, and
 * hardening guidance.
 */

import { Component, Input, Output, EventEmitter, OnInit, inject, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, TechniqueRemediation } from '../../services/api.service';

@Component({
  selector: 'app-remediation-sidebar',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './remediation-sidebar.component.html',
  styleUrls: ['./remediation-sidebar.component.scss']
})
export class RemediationSidebarComponent implements OnInit, OnChanges {
  @Input() techniqueId!: string;
  @Output() close = new EventEmitter<void>();

  private apiService = inject(ApiService);

  remediation: TechniqueRemediation | null = null;
  loading = false;
  error = '';

  ngOnInit(): void {
    this.loadRemediation();
  }

  ngOnChanges(): void {
    if (this.techniqueId) {
      this.loadRemediation();
    }
  }

  loadRemediation(): void {
    if (!this.techniqueId) {
      return;
    }

    this.loading = true;
    this.error = '';

    this.apiService.getTechniqueRemediation(this.techniqueId).subscribe({
      next: (data) => {
        this.remediation = data;
        this.loading = false;
      },
      error: (err) => {
        console.error('Error loading remediation:', err);
        if (err.status === 404) {
          this.error = `No remediation guidance available for technique ${this.techniqueId}`;
        } else {
          this.error = 'Failed to load remediation guidance';
        }
        this.loading = false;
      }
    });
  }

  onClose(): void {
    this.close.emit();
  }
}
