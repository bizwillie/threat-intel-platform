/**
 * UTIP Remediation Sidebar Component
 *
 * Displays actionable remediation guidance for a selected technique
 * including MITRE Mitigations, CIS Controls, Detection Rules, and
 * hardening guidance.
 *
 * SECURITY: Uses takeUntilDestroyed to prevent memory leaks.
 */

import { Component, Input, Output, EventEmitter, OnInit, inject, OnChanges, DestroyRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiService, TechniqueRemediation } from '../../services/api.service';

export type RemediationTab = 'mitigations' | 'detection' | 'hardening';

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
  private destroyRef = inject(DestroyRef);

  remediation: TechniqueRemediation | null = null;
  loading = false;
  error = '';

  // Tab state
  activeTab: RemediationTab = 'mitigations';

  // Tab definitions with counts
  get tabs() {
    const mitigationCount = (this.remediation?.mitigations?.length || 0) +
                            (this.remediation?.cis_controls?.length || 0);
    const detectionCount = this.remediation?.detection_rules?.length || 0;
    const hardeningCount = this.remediation?.hardening_guidance ? 1 : 0;

    return [
      { id: 'mitigations' as RemediationTab, label: 'Mitigations', icon: '🛡️', count: mitigationCount },
      { id: 'detection' as RemediationTab, label: 'Detection', icon: '🔍', count: detectionCount },
      { id: 'hardening' as RemediationTab, label: 'Hardening', icon: '🔒', count: hardeningCount }
    ];
  }

  setActiveTab(tab: RemediationTab): void {
    this.activeTab = tab;
  }

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

    this.apiService.getTechniqueRemediation(this.techniqueId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
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
