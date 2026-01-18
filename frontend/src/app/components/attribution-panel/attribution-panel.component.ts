/**
 * UTIP Attribution Panel Component
 *
 * Displays threat actor attribution for a layer with
 * confidence scores and matching techniques.
 */

import { Component, Input, Output, EventEmitter, OnInit, inject, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, AttributionResponse, Attribution } from '../../services/api.service';

@Component({
  selector: 'app-attribution-panel',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './attribution-panel.component.html',
  styleUrls: ['./attribution-panel.component.scss']
})
export class AttributionPanelComponent implements OnInit, OnChanges {
  @Input() layerId!: string;
  @Output() close = new EventEmitter<void>();

  private apiService = inject(ApiService);

  attribution: AttributionResponse | null = null;
  loading = false;
  error = '';

  ngOnInit(): void {
    this.loadAttribution();
  }

  ngOnChanges(): void {
    if (this.layerId) {
      this.loadAttribution();
    }
  }

  loadAttribution(): void {
    if (!this.layerId) {
      return;
    }

    this.loading = true;
    this.error = '';

    this.apiService.getAttribution(this.layerId).subscribe({
      next: (data) => {
        this.attribution = data;
        this.loading = false;
      },
      error: (err) => {
        console.error('Error loading attribution:', err);
        this.error = 'Failed to load threat actor attribution';
        this.loading = false;
      }
    });
  }

  getConfidenceColor(confidence: number): string {
    if (confidence >= 0.8) return 'var(--color-danger)';
    if (confidence >= 0.6) return 'var(--color-warning)';
    return 'var(--color-accent)';
  }

  getConfidenceLabel(confidence: number): string {
    if (confidence >= 0.8) return 'HIGH';
    if (confidence >= 0.6) return 'MEDIUM';
    return 'LOW';
  }

  onClose(): void {
    this.close.emit();
  }
}
