/**
 * Reusable Skeleton Loader Component
 *
 * Enhanced to match actual content shapes for stats grid and layer cards.
 */

import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-skeleton-loader',
  standalone: true,
  imports: [CommonModule],
  template: `
    <!-- Simple skeleton for basic types -->
    <div *ngIf="!isComplex" class="skeleton" [ngClass]="type" [style.height.px]="height" [style.width]="width"></div>

    <!-- Stat card skeleton with icon + text layout -->
    <div *ngIf="type === 'stat-card'" class="skeleton-stat-card glass-card">
      <div class="stat-icon-skeleton skeleton"></div>
      <div class="stat-info-skeleton">
        <div class="stat-value-skeleton skeleton"></div>
        <div class="stat-label-skeleton skeleton"></div>
      </div>
    </div>

    <!-- Layer card skeleton with title + meta + button -->
    <div *ngIf="type === 'card'" class="skeleton-layer-card glass-card">
      <div class="layer-title-skeleton skeleton"></div>
      <div class="layer-meta-skeleton skeleton"></div>
      <div class="layer-meta-skeleton skeleton short"></div>
      <div class="layer-button-skeleton skeleton"></div>
    </div>
  `,
  styles: [`
    /* Base shimmer animation */
    .skeleton {
      background: linear-gradient(
        90deg,
        var(--color-surface) 25%,
        var(--color-surface-elevated) 50%,
        var(--color-surface) 75%
      );
      background-size: 200% 100%;
      animation: shimmer 1.5s ease-in-out infinite;
      border-radius: var(--radius-md);
    }

    @keyframes shimmer {
      0% { background-position: 200% 0; }
      100% { background-position: -200% 0; }
    }

    /* Simple types */
    .skeleton.text {
      height: 1em;
      margin-bottom: 0.5em;
    }

    .skeleton.title {
      height: 1.5em;
      margin-bottom: 0.5em;
    }

    .skeleton.avatar {
      border-radius: 50%;
      width: 40px;
      height: 40px;
    }

    .skeleton.button {
      height: 40px;
      width: 120px;
    }

    /* Stat Card Skeleton - matches actual stat-card layout */
    .skeleton-stat-card {
      display: flex;
      align-items: center;
      gap: var(--spacing-lg);
      padding: var(--spacing-lg);
      min-height: 100px;
    }

    .stat-icon-skeleton {
      width: 48px;
      height: 48px;
      border-radius: var(--radius-md);
      flex-shrink: 0;
    }

    .stat-info-skeleton {
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: var(--spacing-xs);
    }

    .stat-value-skeleton {
      height: 2.5rem;
      width: 80px;
      border-radius: var(--radius-sm);
    }

    .stat-label-skeleton {
      height: 0.875rem;
      width: 100px;
      border-radius: var(--radius-sm);
    }

    /* Layer Card Skeleton - matches actual layer-card layout */
    .skeleton-layer-card {
      padding: var(--spacing-lg);
      display: flex;
      flex-direction: column;
      gap: var(--spacing-sm);
      min-height: 140px;
    }

    .layer-title-skeleton {
      height: 1.125rem;
      width: 70%;
      border-radius: var(--radius-sm);
    }

    .layer-meta-skeleton {
      height: 0.875rem;
      width: 50%;
      border-radius: var(--radius-sm);
    }

    .layer-meta-skeleton.short {
      width: 35%;
    }

    .layer-button-skeleton {
      height: 32px;
      width: 60px;
      margin-top: var(--spacing-sm);
      border-radius: var(--radius-sm);
    }
  `]
})
export class SkeletonLoaderComponent {
  @Input() type: 'text' | 'title' | 'card' | 'stat-card' | 'avatar' | 'button' | 'custom' = 'text';
  @Input() height: number = 20;
  @Input() width: string = '100%';

  get isComplex(): boolean {
    return this.type === 'stat-card' || this.type === 'card';
  }
}
