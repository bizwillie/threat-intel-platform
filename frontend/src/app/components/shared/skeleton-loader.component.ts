/**
 * Reusable Skeleton Loader Component
 */

import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-skeleton-loader',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="skeleton" [ngClass]="type" [style.height.px]="height" [style.width]="width"></div>
  `,
  styles: [`
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

    .skeleton.text {
      height: 1em;
      margin-bottom: 0.5em;
    }

    .skeleton.title {
      height: 1.5em;
      margin-bottom: 0.5em;
    }

    .skeleton.card {
      height: 120px;
      width: 100%;
    }

    .skeleton.stat-card {
      height: 100px;
      width: 100%;
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
  `]
})
export class SkeletonLoaderComponent {
  @Input() type: 'text' | 'title' | 'card' | 'stat-card' | 'avatar' | 'button' | 'custom' = 'text';
  @Input() height: number = 20;
  @Input() width: string = '100%';
}
