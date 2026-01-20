/**
 * Toast Notification Component
 *
 * Displays toast notifications in the bottom-right corner of the screen.
 * Supports success, error, warning, and info message types.
 */

import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ToastService, Toast } from '../../../services/toast.service';

@Component({
  selector: 'app-toast',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="toast-container">
      @for (toast of toasts$ | async; track toast.id) {
        <div
          class="toast"
          [class.toast-success]="toast.type === 'success'"
          [class.toast-error]="toast.type === 'error'"
          [class.toast-warning]="toast.type === 'warning'"
          [class.toast-info]="toast.type === 'info'"
          (click)="dismiss(toast.id)"
        >
          <span class="toast-icon">
            @switch (toast.type) {
              @case ('success') { <span>&#10003;</span> }
              @case ('error') { <span>&#10007;</span> }
              @case ('warning') { <span>&#9888;</span> }
              @case ('info') { <span>&#8505;</span> }
            }
          </span>
          <span class="toast-message">{{ toast.message }}</span>
          <button class="toast-close" (click)="dismiss(toast.id); $event.stopPropagation()">
            &times;
          </button>
        </div>
      }
    </div>
  `,
  styles: [`
    .toast-container {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      max-width: 400px;
      pointer-events: none;
    }

    .toast {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 1rem 1.25rem;
      border-radius: 8px;
      background: var(--color-surface, #0f172a);
      border: 1px solid var(--color-border, #334155);
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(8px);
      color: var(--color-text-primary, #f8fafc);
      font-size: 0.875rem;
      cursor: pointer;
      pointer-events: auto;
      animation: slideIn 0.3s ease-out;
      transition: transform 0.2s ease, opacity 0.2s ease;
    }

    .toast:hover {
      transform: translateX(-4px);
    }

    @keyframes slideIn {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }

    .toast-icon {
      font-size: 1.25rem;
      flex-shrink: 0;
    }

    .toast-message {
      flex: 1;
      line-height: 1.4;
    }

    .toast-close {
      background: none;
      border: none;
      color: var(--color-text-secondary, #94a3b8);
      font-size: 1.25rem;
      cursor: pointer;
      padding: 0;
      line-height: 1;
      opacity: 0.7;
      transition: opacity 0.2s ease;
    }

    .toast-close:hover {
      opacity: 1;
    }

    /* Type-specific styles */
    .toast-success {
      border-left: 4px solid var(--color-success, #10b981);
    }

    .toast-success .toast-icon {
      color: var(--color-success, #10b981);
    }

    .toast-error {
      border-left: 4px solid var(--color-danger, #ef4444);
    }

    .toast-error .toast-icon {
      color: var(--color-danger, #ef4444);
    }

    .toast-warning {
      border-left: 4px solid var(--color-warning, #f59e0b);
    }

    .toast-warning .toast-icon {
      color: var(--color-warning, #f59e0b);
    }

    .toast-info {
      border-left: 4px solid var(--color-accent, #3b82f6);
    }

    .toast-info .toast-icon {
      color: var(--color-accent, #3b82f6);
    }
  `]
})
export class ToastComponent {
  private toastService = inject(ToastService);

  toasts$ = this.toastService.toasts$;

  dismiss(id: number): void {
    this.toastService.dismiss(id);
  }
}
