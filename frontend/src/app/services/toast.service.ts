/**
 * Toast Notification Service
 *
 * Provides a centralized way to display toast notifications
 * throughout the application for success, error, warning, and info messages.
 */

import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: number;
  message: string;
  type: ToastType;
  duration: number;
}

@Injectable({
  providedIn: 'root'
})
export class ToastService {
  private toasts: Toast[] = [];
  private toastsSubject = new BehaviorSubject<Toast[]>([]);
  private nextId = 0;

  /** Observable of current toasts */
  toasts$: Observable<Toast[]> = this.toastsSubject.asObservable();

  /**
   * Show a success toast
   * @param message The message to display
   * @param duration Duration in milliseconds (default: 4000)
   */
  success(message: string, duration = 4000): void {
    this.show(message, 'success', duration);
  }

  /**
   * Show an error toast
   * @param message The message to display
   * @param duration Duration in milliseconds (default: 6000 for errors)
   */
  error(message: string, duration = 6000): void {
    this.show(message, 'error', duration);
  }

  /**
   * Show a warning toast
   * @param message The message to display
   * @param duration Duration in milliseconds (default: 5000)
   */
  warning(message: string, duration = 5000): void {
    this.show(message, 'warning', duration);
  }

  /**
   * Show an info toast
   * @param message The message to display
   * @param duration Duration in milliseconds (default: 4000)
   */
  info(message: string, duration = 4000): void {
    this.show(message, 'info', duration);
  }

  /**
   * Show a toast notification
   * @param message The message to display
   * @param type The type of toast (success, error, warning, info)
   * @param duration Duration in milliseconds before auto-dismiss
   */
  private show(message: string, type: ToastType, duration: number): void {
    const toast: Toast = {
      id: this.nextId++,
      message,
      type,
      duration
    };

    this.toasts = [...this.toasts, toast];
    this.toastsSubject.next(this.toasts);

    // Auto-dismiss after duration
    if (duration > 0) {
      setTimeout(() => {
        this.dismiss(toast.id);
      }, duration);
    }
  }

  /**
   * Dismiss a specific toast by ID
   * @param id The toast ID to dismiss
   */
  dismiss(id: number): void {
    this.toasts = this.toasts.filter(t => t.id !== id);
    this.toastsSubject.next(this.toasts);
  }

  /**
   * Dismiss all toasts
   */
  dismissAll(): void {
    this.toasts = [];
    this.toastsSubject.next(this.toasts);
  }
}
