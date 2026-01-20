/**
 * Enhanced Search Input Component
 *
 * Features:
 * - Magnifying glass icon
 * - Clear (X) button when has value
 * - Keyboard shortcuts (Escape to clear)
 */

import { Component, Input, Output, EventEmitter, forwardRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, ControlValueAccessor, NG_VALUE_ACCESSOR } from '@angular/forms';

@Component({
  selector: 'app-search-input',
  standalone: true,
  imports: [CommonModule, FormsModule],
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => SearchInputComponent),
      multi: true
    }
  ],
  template: `
    <div class="search-wrapper" [class.focused]="isFocused">
      <span class="search-icon">🔍</span>
      <input
        type="search"
        [placeholder]="placeholder"
        [(ngModel)]="value"
        (ngModelChange)="onValueChange($event)"
        (focus)="isFocused = true"
        (blur)="isFocused = false"
        (keydown.escape)="clear()"
        class="search-field"
        [attr.aria-label]="placeholder"
      >
      <button
        *ngIf="value"
        class="clear-btn"
        (click)="clear()"
        type="button"
        aria-label="Clear search"
        title="Clear"
      >
        ✕
      </button>
    </div>
  `,
  styles: [`
    .search-wrapper {
      position: relative;
      display: flex;
      align-items: center;
      background: var(--color-surface-elevated);
      border: 1px solid var(--color-border);
      border-radius: var(--radius-md);
      transition: all 0.2s ease;
      overflow: hidden;
    }

    .search-wrapper.focused {
      border-color: var(--color-accent);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }

    .search-icon {
      padding-left: var(--spacing-md);
      font-size: 0.875rem;
      opacity: 0.6;
      pointer-events: none;
    }

    .search-field {
      flex: 1;
      background: transparent;
      border: none;
      padding: var(--spacing-sm) var(--spacing-md);
      color: var(--color-text-primary);
      font-size: 0.875rem;
      min-width: 150px;
      outline: none;
    }

    .search-field::placeholder {
      color: var(--color-text-tertiary);
    }

    /* Hide default search cancel button */
    .search-field::-webkit-search-cancel-button {
      -webkit-appearance: none;
      appearance: none;
    }

    .clear-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 24px;
      height: 24px;
      margin-right: var(--spacing-sm);
      background: var(--color-surface);
      border: none;
      border-radius: 50%;
      color: var(--color-text-secondary);
      font-size: 0.75rem;
      cursor: pointer;
      transition: all 0.2s ease;
      flex-shrink: 0;
    }

    .clear-btn:hover {
      background: var(--color-border);
      color: var(--color-text-primary);
    }

    .clear-btn:focus-visible {
      outline: 2px solid var(--color-accent);
      outline-offset: 1px;
    }
  `]
})
export class SearchInputComponent implements ControlValueAccessor {
  @Input() placeholder = 'Search...';
  @Output() searchChange = new EventEmitter<string>();

  value = '';
  isFocused = false;

  private onChange: (value: string) => void = () => {};
  private onTouched: () => void = () => {};

  onValueChange(value: string): void {
    this.value = value;
    this.onChange(value);
    this.searchChange.emit(value);
  }

  clear(): void {
    this.value = '';
    this.onChange('');
    this.searchChange.emit('');
  }

  // ControlValueAccessor implementation
  writeValue(value: string): void {
    this.value = value || '';
  }

  registerOnChange(fn: (value: string) => void): void {
    this.onChange = fn;
  }

  registerOnTouched(fn: () => void): void {
    this.onTouched = fn;
  }
}
