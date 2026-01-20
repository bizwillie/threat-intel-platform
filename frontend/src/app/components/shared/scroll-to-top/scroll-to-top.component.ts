/**
 * Scroll-to-Top Button Component
 *
 * Floating button that appears after scrolling 300px,
 * allowing users to quickly return to the top of the page.
 */

import { Component, HostListener, inject } from '@angular/core';
import { CommonModule, DOCUMENT } from '@angular/common';

@Component({
  selector: 'app-scroll-to-top',
  standalone: true,
  imports: [CommonModule],
  template: `
    <button
      *ngIf="isVisible"
      class="scroll-to-top-btn"
      (click)="scrollToTop()"
      aria-label="Scroll to top"
      title="Back to top"
    >
      <span class="arrow">↑</span>
    </button>
  `,
  styles: [`
    .scroll-to-top-btn {
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      width: 48px;
      height: 48px;
      border-radius: 50%;
      background: var(--color-accent);
      border: none;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      z-index: 1000;
      opacity: 0;
      transform: translateY(20px);
      animation: fadeInUp 0.3s ease forwards;
    }

    .scroll-to-top-btn:hover {
      background: #2563EB;
      transform: translateY(-4px);
      box-shadow: 0 8px 20px rgba(59, 130, 246, 0.5);
    }

    .scroll-to-top-btn:active {
      transform: translateY(-2px);
    }

    .scroll-to-top-btn:focus-visible {
      outline: 2px solid white;
      outline-offset: 2px;
    }

    .arrow {
      color: white;
      font-size: 1.5rem;
      font-weight: 600;
      line-height: 1;
    }

    @keyframes fadeInUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    /* Hide when not visible (for smooth exit) */
    :host:not(.visible) .scroll-to-top-btn {
      animation: fadeOutDown 0.3s ease forwards;
    }

    @keyframes fadeOutDown {
      from {
        opacity: 1;
        transform: translateY(0);
      }
      to {
        opacity: 0;
        transform: translateY(20px);
      }
    }
  `]
})
export class ScrollToTopComponent {
  private document = inject(DOCUMENT);

  isVisible = false;
  private scrollThreshold = 300;

  @HostListener('window:scroll')
  onWindowScroll(): void {
    const scrollPosition = window.pageYOffset ||
      this.document.documentElement.scrollTop ||
      this.document.body.scrollTop || 0;

    this.isVisible = scrollPosition > this.scrollThreshold;
  }

  scrollToTop(): void {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  }
}
