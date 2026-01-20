/**
 * Authentication HTTP Interceptor
 *
 * Automatically attaches JWT tokens to outgoing requests
 * and handles authentication errors (401, 403).
 *
 * SECURITY: Centralizes auth header injection to prevent
 * accidental omission of authentication on API calls.
 */

import { Injectable, inject } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpErrorResponse,
  HTTP_INTERCEPTORS
} from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, filter, take, switchMap } from 'rxjs/operators';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { environment } from '@environments/environment';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<string | null> = new BehaviorSubject<string | null>(null);

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Skip auth header for Keycloak token requests
    if (request.url.includes('/openid-connect/token')) {
      return next.handle(request);
    }

    // Only add auth header to API requests
    if (this.isApiRequest(request.url)) {
      const token = this.authService.getAccessToken();
      if (token) {
        request = this.addAuthHeader(request, token);
      }
    }

    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          return this.handle401Error(request, next);
        } else if (error.status === 403) {
          return this.handle403Error(error);
        }
        return throwError(() => error);
      })
    );
  }

  /**
   * Add Authorization header to request
   */
  private addAuthHeader(request: HttpRequest<any>, token: string): HttpRequest<any> {
    return request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  /**
   * Check if request is to our API
   */
  private isApiRequest(url: string): boolean {
    return url.startsWith(environment.apiUrl) ||
           url.startsWith('/api/');
  }

  /**
   * Handle 401 Unauthorized errors
   * Attempts to refresh the token, or redirects to login
   */
  private handle401Error(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      const refreshToken = this.authService.getRefreshToken();
      if (refreshToken) {
        return this.authService.refreshToken().pipe(
          switchMap((response) => {
            this.isRefreshing = false;
            this.refreshTokenSubject.next(response.access_token);
            return next.handle(this.addAuthHeader(request, response.access_token));
          }),
          catchError((err) => {
            this.isRefreshing = false;
            this.handleAuthFailure();
            return throwError(() => err);
          })
        );
      } else {
        this.isRefreshing = false;
        this.handleAuthFailure();
        return throwError(() => new Error('No refresh token available'));
      }
    }

    // Wait for token refresh to complete
    return this.refreshTokenSubject.pipe(
      filter(token => token !== null),
      take(1),
      switchMap((token) => next.handle(this.addAuthHeader(request, token!)))
    );
  }

  /**
   * Handle 403 Forbidden errors
   */
  private handle403Error(error: HttpErrorResponse): Observable<never> {
    console.warn('Access forbidden:', error.message);
    // Don't redirect, let the component handle the error
    // This allows showing "insufficient permissions" messages
    return throwError(() => error);
  }

  /**
   * Handle authentication failure - logout and redirect to login
   */
  private handleAuthFailure(): void {
    this.authService.logout();
    const currentUrl = this.router.url;
    this.router.navigate(['/login'], {
      queryParams: {
        returnUrl: currentUrl,
        error: 'session_expired'
      }
    });
  }
}

/**
 * Provider for the auth interceptor
 */
export const authInterceptorProvider = {
  provide: HTTP_INTERCEPTORS,
  useClass: AuthInterceptor,
  multi: true
};
