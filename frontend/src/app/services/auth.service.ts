/**
 * UTIP Authentication Service
 *
 * Handles JWT token management and Keycloak authentication.
 */

import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { tap, map } from 'rxjs/operators';
import { environment } from '@environments/environment';

export interface TokenResponse {
  access_token: string;
  expires_in: number;
  refresh_expires_in: number;
  refresh_token: string;
  token_type: string;
  session_state: string;
  scope: string;
}

export interface User {
  username: string;
  email: string;
  roles: string[];
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly tokenUrl = `${environment.keycloakUrl}/realms/${environment.keycloakRealm}/protocol/openid-connect/token`;
  private readonly userInfoUrl = `${environment.keycloakUrl}/realms/${environment.keycloakRealm}/protocol/openid-connect/userinfo`;

  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  // Check if auth is disabled (for simplified docker setup)
  private readonly authDisabled = (environment as any).authDisabled ?? false;

  constructor(private http: HttpClient) {
    // If auth is disabled, set a mock dev user
    if (this.authDisabled) {
      this.currentUserSubject.next({
        username: 'dev-user',
        email: 'dev@localhost',
        roles: ['analyst', 'admin', 'hunter']
      });
      return;
    }

    // Check for existing token on initialization
    if (this.getAccessToken()) {
      this.loadUserInfo();
    }
  }

  /**
   * Login with username and password
   */
  login(username: string, password: string): Observable<TokenResponse> {
    const body = new URLSearchParams();
    body.set('client_id', environment.keycloakClientId);
    body.set('grant_type', 'password');
    body.set('username', username);
    body.set('password', password);

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded'
    });

    return this.http.post<TokenResponse>(this.tokenUrl, body.toString(), { headers }).pipe(
      tap(response => {
        this.storeTokens(response);
        this.loadUserInfo();
      })
    );
  }

  /**
   * Refresh access token using refresh token
   */
  refreshToken(): Observable<TokenResponse> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const body = new URLSearchParams();
    body.set('client_id', environment.keycloakClientId);
    body.set('grant_type', 'refresh_token');
    body.set('refresh_token', refreshToken);

    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded'
    });

    return this.http.post<TokenResponse>(this.tokenUrl, body.toString(), { headers }).pipe(
      tap(response => {
        this.storeTokens(response);
      })
    );
  }

  /**
   * Logout and clear tokens
   */
  logout(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('token_expires_at');
    this.currentUserSubject.next(null);
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    // Always authenticated when auth is disabled
    if (this.authDisabled) {
      return true;
    }

    const token = this.getAccessToken();
    if (!token) {
      return false;
    }

    const expiresAt = localStorage.getItem('token_expires_at');
    if (!expiresAt) {
      return false;
    }

    return Date.now() < parseInt(expiresAt, 10);
  }

  /**
   * Get current access token
   */
  getAccessToken(): string | null {
    return localStorage.getItem('access_token');
  }

  /**
   * Get current refresh token
   */
  getRefreshToken(): string | null {
    return localStorage.getItem('refresh_token');
  }

  /**
   * Get current user
   */
  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }

  /**
   * Check if user has a specific role
   */
  hasRole(role: string): boolean {
    const user = this.getCurrentUser();
    return user ? user.roles.includes(role) : false;
  }

  /**
   * Decode JWT token to extract user information
   */
  private decodeToken(token: string): any {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
      return JSON.parse(jsonPayload);
    } catch (error) {
      console.error('Error decoding token:', error);
      return null;
    }
  }

  /**
   * Store tokens in localStorage
   */
  private storeTokens(response: TokenResponse): void {
    localStorage.setItem('access_token', response.access_token);
    localStorage.setItem('refresh_token', response.refresh_token);

    const expiresAt = Date.now() + (response.expires_in * 1000);
    localStorage.setItem('token_expires_at', expiresAt.toString());
  }

  /**
   * Load user information from token
   */
  private loadUserInfo(): void {
    const token = this.getAccessToken();
    if (!token) {
      return;
    }

    const decoded = this.decodeToken(token);
    if (decoded) {
      const user: User = {
        username: decoded.preferred_username || decoded.sub,
        email: decoded.email || '',
        roles: decoded.realm_access?.roles || []
      };
      this.currentUserSubject.next(user);
    }
  }
}
