/**
 * UTIP Core API Service
 *
 * Handles all HTTP communication with the Core API backend.
 * Replaces localStorage with API-backed persistence.
 */

import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { environment } from '@environments/environment';

/**
 * Type Definitions for API Responses
 */

export interface TechniqueResponse {
  technique_id: string;
  name: string;
  description: string;
  tactic: string;
}

export interface ExtractedTechnique {
  id: string;
  report_id: string;
  technique_id: string;
  confidence: number;
  evidence: string;
  extraction_method: string;
  created_at: string;
}

export interface LayerTechnique {
  technique_id: string;
  color: string;
  confidence: number;
  from_intel: boolean;
  from_vuln: boolean;
}

export interface LayerBreakdown {
  red: number;
  yellow: number;
  blue: number;
}

export interface LayerStatistics {
  total_techniques: number;
  avg_confidence: number;
  intel_sources: number;
  vuln_sources: number;
}

export interface Layer {
  id: string;
  name: string;
  description?: string;
  created_by: string;
  created_at: string;
}

export interface LayerDetail extends Layer {
  techniques: LayerTechnique[];
  breakdown: LayerBreakdown;
  statistics: LayerStatistics;
}

export interface LayerGenerateRequest {
  name: string;
  description?: string;
  intel_reports: string[];
  vuln_scans: string[];
}

export interface LayerGenerateResponse {
  layer_id: string;
  name: string;
  breakdown: LayerBreakdown;
  statistics: LayerStatistics;
}

export interface ThreatActor {
  actor_id: string;
  name: string;
  description: string;
}

export interface Attribution {
  actor: ThreatActor;
  confidence: number;
  matching_techniques: string[];
  total_techniques: number;
  overlap_count: number;
}

export interface AttributionResponse {
  layer_id: string;
  attributions: Attribution[];
  total_layer_techniques: number;
}

export interface Mitigation {
  mitigation_id: string;
  name: string;
  description: string;
}

export interface CISControl {
  control_id: string;
  control: string;
  safeguard: string;
}

export interface DetectionRule {
  rule_name: string;
  description: string;
  log_source: string;
  detection: string;
}

export interface TechniqueRemediation {
  technique_id: string;
  mitigations: Mitigation[];
  cis_controls: CISControl[];
  detection_rules: DetectionRule[];
  hardening_guidance: string;
}

export interface ThreatReport {
  id: string;
  filename: string;
  source_type: string;
  status: string;
  uploaded_by: string;
  created_at: string;
}

export interface VulnerabilityScan {
  id: string;
  filename: string;
  scan_date: string;
  uploaded_by: string;
  created_at: string;
}

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private http = inject(HttpClient);
  private readonly apiUrl = environment.apiUrl;

  /**
   * Get authentication headers with JWT token
   */
  private getAuthHeaders(): HttpHeaders {
    const token = localStorage.getItem('access_token');
    return new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : ''
    });
  }

  /**
   * Handle HTTP errors
   */
  private handleError(error: any): Observable<never> {
    console.error('API Error:', error);
    return throwError(() => error);
  }

  // ==========================================
  // LAYER ENDPOINTS
  // ==========================================

  /**
   * Get all layers
   */
  getLayers(): Observable<Layer[]> {
    return this.http.get<Layer[]>(`${this.apiUrl}/layers`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get a specific layer with all techniques
   */
  getLayer(layerId: string): Observable<LayerDetail> {
    return this.http.get<LayerDetail>(`${this.apiUrl}/layers/${layerId}`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Generate a new layer from intel reports and vulnerability scans
   * TODO: Build layer generation UI - connect to layer creation form
   */
  generateLayer(request: LayerGenerateRequest): Observable<LayerGenerateResponse> {
    return this.http.post<LayerGenerateResponse>(`${this.apiUrl}/layers/generate`, request, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Delete a layer
   * TODO: Build layer deletion UI - add delete button to layer list/detail views
   */
  deleteLayer(layerId: string): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/layers/${layerId}`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  // ==========================================
  // THREAT INTEL ENDPOINTS
  // ==========================================

  /**
   * Upload a threat intelligence report
   * TODO: Build intel upload UI - create file upload component for threat reports
   */
  uploadIntelReport(file: File): Observable<{ report_id: string; status: string }> {
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('access_token');
    const headers = new HttpHeaders({
      'Authorization': token ? `Bearer ${token}` : ''
    });

    return this.http.post<{ report_id: string; status: string }>(
      `${this.apiUrl}/intel/upload`,
      formData,
      { headers }
    ).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get all threat reports
   */
  getThreatReports(): Observable<ThreatReport[]> {
    return this.http.get<ThreatReport[]>(`${this.apiUrl}/intel/reports`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get extracted techniques from a specific report
   * TODO: Build report details UI - show techniques extracted from each report
   */
  getReportTechniques(reportId: string): Observable<ExtractedTechnique[]> {
    return this.http.get<ExtractedTechnique[]>(`${this.apiUrl}/intel/reports/${reportId}/techniques`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  // ==========================================
  // VULNERABILITY ENDPOINTS
  // ==========================================

  /**
   * Upload a Nessus vulnerability scan
   * TODO: Build vuln upload UI - create file upload component for Nessus scans
   */
  uploadVulnerabilityScan(file: File): Observable<{ scan_id: string; vulnerabilities_found: number }> {
    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('access_token');
    const headers = new HttpHeaders({
      'Authorization': token ? `Bearer ${token}` : ''
    });

    return this.http.post<{ scan_id: string; vulnerabilities_found: number }>(
      `${this.apiUrl}/vuln/upload`,
      formData,
      { headers }
    ).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get all vulnerability scans
   */
  getVulnerabilityScans(): Observable<VulnerabilityScan[]> {
    return this.http.get<VulnerabilityScan[]>(`${this.apiUrl}/vuln/scans`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get techniques mapped from a specific vulnerability scan
   * TODO: Build scan details UI - show CVE-to-technique mappings per scan
   */
  getScanTechniques(scanId: string): Observable<TechniqueResponse[]> {
    return this.http.get<TechniqueResponse[]>(`${this.apiUrl}/vuln/scans/${scanId}/techniques`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  // ==========================================
  // ATTRIBUTION ENDPOINTS
  // ==========================================

  /**
   * Get threat actor attribution for a layer
   */
  getAttribution(layerId: string): Observable<AttributionResponse> {
    return this.http.post<AttributionResponse>(
      `${this.apiUrl}/attribution`,
      { layer_id: layerId },
      { headers: this.getAuthHeaders() }
    ).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get all threat actors
   * TODO: Build actors list UI - create threat actor directory/browser
   */
  getThreatActors(): Observable<ThreatActor[]> {
    return this.http.get<ThreatActor[]>(`${this.apiUrl}/attribution/actors`, {
      headers: this.getAuthHeaders()
    }).pipe(
      catchError(this.handleError)
    );
  }

  // ==========================================
  // REMEDIATION ENDPOINTS
  // ==========================================

  /**
   * Get remediation guidance for a specific technique
   */
  getTechniqueRemediation(techniqueId: string): Observable<TechniqueRemediation> {
    return this.http.get<TechniqueRemediation>(
      `${this.apiUrl}/remediation/techniques/${techniqueId}`,
      { headers: this.getAuthHeaders() }
    ).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get comprehensive remediation for all techniques in a layer
   * TODO: Build layer remediation UI - comprehensive remediation report view
   */
  getLayerRemediation(layerId: string): Observable<any> {
    return this.http.get<any>(
      `${this.apiUrl}/remediation/layers/${layerId}`,
      { headers: this.getAuthHeaders() }
    ).pipe(
      catchError(this.handleError)
    );
  }

  /**
   * Get remediation coverage statistics
   * TODO: Build coverage dashboard UI - remediation coverage metrics/charts
   */
  getRemediationCoverage(): Observable<any> {
    return this.http.get<any>(
      `${this.apiUrl}/remediation/coverage`,
      { headers: this.getAuthHeaders() }
    ).pipe(
      catchError(this.handleError)
    );
  }

  // ==========================================
  // HEALTH CHECK
  // ==========================================

  /**
   * Health check endpoint
   * TODO: Build health status indicator - show API connectivity status in UI
   */
  healthCheck(): Observable<any> {
    return this.http.get(`${this.apiUrl.replace('/api/v1', '')}/health`).pipe(
      catchError(this.handleError)
    );
  }
}
