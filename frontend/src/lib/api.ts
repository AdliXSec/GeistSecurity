export type AuditMode = 'HYBRID' | 'BLACKBOX' | 'WHITEBOX';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface AuditCreateRequest {
  project_name: string;
  mode: AuditMode;
  target_url?: string;
  github_repo_url?: string;
  branch?: string;
  entropy_threshold?: number;
  scan_depth?: 'Shallow' | 'Medium' | 'Deep';
  js_exposure?: boolean;
  enable_nuclei?: boolean;
  nuclei_profile?: 'quick' | 'full';
}

export interface AuditCreateResponse {
  session_id: string;
  status: string;
  stream_endpoint: string;
  report_endpoint: string;
  message: string;
}

export interface TargetInfo {
  target_url?: string;
  github_repo_url?: string;
  branch?: string;
  detected_tech_stack?: string[];
  ai_status_message?: string;
  entropy_threshold?: number;
  scan_depth?: 'Shallow' | 'Medium' | 'Deep';
  js_exposure?: boolean;
  enable_nuclei?: boolean;
  nuclei_profile?: 'quick' | 'full';
  nuclei_findings_count?: number;
}

export interface SummaryCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface PostureScore {
  score: number;
  max_score: number;
  grade: string;
  grade_label: string;
  summary_counts: SummaryCounts;
}

export interface FindingLocation {
  source_origin: string;
  path: string;
  line_start?: number;
  line_end?: number;
}

export interface CodePatch {
  language: string;
  original_code: string;
  patched_code: string;
}

export interface AIRemediation {
  model: string;
  risk_explanation: string;
  remediation_steps: string[];
  code_patch: CodePatch;
  warning?: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  category: string;
  severity: SeverityLevel;
  title: string;
  cwe_id: string;
  owasp_category: string;
  cvss_score: number;
  location: FindingLocation;
  redacted_code_snippet: string;
  evidence_metadata: Record<string, any>;
  ai_remediation: AIRemediation;
}

export interface OpenPortItem {
  port: number;
  service: string;
  status: string;
  risk: string;
}

export interface SSLSummaryItem {
  valid: boolean;
  days_left: number;
  issuer: string;
  protocol: string;
  redirect_https: boolean;
  expired: boolean;
}

export interface DetectedTechItem {
  name: string;
  version?: string;
  outdated: boolean;
  cve_count: number;
  cves: string[];
}

export interface SensitiveDirItem {
  path: string;
  status: number;
  risk: string;
  detail?: string;
  disallowed_routes?: string[];
}

export interface HtmlLeakItem {
  type?: string;
  snippet?: string;
  matched_keywords?: string[];
  line?: number;
  entropy?: number;
}

export interface JsAssetItem {
  url: string;
  filename: string;
  size_kb: number;
  discovered_endpoints: string[];
  secrets_found: number;
  sourcemap_exposed: boolean;
  sourcemap_url?: string | null;
  sub_chunks: string[];
}

export interface ReconSummary {
  open_ports: OpenPortItem[];
  ssl_summary?: SSLSummaryItem;
  detected_tech: DetectedTechItem[];
  sensitive_dirs: SensitiveDirItem[];
  html_leaks: HtmlLeakItem[];
  js_assets?: JsAssetItem[];
}

export interface AuditReport {
  session_id: string;
  project_name: string;
  mode: AuditMode;
  status: string;
  audited_at: string;
  duration_ms: number;
  target_info: TargetInfo;
  posture_score: PostureScore;
  findings: Finding[];
  recon_summary?: ReconSummary;
  ai_status_message?: string;
}

export interface AuditSummaryItem {
  session_id: string;
  project_name: string;
  mode: AuditMode;
  status: string;
  score: number;
  grade: string;
  grade_label: string;
  critical_count: number;
  high_count: number;
  target_url?: string;
  github_repo_url?: string;
  branch?: string;
  created_at: string;
  duration_ms: number;
}

// ------------------------------------------------------------------
//  User & Authentication Types
// ------------------------------------------------------------------

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: UserProfile;
}

export interface RegisterPayload {
  username: string;
  email: string;
  password: string;
  full_name?: string;
}

export interface LoginPayload {
  username_or_email: string;
  password: string;
}

function resolveApiBase(): string {
  const envUrl = (
    (import.meta.env.VITE_API_URL as string | undefined) ||
    (import.meta.env.VITE_BACKEND_URL as string | undefined) ||
    ''
  ).trim();

  if (!envUrl) {
    return '/api/v1';
  }

  const cleanUrl = envUrl.replace(/\/+$/, '');
  if (cleanUrl.endsWith('/api/v1')) {
    return cleanUrl;
  }
  if (cleanUrl.endsWith('/api')) {
    return `${cleanUrl}/v1`;
  }
  return `${cleanUrl}/api/v1`;
}

export const API_BASE = resolveApiBase();
const TOKEN_KEY = 'geist_auth_token';
const USER_KEY = 'geist_auth_user';

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getAuthHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = getStoredToken();
  const headers: Record<string, string> = { ...extra };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export function isAuthenticated(): boolean {
  return Boolean(getStoredToken());
}

export function getStoredUser(): UserProfile | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setStoredAuth(token: string, user: UserProfile): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch (err) {
    console.error('Failed to store auth session', err);
  }
}

export function clearStoredAuth(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch (err) {
    console.error('Failed to clear auth session', err);
  }
}

export async function loginUser(payload: LoginPayload): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: 'Authentication failed' }));
    throw new Error(errorData.detail || 'Invalid username or password');
  }

  const data: AuthResponse = await res.json();
  setStoredAuth(data.access_token, data.user);
  return data;
}

export async function registerUser(payload: RegisterPayload): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: 'Registration failed' }));
    throw new Error(errorData.detail || 'Failed to create user account');
  }

  const data: AuthResponse = await res.json();
  setStoredAuth(data.access_token, data.user);
  return data;
}

export async function getCurrentUser(): Promise<UserProfile | null> {
  const token = getStoredToken();
  if (!token) return null;
  try {
    const res = await fetch(`${API_BASE}/auth/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (!res.ok) {
      clearStoredAuth();
      return null;
    }
    const user: UserProfile = await res.json();
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    return user;
  } catch {
    return getStoredUser();
  }
}

export async function createAudit(payload: AuditCreateRequest): Promise<AuditCreateResponse> {
  const res = await fetch(`${API_BASE}/audits`, {
    method: 'POST',
    headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: 'Failed to create audit session' }));
    throw new Error(errorData.detail || `HTTP Error ${res.status}`);
  }

  return res.json();
}

export async function getAuditReport(sessionId: string): Promise<AuditReport> {
  const res = await fetch(`${API_BASE}/audits/${sessionId}/report`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch audit report: ${res.statusText}`);
  }
  return res.json();
}

export async function getAuditsList(): Promise<AuditSummaryItem[]> {
  try {
    const res = await fetch(`${API_BASE}/audits`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) return [];
    return await res.json();
  } catch (err) {
    console.warn('Backend audit list unreachable, fallback to local data', err);
    return [];
  }
}

export async function deleteAudit(sessionId: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/audits/${sessionId}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to delete audit: ${res.statusText}`);
  }
  return res.json();
}

export async function batchDeleteAudits(sessionIds: string[]): Promise<{ success: boolean; deleted_count: number; message: string }> {
  const res = await fetch(`${API_BASE}/audits/batch-delete`, {
    method: 'POST',
    headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ session_ids: sessionIds }),
  });
  if (!res.ok) {
    throw new Error(`Failed to batch delete audits: ${res.statusText}`);
  }
  return res.json();
}
