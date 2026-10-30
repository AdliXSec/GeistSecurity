from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class AuditMode(str, Enum):
    HYBRID = "HYBRID"
    BLACKBOX = "BLACKBOX"
    WHITEBOX = "WHITEBOX"

class AuditStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AuditCreateRequest(BaseModel):
    project_name: str = Field(..., description="Nama proyek yang diaudit")
    mode: AuditMode = Field(default=AuditMode.HYBRID, description="Mode audit: HYBRID, BLACKBOX, atau WHITEBOX")
    target_url: Optional[str] = Field(None, description="URL target untuk pengujian blackbox DAST")
    github_repo_url: Optional[str] = Field(None, description="URL repositori GitHub untuk pengujian whitebox SAST")
    branch: Optional[str] = Field(default="main", description="Nama branch Git target")
    entropy_threshold: Optional[float] = Field(default=4.2, ge=1.0, le=8.0, description="Batas ambang Shannon Entropy H(X)")
    scan_depth: Optional[str] = Field(default="Deep", description="Kedalaman scan: Shallow, Medium, atau Deep")
    js_exposure: Optional[bool] = Field(default=True, description="Aktifkan ekstraksi dan deobfuscation asset JS")
    enable_nuclei: Optional[bool] = Field(default=True, description="Aktifkan Nuclei scanner berbasis curated templates")
    nuclei_profile: Optional[str] = Field(default="quick", description="Profil Nuclei: quick atau full")
    auth_headers: Optional[Dict[str, str]] = Field(default=None, description="Header kustom/autentikasi (mis. Authorization: Bearer <token>)")
    auth_cookies: Optional[Dict[str, str]] = Field(default=None, description="Cookie autentikasi/sesi (mis. session=xxx; token=yyy)")
    auth_token: Optional[str] = Field(default=None, description="Token bearer atau API key opsional (otomatis disuntikkan ke Authorization header)")
    auth_cookie_string: Optional[str] = Field(default=None, description="String cookie mentah opsional (mis. session_id=abc; jwt=xyz)")

class AuditCreateResponse(BaseModel):
    session_id: str
    status: AuditStatus
    stream_endpoint: str
    report_endpoint: str
    message: str

class SSEEventData(BaseModel):
    stage: str
    progress: int
    message: str
    timestamp: str
    redirect_report_url: Optional[str] = None

class TargetInfo(BaseModel):
    target_url: Optional[str] = None
    github_repo_url: Optional[str] = None
    branch: Optional[str] = "main"
    detected_tech_stack: List[str] = []
    ai_status_message: Optional[str] = None
    entropy_threshold: Optional[float] = 4.2
    scan_depth: Optional[str] = "Deep"
    js_exposure: Optional[bool] = True
    auth_headers: Optional[Dict[str, str]] = None
    auth_cookies: Optional[Dict[str, str]] = None
    enable_nuclei: Optional[bool] = True
    nuclei_profile: Optional[str] = "quick"
    nuclei_findings_count: Optional[int] = 0

class SummaryCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class PostureScore(BaseModel):
    score: int
    max_score: int = 100
    grade: str
    grade_label: str
    summary_counts: SummaryCounts

class FindingLocation(BaseModel):
    source_origin: str
    path: str
    line_start: Optional[int] = 1
    line_end: Optional[int] = 1

class CodePatch(BaseModel):
    language: str
    original_code: str
    patched_code: str

class AIRemediation(BaseModel):
    model: str
    risk_explanation: str
    remediation_steps: List[str]
    code_patch: CodePatch
    warning: Optional[str] = None

class Finding(BaseModel):
    id: str
    rule_id: str
    category: str
    severity: SeverityLevel
    title: str
    cwe_id: str
    owasp_category: str
    cvss_score: float
    location: FindingLocation
    redacted_code_snippet: str
    evidence_metadata: Dict[str, Any]
    ai_remediation: AIRemediation

class OpenPortItem(BaseModel):
    port: int
    service: str
    status: str = "OPEN"
    risk: str = "INFO"

class SSLSummaryItem(BaseModel):
    valid: bool = True
    days_left: int = 0
    issuer: str = ""
    protocol: str = "TLSv1.3"
    redirect_https: bool = True
    expired: bool = False

class DetectedTechItem(BaseModel):
    name: str
    version: Optional[str] = None
    outdated: bool = False
    cve_count: int = 0
    cves: List[str] = []

class SensitiveDirItem(BaseModel):
    path: str
    status: int = 200
    risk: str = "INFO"
    detail: Optional[str] = None
    disallowed_routes: List[str] = []

class JsAssetItem(BaseModel):
    url: str
    filename: str
    size_kb: float = 0.0
    discovered_endpoints: List[str] = []
    secrets_found: int = 0
    sourcemap_exposed: bool = False
    sourcemap_url: Optional[str] = None
    sub_chunks: List[str] = []

class ParameterItem(BaseModel):
    name: str
    param_type: str = "QUERY_STRING"
    endpoint: str = "/"
    risk_category: str = "STANDARD_INPUT"
    severity: str = "INFO"
    description: Optional[str] = None

class ReconSummary(BaseModel):
    open_ports: List[OpenPortItem] = []
    ssl_summary: Optional[SSLSummaryItem] = None
    detected_tech: List[DetectedTechItem] = []
    sensitive_dirs: List[SensitiveDirItem] = []
    html_leaks: List[Dict[str, Any]] = []
    js_assets: List[JsAssetItem] = []
    discovered_parameters: List[ParameterItem] = []

class AuditReportResponse(BaseModel):
    session_id: str
    project_name: str
    mode: AuditMode
    status: AuditStatus
    audited_at: str
    duration_ms: int
    target_info: TargetInfo
    posture_score: PostureScore
    findings: List[Finding]
    recon_summary: Optional[ReconSummary] = None
    ai_status_message: Optional[str] = None

class AuditSummaryItem(BaseModel):
    session_id: str
    project_name: str
    mode: AuditMode
    status: AuditStatus
    score: int
    grade: str
    grade_label: str
    created_at: str
    duration_ms: int
    critical_count: int
    high_count: int
    target_url: Optional[str] = None
    github_repo_url: Optional[str] = None
    branch: Optional[str] = "main"

class PatchSimulationRequest(BaseModel):
    patched_finding_ids: List[str]

class PatchSimulationResponse(BaseModel):
    old_score: int
    old_grade: str
    new_score: int
    new_grade: str
    new_grade_label: str
    score_delta: int
    resolved_count: int
    remaining_critical: int
    remaining_high: int
    remaining_medium: int
    remaining_low: int

class BatchDeleteRequest(BaseModel):
    session_ids: List[str]

class BatchDeleteResponse(BaseModel):
    success: bool
    deleted_count: int
    deleted_ids: List[str]
    message: str

# ====================================================================
#  Authentication Schemas
# ====================================================================

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username for security operator")
    email: str = Field(..., min_length=5, max_length=100, description="Work or personal email address")
    password: str = Field(..., min_length=6, max_length=100, description="Secure account password")
    full_name: Optional[str] = Field(None, max_length=100, description="Operator full name")

class UserLoginRequest(BaseModel):
    username_or_email: str = Field(..., description="Username or email address")
    password: str = Field(..., description="Account password")

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    created_at: str

class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class PresetCreateRequest(BaseModel):
    project_name: str = Field(..., max_length=150, description="Preset identifier name")
    mode: AuditMode = Field(default=AuditMode.HYBRID, description="Audit operation mode")
    url: Optional[str] = Field(default="", description="Target web application URL")
    repo: Optional[str] = Field(default="", description="Target GitHub repository URL")
    branch: Optional[str] = Field(default="main", description="Target Git branch")
    is_demo: Optional[bool] = Field(default=False, description="Flag indicating system demo preset")

class PresetResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    project_name: str
    mode: str
    url: Optional[str] = ""
    repo: Optional[str] = ""
    branch: Optional[str] = "main"
    is_demo: bool = False
    created_at: str
    updated_at: Optional[str] = None
