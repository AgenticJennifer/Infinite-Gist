"""
Pydantic models for gists and scanning.
"""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SecretType(str, Enum):
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    SSH_PRIVATE_KEY = "ssh_private_key"
    PRIVATE_KEY = "private_key"
    API_KEY = "api_key"
    PASSWORD = "password"
    EMAIL = "email"
    CREDIT_CARD = "credit_card"
    SOCIAL_SECURITY = "social_security"


class GistBase(BaseModel):
    github_gist_id: str
    html_url: str
    git_pull_url: str
    git_push_url: str
    commits_url: str
    forks_url: str
    public: bool
    created_at: datetime
    updated_at: datetime
    description: Optional[str] = None
    comments: int = 0
    commits: int = 0


class GistCreate(GistBase):
    pass


class GistUpdate(BaseModel):
    html_url: Optional[str] = None
    git_pull_url: Optional[str] = None
    git_push_url: Optional[str] = None
    commits_url: Optional[str] = None
    forks_url: Optional[str] = None
    public: Optional[bool] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    description: Optional[str] = None
    comments: Optional[int] = None
    commits: Optional[int] = None


class GistInDBBase(GistBase):
    id: int
    user_id: int
    last_scanned_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class Gist(GistInDBBase):
    pass


class GistFileBase(BaseModel):
    filename: str
    type: Optional[str] = None
    language: Optional[str] = None
    raw_url: Optional[str] = None
    size: int = 0


class GistFileCreate(GistFileBase):
    pass


class GistFileUpdate(BaseModel):
    filename: Optional[str] = None
    type: Optional[str] = None
    language: Optional[str] = None
    raw_url: Optional[str] = None
    size: Optional[int] = None


class GistFileInDBBase(GistFileBase):
    id: int
    gist_id: int
    content: Optional[str] = None

    class Config:
        from_attributes = True


class GistFile(GistFileInDBBase):
    pass


class ScanResultBase(BaseModel):
    scan_type: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    secrets_found: int = 0
    files_scanned: int = 0
    error_message: Optional[str] = None


class ScanResultCreate(ScanResultBase):
    pass


class ScanResultUpdate(BaseModel):
    scan_type: Optional[str] = None
    status: Optional[ScanStatus] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    secrets_found: Optional[int] = None
    files_scanned: Optional[int] = None
    error_message: Optional[str] = None


class ScanResultInDBBase(ScanResultBase):
    id: int
    gist_id: int

    class Config:
        from_attributes = True


class ScanResult(ScanResultInDBBase):
    pass


class SecretMatchBase(BaseModel):
    secret_type: SecretType
    value: str
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    confidence: float
    matched_text: str
    context: str


class SecretMatchCreate(SecretMatchBase):
    pass


class SecretMatchUpdate(BaseModel):
    secret_type: Optional[SecretType] = None
    value: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    confidence: Optional[float] = None
    matched_text: Optional[str] = None
    context: Optional[str] = None


class SecretMatchInDBBase(SecretMatchBase):
    id: int
    gist_file_id: int
    scan_id: int

    class Config:
        from_attributes = True


class SecretMatch(SecretMatchInDBBase):
    pass


# Response models for API endpoints
class GistResponse(Gist):
    pass


class GistFileResponse(GistFile):
    pass


class ScanResultResponse(ScanResult):
    pass


class SecretMatchResponse(SecretMatch):
    pass


class ScanStatsResponse(BaseModel):
    gist_count: int
    scan_count: int
    completed_scan_count: int
    failed_scan_count: int
    secrets_count: int
    secrets_by_type: dict[str, int]


class ScanResponse(BaseModel):
    message: str
    github_account_id: int
    status: str


class GitHubAccountScanRequest(BaseModel):
    github_account_id: int


# ---- Phase 2: Credible Detection response schemas ----

class FindingResponse(BaseModel):
    id: int
    gist_id: int
    gist_file_id: Optional[int] = None
    gist_revision_id: Optional[int] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    content_snippet: Optional[str] = None
    finding_type: Optional[str] = None
    secret_type: Optional[str] = None
    severity: str
    confidence: int
    masked_value: Optional[str] = None
    value_hash: Optional[str] = None
    detected_at: Optional[datetime] = None
    status: str

    class Config:
        from_attributes = True


class CorrelationGroupResponse(BaseModel):
    value_hash: str
    finding_count: int
    severity: str
    secret_type: str
    gist_ids: List[int]
    first_detected: Optional[datetime] = None
    last_detected: Optional[datetime] = None


class TemporalEventResponse(BaseModel):
    timestamp: datetime
    event_type: str
    gist_id: int
    finding_id: Optional[int] = None
    details: Optional[str] = None


class TemporalAnalysisResponse(BaseModel):
    gist_id: int
    total_events: int
    re_exposure_count: int
    persistence_count: int
    posture_trend: str
    events: List[TemporalEventResponse]
    first_detected: Optional[datetime] = None
    last_detected: Optional[datetime] = None


class FindingStatsResponse(BaseModel):
    total_findings: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
    by_status: dict[str, int]
    average_confidence: float


# ---- Phase 3: Triage Service response schemas ----
class TriageRequest(BaseModel):
    finding_ids: List[int]


class TriageResult(BaseModel):
    finding_id: int
    verdict: str
    confidence: float
    reason: str


class TriageBatchResponse(BaseModel):
    message: str
    findings_count: int
    triage_results: List[TriageResult]


class TriageStatusResponse(BaseModel):
    pending_findings: int
    pending_by_confidence: dict[str, int]
    auto_accepted: int
    auto_rejected: int
    triage_thresholds: dict[str, str]


class TriageVerdictUpdate(BaseModel):
    finding_id: int
    verdict: str


# ---- Phase 3: Evidence Masker response schemas ----
class EvidenceMaskRequest(BaseModel):
    finding_id: int


class EvidenceMaskResponse(BaseModel):
    finding_id: int
    original_value_hash: str
    masked_value: str
    mask_type: str
    masked_at: datetime


# ---- Phase 3: TruffleHog Scanner response schemas ----
class TruffleHogScanRequest(BaseModel):
    github_account_id: int
    scan_type: str = "full"


class TruffleHogScanResponse(BaseModel):
    message: str
    github_account_id: int
    scan_type: str
    status: str
    scan_id: Optional[int] = None


class TruffleHogStatusResponse(BaseModel):
    binary_available: bool
    binary_path: Optional[str] = None
    version: Optional[str] = None
    supported_scan_types: List[str]
    config: dict


class RemediationRequest(BaseModel):
    finding_id: int


class RemediationResponse(BaseModel):
    id: int
    action_type: str
    status: str
    finding_id: int
    requested_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    verified: bool = False
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class RemediationHistoryResponse(BaseModel):
    actions: List[RemediationResponse]
    total: int