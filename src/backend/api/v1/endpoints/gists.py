"""
Endpoints for managing GitHub gists and scanning for secrets.
"""

from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.db.models import (
    Finding,
    FindingStatus,
    Gist,
    GistFile,
    GitHubAccount,
    ScanResult,
    SeverityLevel,
    User,
)
from src.backend.db.session import get_db
from src.backend.schemas.gists import (
    CorrelationGroupResponse,
    FindingResponse,
    FindingStatsResponse,
    GistFileResponse,
    GistResponse,
    ScanResponse,
    ScanResultResponse,
    TemporalAnalysisResponse,
    TemporalEventResponse,
)
from src.backend.services.evidence_masker import EvidenceMasker
from src.backend.services.finding_correlator import FindingCorrelator
from src.backend.services.gist_scanner import scan_github_account
from src.backend.services.secret_scanner import SecretMatch, SecretType
from src.backend.services.temporal_analyzer import TemporalAnalyzer
from src.backend.services.triage_service import TriageService
from src.backend.services.trufflehog_scanner import TruffleHogScanner

# Module-level service instances for endpoint mocking
triage_service = TriageService()
evidence_masker = EvidenceMasker()


def correlation_analyzer(db=None):
    return FindingCorrelator(db)


router = APIRouter()


def _enum_to_str(value) -> str:
    """Convert an enum (or already-str value) to its string form for API responses."""
    return value.value if hasattr(value, "value") else str(value)


# Triage confidence thresholds — single source of truth for the status endpoint
# response and the pending-by-confidence query.
TRIAGE_THRESHOLDS = {
    "auto_triage": 0.75,
    "manual_review": 0.35,
    "escalation": 0.90,
}


@router.post("/scan/account/{github_account_id}", response_model=ScanResponse)
async def scan_github_account_endpoint(
    github_account_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    github_account = (
        db.query(GitHubAccount)
        .filter(GitHubAccount.id == github_account_id)
        .filter(GitHubAccount.user_id == current_user.id)
        .first()
    )

    if not github_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="GitHub account not found or access denied",
        )

    background_tasks.add_task(scan_github_account, github_account_id)

    return ScanResponse(
        message="Scan initiated successfully",
        github_account_id=github_account_id,
        status="started",
    )


@router.get("/scans", response_model=List[ScanResultResponse])
async def get_scan_results(
    skip: int = 0,
    limit: int = 100,
    gist_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    query = db.query(ScanResult).join(Gist).filter(Gist.user_id == current_user.id)

    if gist_id:
        query = query.filter(ScanResult.gist_id == gist_id)

    return query.offset(skip).limit(limit).all()


@router.get("/scans/{scan_id}", response_model=ScanResultResponse)
async def get_scan_result(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(ScanResult)
        .join(Gist)
        .filter(ScanResult.id == scan_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    return scan


@router.get("/gists", response_model=List[GistResponse])
async def get_user_gists(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    return (
        db.query(Gist)
        .filter(Gist.user_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/gists/{gist_id}", response_model=GistResponse)
async def get_gist(
    gist_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    gist = (
        db.query(Gist)
        .filter(Gist.id == gist_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not gist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Gist not found"
        )

    return gist


@router.get("/gists/{gist_id}/files", response_model=List[GistFileResponse])
async def get_gist_files(
    gist_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    gist = (
        db.query(Gist)
        .filter(Gist.id == gist_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not gist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Gist not found"
        )

    return db.query(GistFile).filter(GistFile.gist_id == gist_id).all()


@router.get("/gists/{gist_id}/findings", response_model=List[FindingResponse])
async def get_gist_findings(
    gist_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    gist = (
        db.query(Gist)
        .filter(Gist.id == gist_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not gist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Gist not found"
        )

    findings = db.query(Finding).filter(Finding.gist_id == gist_id).all()
    return [_finding_to_response(f) for f in findings]


@router.get("/gists/{gist_id}/temporal", response_model=TemporalAnalysisResponse)
async def get_temporal_analysis(
    gist_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    gist = (
        db.query(Gist)
        .filter(Gist.id == gist_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not gist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Gist not found"
        )

    analyzer = TemporalAnalyzer()
    analysis = analyzer.analyze_gist_history(gist_id, db)
    posture = analyzer.analyze_user_posture(current_user.id, db)

    first_detected = min(analysis.first_seen.values(), default=None)
    last_detected = max(analysis.last_seen.values(), default=None)

    return TemporalAnalysisResponse(
        gist_id=gist_id,
        total_events=len(analysis.events),
        re_exposure_count=len(analysis.re_exposures),
        persistence_count=sum(analysis.persistence_counts.values()),
        posture_trend=posture["findings_trend"],
        events=[
            TemporalEventResponse(
                timestamp=e.timestamp,
                event_type=e.event_type,
                gist_id=e.gist_id,
                finding_id=e.finding_id,
                details=e.severity,
            )
            for e in analysis.events
        ],
        first_detected=first_detected,
        last_detected=last_detected,
    )


@router.get("/findings", response_model=List[FindingResponse])
async def get_all_findings(
    skip: int = 0,
    limit: int = 100,
    secret_type: Optional[str] = None,
    min_confidence: int = 0,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    query = db.query(Finding).join(Gist).filter(Gist.user_id == current_user.id)

    if secret_type:
        query = query.filter(Finding.secret_type == secret_type)

    if min_confidence > 0:
        query = query.filter(Finding.confidence >= min_confidence)

    if severity:
        try:
            sev_enum = SeverityLevel(severity)
            query = query.filter(Finding.severity == sev_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}",
            )

    findings = query.offset(skip).limit(limit).all()
    return [_finding_to_response(f) for f in findings]


@router.get("/findings/stats", response_model=FindingStatsResponse)
async def get_finding_stats(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    # Use a subquery to filter findings by user's gists in a single query
    # This avoids N+1 pattern of fetching all gist IDs first
    user_gist_ids = select(Gist.id).where(Gist.user_id == current_user.id)
    base_q = db.query(Finding).filter(Finding.gist_id.in_(user_gist_ids))

    total = base_q.count()

    if total == 0:
        return FindingStatsResponse(
            total_findings=0,
            by_severity={},
            by_type={},
            by_status={},
            average_confidence=0.0,
        )

    by_severity = {
        str(sev): cnt
        for sev, cnt in base_q.with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    }
    by_type = {
        str(t): cnt
        for t, cnt in base_q.with_entities(Finding.secret_type, func.count(Finding.id))
        .group_by(Finding.secret_type)
        .all()
        if t
    }
    by_status = {
        str(s): cnt
        for s, cnt in base_q.with_entities(Finding.status, func.count(Finding.id))
        .group_by(Finding.status)
        .all()
    }
    avg_conf = (
        base_q.with_entities(func.avg(Finding.confidence.cast(func.Float()))).scalar()
        or 0.0
    )

    return FindingStatsResponse(
        total_findings=total,
        by_severity=by_severity,
        by_type=by_type,
        by_status=by_status,
        average_confidence=round(avg_conf, 2),
    )


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    return _finding_to_response(finding)


@router.put("/findings/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: int,
    new_status: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    try:
        finding.status = FindingStatus(new_status)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status: {new_status}",
        )

    db.add(finding)
    db.commit()
    db.refresh(finding)
    return _finding_to_response(finding)


@router.put("/findings/{finding_id}/ignore", response_model=FindingResponse)
async def ignore_finding(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found"
        )

    finding.status = FindingStatus.FALSE_POSITIVE
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return _finding_to_response(finding)


@router.get("/correlations", response_model=List[CorrelationGroupResponse])
def get_correlations(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    correlator = FindingCorrelator(db)
    groups = correlator.find_correlations(user_id=current_user.id)

    return [
        CorrelationGroupResponse(
            value_hash=g.value_hash,
            finding_count=g.finding_count,
            severity=_enum_to_str(g.severity),
            secret_type=g.secret_type or "unknown",
            gist_ids=g.gist_ids,
            first_detected=g.first_detected,
            last_detected=g.last_detected,
        )
        for g in groups
    ]


@router.get(
    "/findings/{finding_id}/correlations", response_model=List[CorrelationGroupResponse]
)
def get_finding_correlations(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    # Verify finding belongs to user
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found or access denied",
        )

    correlator = FindingCorrelator(db)
    groups = correlator.find_correlations(
        finding_id=finding_id, user_id=current_user.id
    )

    return [
        CorrelationGroupResponse(
            value_hash=g.value_hash,
            finding_count=g.finding_count,
            severity=_enum_to_str(g.severity),
            secret_type=g.secret_type or "unknown",
            gist_ids=g.gist_ids,
            first_detected=g.first_detected,
            last_detected=g.last_detected,
        )
        for g in groups
    ]


@router.get("/correlations/insights", response_model=dict)
def get_correlation_insights(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    analyzer = FindingCorrelator(db)
    insights = analyzer.identify_correlation_patterns(user_id=current_user.id)

    return {
        "total_correlated_findings": insights.get("total_related_findings", 0),
        "active_correlation_campaigns": insights.get("total_related_findings", 0),
        "dominant_secret_types": insights.get("patterns", {}).get(
            "dominant_secret_types", {}
        ),
        "risk_distribution": insights.get("patterns", {}).get(
            "severity_distribution", {}
        ),
        "multi_gist_patterns": insights.get("cross_gist_patterns", {}),
    }


@router.post("/triage", response_model=dict)
async def triage_findings_endpoint(
    finding_ids: List[int],
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    # Input validation: prevent DoS via large batches
    MAX_TRIAGE_BATCH_SIZE = 100
    if len(finding_ids) > MAX_TRIAGE_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {len(finding_ids)} exceeds maximum of {MAX_TRIAGE_BATCH_SIZE}",
        )

    if not finding_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="finding_ids list cannot be empty",
        )

    # Verify all findings belong to user
    findings = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id.in_(finding_ids))
        .filter(Gist.user_id == current_user.id)
        .all()
    )

    if len(findings) != len(finding_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Some findings not found or access denied",
        )

    # Convert findings to SecretMatch objects for triage
    matches = []
    for f in findings:
        try:
            st = SecretType(f.secret_type) if f.secret_type else SecretType.API_KEY
        except ValueError:
            st = SecretType.API_KEY
        matches.append(
            SecretMatch(
                type=st,
                value=f.masked_value or "",
                file_path=f.file_path or "",
                line_number=f.line_start or 0,
                column_start=0,
                column_end=0,
                confidence=(f.confidence or 0) / 100.0,
                matched_text=f.masked_value or "",
                context=f.content_snippet or "",
            )
        )

    # triage_batch returns a dict of {verdict: [SecretMatch, ...]} lists
    triage_result = triage_service.triage_batch(matches)

    return {
        "findings_count": len(finding_ids),
        "triage_results": triage_result,
        "user_id": current_user.id,
    }


@router.get("/triage/status", response_model=dict)
def get_triage_status(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    # Get user's gist IDs
    user_gist_ids = [
        g.id for g in db.query(Gist.id).filter(Gist.user_id == current_user.id).all()
    ]

    if not user_gist_ids:
        return {
            "pending_findings": 0,
            "pending_by_confidence": [],
            "triage_thresholds": {
                "auto_triage_threshold": 0.75,
                "manual_review_threshold": 0.35,
                "escalation_threshold": 0.90,
            },
        }

    # Calculate status from findings
    pending_findings = (
        db.query(Finding).filter(Finding.gist_id.in_(user_gist_ids)).count()
    )

    pending_by_confidence = []
    borderline_count = (
        db.query(Finding)
        .filter(Finding.gist_id.in_(user_gist_ids))
        .filter(
            Finding.confidence.between(
                TRIAGE_THRESHOLDS["manual_review"], TRIAGE_THRESHOLDS["auto_triage"]
            )
        )
        .count()
    )
    high_confidence = (
        db.query(Finding)
        .filter(Finding.gist_id.in_(user_gist_ids))
        .filter(Finding.confidence >= 0.75)
        .count()
    )
    low_confidence = (
        db.query(Finding)
        .filter(Finding.gist_id.in_(user_gist_ids))
        .filter(Finding.confidence < 0.35)
        .count()
    )

    pending_by_confidence = [
        {"range": "low (under 0.35)", "count": low_confidence},
        {"range": "borderline (0.35-0.75)", "count": borderline_count},
        {"range": "high (over 0.75)", "count": high_confidence},
    ]

    return {
        "pending_findings": pending_findings,
        "pending_by_confidence": pending_by_confidence,
        "triage_thresholds": {
            "auto_triage_threshold": TRIAGE_THRESHOLDS["auto_triage"],
            "manual_review_threshold": TRIAGE_THRESHOLDS["manual_review"],
            "escalation_threshold": TRIAGE_THRESHOLDS["escalation"],
        },
    }


@router.put("/triage/{finding_id}/verdict", response_model=dict)
async def update_triage_verdict(
    finding_id: int,
    verdict: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    # Verify finding belongs to user
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found or access denied",
        )

    # Update finding status based on verdict
    if verdict == "accept":
        finding.status = FindingStatus.ACCEPTED
    elif verdict == "reject":
        finding.status = FindingStatus.FALSE_POSITIVE
    elif verdict == "escalate":
        finding.status = FindingStatus.ESCALATED
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid verdict: {verdict}",
        )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return {
        "finding_id": finding_id,
        "verdict": verdict,
        "status": finding.status.value,
        "message": f"Finding {finding_id} status updated to {verdict}",
    }


@router.post("/evidence/mask", response_model=dict)
async def mask_finding_evidence(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    # Verify finding belongs to user
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found or access denied",
        )

    # Convert finding to SecretMatch for masking
    masked_result = evidence_masker.create_masked_evidence(
        value=finding.masked_value or "",
        matched_text=finding.masked_value or "",
        context=finding.content_snippet or "",
        value_hash=finding.value_hash or "",
        secret_type=finding.secret_type or "unknown",
        severity=finding.severity.value if finding.severity else "low",
        confidence=(finding.confidence or 0) / 100.0,
    )

    return {
        "finding_id": finding_id,
        "masked_value": masked_result.masked_value,
        "context_masked": masked_result.context_masked,
        "snippet": masked_result.snippet,
    }


@router.post("/trufflehog/scan", response_model=dict)
async def start_trufflehog_scan_endpoint(
    github_account_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    # Verify GitHub account belongs to user
    github_account = (
        db.query(GitHubAccount)
        .filter(GitHubAccount.id == github_account_id)
        .filter(GitHubAccount.user_id == current_user.id)
        .first()
    )

    if not github_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="GitHub account not found or access denied",
        )

    # Start the scan in the background
    background_tasks.add_task(TruffleHogScanner.scan_account, github_account_id)

    return {
        "status": "started",
        "github_account_id": github_account_id,
        "message": "TruffleHog scan initiated successfully",
    }


@router.get("/trufflehog/status", response_model=dict)
async def get_trufflehog_status_endpoint(
    current_user: User = Depends(get_current_active_user),
):
    status_info = TruffleHogScanner.get_status()

    return {
        "available": status_info.available,
        "scanner_path": status_info.scanner_path,
        "capabilities": status_info.capabilities,
    }


def _finding_to_response(f: Finding) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        gist_id=f.gist_id,
        gist_file_id=f.gist_file_id,
        gist_revision_id=f.gist_revision_id,
        file_path=f.file_path,
        line_start=f.line_start,
        line_end=f.line_end,
        content_snippet=f.content_snippet,
        finding_type=f.finding_type,
        secret_type=f.secret_type,
        severity=f.severity.value if f.severity else "low",
        confidence=f.confidence or 0,
        masked_value=f.masked_value,
        value_hash=f.value_hash,
        detected_at=f.detected_at,
        status=f.status.value if f.status else "new",
    )
