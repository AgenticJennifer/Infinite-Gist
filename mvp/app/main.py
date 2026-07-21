from __future__ import annotations

import csv
import io
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.audit import write_audit_event
from app.config import get_settings
from app.db import SessionLocal, get_db, init_db
from app.github_client import GitHubClient, exchange_oauth_code
from app.models import (
    AuditEvent,
    AuditEventType,
    EvidenceAccessEvent,
    Finding,
    FindingStatus,
    GitHubAccount,
    ScanRun,
    User,
)
from app.scanner import GistScanner, sync_detector_rules, update_finding_status
from app.security import decrypt_token, destination_hash, encrypt_token

settings = get_settings()
app = FastAPI(title=settings.app_name)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
serializer = URLSafeTimedSerializer(settings.app_secret, salt="github-oauth-state")


@app.on_event("startup")
def startup() -> None:
    init_db()
    with SessionLocal() as db:
        ensure_default_user(db)
        sync_detector_rules(db)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = ensure_default_user(db)
    accounts = db.scalars(select(GitHubAccount).where(GitHubAccount.user_id == user.id)).all()
    if not accounts:
        return templates.TemplateResponse(
            "onboarding.html",
            {
                "request": request,
                "settings": settings,
                "user": user,
                "accounts": accounts,
                "error": request.query_params.get("error"),
            },
        )
    return dashboard(request, db)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = ensure_default_user(db)
    severity = request.query_params.get("severity")
    status = request.query_params.get("status")
    query = (
        select(Finding)
        .where(Finding.user_id == user.id)
        .options(selectinload(Finding.gist), selectinload(Finding.evidences))
        .order_by(desc(Finding.severity), desc(Finding.last_seen_at))
    )
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    findings = db.scalars(query).all()
    accounts = db.scalars(select(GitHubAccount).where(GitHubAccount.user_id == user.id)).all()
    scans = db.scalars(
        select(ScanRun).where(ScanRun.user_id == user.id).order_by(desc(ScanRun.created_at)).limit(5)
    ).all()
    counts = _finding_counts(db, user.id)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "settings": settings,
            "user": user,
            "accounts": accounts,
            "findings": findings,
            "scans": scans,
            "counts": counts,
            "severity": severity or "",
            "status": status or "",
            "statuses": [item.value for item in FindingStatus],
        },
    )


@app.get("/connect/github")
def connect_github(db: Session = Depends(get_db)) -> RedirectResponse:
    user = ensure_default_user(db)
    if not settings.github_client_id:
        return RedirectResponse("/?error=GITHUB_CLIENT_ID is not configured", status_code=303)
    state = serializer.dumps({"user_id": user.id})
    params = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_callback_url,
            "scope": "gist",
            "state": state,
        }
    )
    return RedirectResponse(f"{settings.github_oauth_authorize_url}?{params}", status_code=303)


@app.get("/auth/github/callback")
def github_callback(
    code: str,
    state: str,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    try:
        state_payload = serializer.loads(state, max_age=600)
    except BadSignature:
        return RedirectResponse("/?error=Invalid OAuth state", status_code=303)
    user = db.get(User, int(state_payload["user_id"]))
    if user is None:
        user = ensure_default_user(db)
    token_payload = exchange_oauth_code(code)
    token = token_payload["access_token"]
    scopes = token_payload.get("scope", "")
    connect_account_from_token(db, user, token, scopes=scopes)
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/connect/pat")
def connect_pat(token: str = Form(...), db: Session = Depends(get_db)) -> RedirectResponse:
    if not settings.allow_dev_pat_connect:
        raise HTTPException(status_code=403, detail="Developer PAT connect is disabled")
    user = ensure_default_user(db)
    try:
        connect_account_from_token(db, user, token, scopes="manual-token")
    except Exception as exc:
        return RedirectResponse(f"/?error=Token connection failed: {exc.__class__.__name__}", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/scans/start")
def start_scan(account_id: int = Form(...), db: Session = Depends(get_db)) -> RedirectResponse:
    user = ensure_default_user(db)
    account = db.get(GitHubAccount, account_id)
    if account is None or account.user_id != user.id:
        raise HTTPException(status_code=404, detail="GitHub account not found")
    scan = ScanRun(user_id=user.id, github_account_id=account.id, scan_type="manual")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    token = decrypt_token(account.token_encrypted)
    with GitHubClient(token) as client:
        scanner = GistScanner(db, account, client, settings.max_revisions_per_gist)
        try:
            scanner.run_scan(scan)
        except Exception:
            return RedirectResponse(f"/dashboard?error=Scan failed", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/findings/{stable_id}", response_class=HTMLResponse)
def finding_detail(stable_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = ensure_default_user(db)
    finding = db.scalar(
        select(Finding)
        .where(Finding.stable_id == stable_id, Finding.user_id == user.id)
        .options(
            selectinload(Finding.gist),
            selectinload(Finding.evidences),
            selectinload(Finding.transitions),
            selectinload(Finding.verification_attempts),
            selectinload(Finding.fingerprint),
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return templates.TemplateResponse(
        "finding_detail.html",
        {
            "request": request,
            "settings": settings,
            "finding": finding,
            "statuses": [item.value for item in FindingStatus],
            "message": request.query_params.get("message"),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/findings/{stable_id}/status")
def set_finding_status(
    stable_id: str,
    status: str = Form(...),
    reason: str = Form(""),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    user = ensure_default_user(db)
    finding = db.scalar(select(Finding).where(Finding.stable_id == stable_id, Finding.user_id == user.id))
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        next_status = FindingStatus(status)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid status") from None
    update_finding_status(db, finding, next_status, "user", reason or None)
    return RedirectResponse(f"/findings/{stable_id}?message=Status updated", status_code=303)


@app.post("/findings/{stable_id}/verify")
def verify_finding(stable_id: str, db: Session = Depends(get_db)) -> RedirectResponse:
    user = ensure_default_user(db)
    finding = db.scalar(
        select(Finding)
        .where(Finding.stable_id == stable_id, Finding.user_id == user.id)
        .options(selectinload(Finding.gist), selectinload(Finding.fingerprint))
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    account = db.get(GitHubAccount, finding.github_account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="GitHub account not found")
    token = decrypt_token(account.token_encrypted)
    with GitHubClient(token) as client:
        scanner = GistScanner(db, account, client, settings.max_revisions_per_gist)
        try:
            attempt = scanner.verify_finding(finding, actor="user")
        except Exception as exc:
            return RedirectResponse(
                f"/findings/{stable_id}?error=Verification failed: {exc.__class__.__name__}",
                status_code=303,
            )
    return RedirectResponse(f"/findings/{stable_id}?message=Verification result: {attempt.result}", status_code=303)


@app.post("/findings/{stable_id}/evidence/reveal")
def reveal_evidence(stable_id: str, reason: str = Form(""), db: Session = Depends(get_db)) -> RedirectResponse:
    user = ensure_default_user(db)
    finding = db.scalar(select(Finding).where(Finding.stable_id == stable_id, Finding.user_id == user.id))
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    event = EvidenceAccessEvent(
        user_id=user.id,
        finding_id=finding.id,
        actor="user",
        reason=reason or "User requested evidence access.",
        revealed_raw_secret=False,
    )
    db.add(event)
    write_audit_event(
        db,
        AuditEventType.evidence_revealed,
        "Masked evidence viewed. Raw secret reveal is disabled in this MVP.",
        user_id=user.id,
        github_account_id=finding.github_account_id,
        finding_id=finding.id,
        actor="user",
    )
    db.commit()
    return RedirectResponse(f"/findings/{stable_id}?message=Masked evidence access recorded", status_code=303)


@app.get("/audit", response_class=HTMLResponse)
def audit_log(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = ensure_default_user(db)
    events = db.scalars(
        select(AuditEvent).where(AuditEvent.user_id == user.id).order_by(desc(AuditEvent.created_at)).limit(200)
    ).all()
    return templates.TemplateResponse("audit.html", {"request": request, "events": events, "settings": settings})


@app.get("/export/findings.csv")
def export_findings_csv(db: Session = Depends(get_db)) -> StreamingResponse:
    user = ensure_default_user(db)
    findings = db.scalars(
        select(Finding)
        .where(Finding.user_id == user.id)
        .options(selectinload(Finding.gist), selectinload(Finding.evidences))
        .order_by(desc(Finding.last_seen_at))
    ).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "stable_id",
            "severity",
            "confidence",
            "status",
            "presence",
            "finding_type",
            "gist_id",
            "gist_url",
            "file_path",
            "line_start",
            "line_end",
            "masked_preview",
            "verification_result",
            "residual_risk",
            "recommendation",
        ]
    )
    for finding in findings:
        masked_preview = finding.evidences[0].masked_preview if finding.evidences else ""
        writer.writerow(
            [
                finding.stable_id,
                finding.severity.value,
                finding.confidence,
                finding.status.value,
                finding.presence.value,
                finding.finding_type,
                finding.gist.github_gist_id,
                finding.gist.html_url,
                finding.file_path,
                finding.line_start,
                finding.line_end,
                masked_preview,
                finding.verification_result or "",
                finding.residual_risk or "",
                finding.remediation_recommendation,
            ]
        )
    buffer.seek(0)
    write_audit_event(
        db,
        AuditEventType.export_created,
        "Masked findings CSV exported.",
        user_id=user.id,
        actor="user",
        metadata={"rows": len(findings)},
    )
    db.commit()
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=infinite-gist-findings.csv"},
    )


def ensure_default_user(db: Session) -> User:
    user = db.get(User, 1)
    if user is None:
        user = User(id=1, display_name="Local User")
        db.add(user)
        db.flush()
        write_audit_event(db, AuditEventType.user_created, "Default local user created.", user_id=user.id, actor="system")
        db.commit()
    return user


def connect_account_from_token(db: Session, user: User, token: str, scopes: str) -> GitHubAccount:
    with GitHubClient(token) as client:
        profile = client.get_authenticated_user()
    github_login = profile.get("login") or "unknown"
    account = db.scalar(
        select(GitHubAccount).where(GitHubAccount.user_id == user.id, GitHubAccount.github_login == github_login)
    )
    encrypted = encrypt_token(token)
    if account is None:
        account = GitHubAccount(
            user_id=user.id,
            github_login=github_login,
            github_user_id=str(profile.get("id")) if profile.get("id") else None,
            token_encrypted=encrypted,
            scopes=scopes or "",
        )
        db.add(account)
        db.flush()
    else:
        account.token_encrypted = encrypted
        account.github_user_id = str(profile.get("id")) if profile.get("id") else account.github_user_id
        account.scopes = scopes or account.scopes
    write_audit_event(
        db,
        AuditEventType.github_account_connected,
        "GitHub account connected.",
        user_id=user.id,
        github_account_id=account.id,
        actor="user",
        metadata={
            "github_login": github_login,
            "scopes": scopes,
            "destination_hash": destination_hash(github_login),
        },
    )
    db.commit()
    return account


def _finding_counts(db: Session, user_id: int) -> dict[str, int]:
    findings = db.scalars(select(Finding).where(Finding.user_id == user_id)).all()
    counts = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "history_only": 0}
    for finding in findings:
        counts[finding.severity.value] += 1
        if finding.presence.value == "history_only":
            counts["history_only"] += 1
    return counts
