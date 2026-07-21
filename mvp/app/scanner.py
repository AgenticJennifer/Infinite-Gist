from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.detectors import (
    DetectorMatch,
    detector_rule_catalog,
    recommended_action,
    residual_risk_for_presence,
    scan_content,
)
from app.github_client import GitHubClient, extract_gist_files, parse_github_datetime
from app.models import (
    AuditEventType,
    DetectorRule,
    Finding,
    FindingEvidence,
    FindingStateTransition,
    FindingStatus,
    Gist,
    GistRevision,
    GitHubAccount,
    Presence,
    ScanRun,
    ScanStatus,
    SecretFingerprint,
    Severity,
    VerificationAttempt,
    utcnow,
)
from app.security import mask_secret, redact_line, secret_fingerprint, stable_finding_id


@dataclass
class ScanStats:
    gists_seen: int = 0
    revisions_seen: int = 0
    findings_created: int = 0
    findings_updated: int = 0


class GistScanner:
    def __init__(self, db: Session, github_account: GitHubAccount, client: GitHubClient, max_revisions: int) -> None:
        self.db = db
        self.github_account = github_account
        self.client = client
        self.max_revisions = max_revisions
        self.stats = ScanStats()

    def run_scan(self, scan_run: ScanRun) -> ScanRun:
        sync_detector_rules(self.db)
        scan_run.status = ScanStatus.running
        scan_run.started_at = utcnow()
        write_audit_event(
            self.db,
            AuditEventType.scan_started,
            "Manual Gist scan started.",
            user_id=scan_run.user_id,
            github_account_id=scan_run.github_account_id,
            actor="system",
        )
        self.db.commit()

        try:
            gist_summaries = self.client.list_authenticated_gists()
            self.stats.gists_seen = len(gist_summaries)
            for gist_summary in gist_summaries:
                self._scan_single_gist_summary(gist_summary)
            scan_run.status = ScanStatus.completed
            scan_run.completed_at = utcnow()
            scan_run.gists_seen = self.stats.gists_seen
            scan_run.revisions_seen = self.stats.revisions_seen
            scan_run.findings_created = self.stats.findings_created
            scan_run.findings_updated = self.stats.findings_updated
            write_audit_event(
                self.db,
                AuditEventType.scan_completed,
                "Gist scan completed.",
                user_id=scan_run.user_id,
                github_account_id=scan_run.github_account_id,
                actor="system",
                metadata={
                    "gists_seen": self.stats.gists_seen,
                    "revisions_seen": self.stats.revisions_seen,
                    "findings_created": self.stats.findings_created,
                    "findings_updated": self.stats.findings_updated,
                },
            )
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            scan_run = self.db.get(ScanRun, scan_run.id) or scan_run
            scan_run.status = ScanStatus.failed
            scan_run.completed_at = utcnow()
            scan_run.error_message = str(exc)[:2000]
            write_audit_event(
                self.db,
                AuditEventType.scan_failed,
                "Gist scan failed.",
                user_id=scan_run.user_id,
                github_account_id=scan_run.github_account_id,
                actor="system",
                metadata={"error_class": exc.__class__.__name__},
            )
            self.db.commit()
            raise
        return scan_run

    def verify_finding(self, finding: Finding, actor: str = "user") -> VerificationAttempt:
        attempt = VerificationAttempt(finding_id=finding.id, status="running")
        self.db.add(attempt)
        write_audit_event(
            self.db,
            AuditEventType.verification_started,
            "Finding verification started.",
            user_id=finding.user_id,
            github_account_id=finding.github_account_id,
            finding_id=finding.id,
            actor=actor,
        )
        self.db.flush()

        gist = finding.gist
        observed_current = False
        observed_history = False
        target_hmac = finding.fingerprint.hmac_sha256

        gist_payload = self.client.get_gist(gist.github_gist_id)
        current_sha = _current_revision_sha(gist_payload)
        for file_content in extract_gist_files(gist_payload, self.client):
            for match in scan_content(file_content.content):
                if self._match_is_target(finding, match, target_hmac):
                    observed_current = True
                    self._record_evidence(finding, None, current_sha, file_content.filename, match, True)

        commits = self.client.list_gist_commits(gist.github_gist_id, max_items=self.max_revisions)
        for commit in commits:
            sha = commit.get("version") or commit.get("sha")
            if not sha:
                continue
            revision_payload = self.client.get_gist_revision(gist.github_gist_id, sha)
            revision = self._upsert_revision(gist, revision_payload, sha)
            for file_content in extract_gist_files(revision_payload, self.client):
                for match in scan_content(file_content.content):
                    if self._match_is_target(finding, match, target_hmac):
                        observed_history = True
                        self._record_evidence(finding, revision, sha, file_content.filename, match, False)

        presence = _presence_from_flags(observed_current, observed_history)
        finding.presence = presence
        finding.last_verified_at = utcnow()
        finding.verification_result = presence.value
        finding.residual_risk = residual_risk_for_presence(presence.value)

        if presence == Presence.absent:
            _transition_finding(self.db, finding, FindingStatus.verified_fixed, actor, "Verification found no current or historical evidence.")
            attempt.result = "verified_fixed"
        elif presence == Presence.history_only:
            _transition_finding(self.db, finding, FindingStatus.partially_fixed, actor, "Current content is clean, but history still contains evidence.")
            attempt.result = "history_risk_remains"
        else:
            if finding.status in {FindingStatus.verified_fixed, FindingStatus.partially_fixed, FindingStatus.fixed_pending_verification}:
                _transition_finding(self.db, finding, FindingStatus.reopened, actor, "Verification observed exposure again.")
            attempt.result = "still_present"

        attempt.status = "completed"
        attempt.completed_at = utcnow()
        attempt.details = finding.residual_risk
        write_audit_event(
            self.db,
            AuditEventType.verification_completed,
            "Finding verification completed.",
            user_id=finding.user_id,
            github_account_id=finding.github_account_id,
            finding_id=finding.id,
            actor=actor,
            metadata={"result": attempt.result, "presence": presence.value},
        )
        self.db.commit()
        return attempt

    def _scan_single_gist_summary(self, gist_summary: dict[str, Any]) -> None:
        github_gist_id = gist_summary.get("id")
        if not github_gist_id:
            return
        gist_payload = self.client.get_gist(github_gist_id)
        gist = self._upsert_gist(gist_payload)
        current_sha = _current_revision_sha(gist_payload)

        for file_content in extract_gist_files(gist_payload, self.client):
            self._scan_file(gist, None, current_sha, file_content.filename, file_content.content, is_current=True)

        commits = self.client.list_gist_commits(github_gist_id, max_items=self.max_revisions)
        for commit in commits:
            sha = commit.get("version") or commit.get("sha")
            if not sha:
                continue
            revision_payload = self.client.get_gist_revision(github_gist_id, sha)
            revision = self._upsert_revision(gist, revision_payload, sha)
            self.stats.revisions_seen += 1
            for file_content in extract_gist_files(revision_payload, self.client):
                self._scan_file(gist, revision, sha, file_content.filename, file_content.content, is_current=False)

        gist.last_scanned_at = utcnow()
        self.db.commit()

    def _scan_file(
        self,
        gist: Gist,
        revision: GistRevision | None,
        revision_sha: str,
        file_path: str,
        content: str,
        *,
        is_current: bool,
    ) -> None:
        for match in scan_content(content):
            finding = self._upsert_finding(gist, revision, revision_sha, file_path, match, is_current)
            self._record_evidence(finding, revision, revision_sha, file_path, match, is_current)

    def _upsert_gist(self, payload: dict[str, Any]) -> Gist:
        github_gist_id = payload["id"]
        gist = self.db.scalar(
            select(Gist).where(
                Gist.github_account_id == self.github_account.id,
                Gist.github_gist_id == github_gist_id,
            )
        )
        owner = payload.get("owner") or {}
        if gist is None:
            gist = Gist(github_account_id=self.github_account.id, github_gist_id=github_gist_id)
            self.db.add(gist)
        gist.owner_login = owner.get("login")
        gist.description = payload.get("description")
        gist.html_url = payload.get("html_url")
        gist.public = bool(payload.get("public"))
        gist.files_summary = _files_summary(payload)
        gist.created_at_remote = parse_github_datetime(payload.get("created_at"))
        gist.updated_at_remote = parse_github_datetime(payload.get("updated_at"))
        gist.last_seen_at = utcnow()
        self.db.flush()
        return gist

    def _upsert_revision(self, gist: Gist, payload: dict[str, Any], sha: str) -> GistRevision:
        revision = self.db.scalar(
            select(GistRevision).where(GistRevision.gist_id == gist.id, GistRevision.revision_sha == sha)
        )
        if revision is None:
            revision = GistRevision(gist_id=gist.id, revision_sha=sha)
            self.db.add(revision)
        history = payload.get("history") or []
        committed_at = None
        for item in history:
            if item.get("version") == sha:
                committed_at = parse_github_datetime(item.get("committed_at"))
                break
        revision.committed_at = committed_at
        revision.scanned_at = utcnow()
        revision.files_summary = _files_summary(payload)
        self.db.flush()
        return revision

    def _upsert_finding(
        self,
        gist: Gist,
        revision: GistRevision | None,
        revision_sha: str,
        file_path: str,
        match: DetectorMatch,
        is_current: bool,
    ) -> Finding:
        fp_value = secret_fingerprint(match.secret_value, match.finding_type)
        fingerprint = self.db.scalar(select(SecretFingerprint).where(SecretFingerprint.hmac_sha256 == fp_value))
        if fingerprint is None:
            fingerprint = SecretFingerprint(hmac_sha256=fp_value, secret_family=match.finding_type)
            self.db.add(fingerprint)
            self.db.flush()
        else:
            fingerprint.last_seen_at = utcnow()

        finding = self.db.scalar(
            select(Finding).where(
                Finding.github_account_id == self.github_account.id,
                Finding.gist_id == gist.id,
                Finding.file_path == file_path,
                Finding.detector_id == match.detector_id,
                Finding.fingerprint_id == fingerprint.id,
            )
        )
        presence = Presence.current if is_current else Presence.history_only
        if finding is None:
            stable_id = stable_finding_id(self.github_account.id, gist.id, file_path, match.detector_id, fp_value)
            finding = Finding(
                stable_id=stable_id,
                user_id=self.github_account.user_id,
                github_account_id=self.github_account.id,
                gist_id=gist.id,
                fingerprint_id=fingerprint.id,
                detector_id=match.detector_id,
                detector_version=match.detector_version,
                finding_type=match.finding_type,
                severity=match.severity,
                confidence=match.confidence,
                presence=presence,
                file_path=file_path,
                line_start=match.line_start,
                line_end=match.line_end,
                remediation_recommendation=recommended_action(match.finding_type, match.severity),
                residual_risk=residual_risk_for_presence(presence.value),
                validity_state=match.validity_state,
                metadata_json={"first_revision_sha": revision_sha},
            )
            self.db.add(finding)
            self.db.flush()
            _transition_finding(self.db, finding, FindingStatus.open, "system", "Finding created by detector.")
            write_audit_event(
                self.db,
                AuditEventType.finding_created,
                "Finding created.",
                user_id=finding.user_id,
                github_account_id=finding.github_account_id,
                finding_id=finding.id,
                actor="system",
                metadata={"detector_id": match.detector_id, "finding_type": match.finding_type},
            )
            self.stats.findings_created += 1
            return finding

        old_status = finding.status
        finding.last_seen_at = utcnow()
        finding.detector_version = match.detector_version
        finding.severity = _max_severity(finding.severity, match.severity)
        finding.confidence = max(finding.confidence, match.confidence)
        finding.presence = _merge_presence(finding.presence, is_current)
        finding.residual_risk = residual_risk_for_presence(finding.presence.value)
        finding.validity_state = match.validity_state if finding.validity_state == "unverified" else finding.validity_state
        if finding.status in {FindingStatus.verified_fixed, FindingStatus.partially_fixed}:
            _transition_finding(self.db, finding, FindingStatus.reopened, "system", "Finding observed again during scan.")
        elif old_status == FindingStatus.open:
            # No transition needed for still-open findings.
            pass
        self.db.flush()
        write_audit_event(
            self.db,
            AuditEventType.finding_updated,
            "Finding updated from scan evidence.",
            user_id=finding.user_id,
            github_account_id=finding.github_account_id,
            finding_id=finding.id,
            actor="system",
            metadata={"detector_id": match.detector_id, "presence": finding.presence.value},
        )
        self.stats.findings_updated += 1
        return finding

    def _record_evidence(
        self,
        finding: Finding,
        revision: GistRevision | None,
        revision_sha: str,
        file_path: str,
        match: DetectorMatch,
        is_current: bool,
    ) -> None:
        existing = self.db.scalar(
            select(FindingEvidence).where(
                FindingEvidence.finding_id == finding.id,
                FindingEvidence.revision_sha == revision_sha,
                FindingEvidence.file_path == file_path,
                FindingEvidence.line_start == match.line_start,
                FindingEvidence.line_end == match.line_end,
                FindingEvidence.masked_preview == mask_secret(match.secret_value),
            )
        )
        if existing is not None:
            if is_current and not existing.is_current:
                existing.is_current = True
            return
        evidence = FindingEvidence(
            finding_id=finding.id,
            gist_revision_id=revision.id if revision else None,
            revision_sha=revision_sha,
            file_path=file_path,
            line_start=match.line_start,
            line_end=match.line_end,
            masked_preview=mask_secret(match.secret_value),
            context_excerpt=redact_line(match.line_text, match.secret_value),
            explanation=match.explanation,
            is_current=is_current,
        )
        self.db.add(evidence)
        try:
            self.db.flush()
        except IntegrityError:
            self.db.rollback()
            # Caller will continue safely; duplicate evidence is not security-relevant.

    def _match_is_target(self, finding: Finding, match: DetectorMatch, target_hmac: str) -> bool:
        if match.detector_id != finding.detector_id:
            return False
        return secret_fingerprint(match.secret_value, match.finding_type) == target_hmac


def sync_detector_rules(db: Session) -> None:
    for item in detector_rule_catalog():
        existing = db.scalar(
            select(DetectorRule).where(
                DetectorRule.detector_id == item["detector_id"], DetectorRule.version == item["version"]
            )
        )
        if existing is None:
            db.add(
                DetectorRule(
                    detector_id=str(item["detector_id"]),
                    version=str(item["version"]),
                    finding_type=str(item["finding_type"]),
                    default_severity=item["default_severity"],
                    description=str(item["description"]),
                )
            )
    db.commit()


def _transition_finding(db: Session, finding: Finding, to_status: FindingStatus, actor: str, reason: str) -> None:
    from_status = finding.status.value if finding.status else None
    if finding.status != to_status:
        finding.status = to_status
    transition = FindingStateTransition(
        finding_id=finding.id,
        from_status=from_status,
        to_status=to_status.value,
        actor=actor,
        reason=reason,
    )
    db.add(transition)


def update_finding_status(db: Session, finding: Finding, status: FindingStatus, actor: str, reason: str | None) -> None:
    _transition_finding(db, finding, status, actor, reason or "Status changed by user.")
    write_audit_event(
        db,
        AuditEventType.finding_status_changed,
        "Finding status changed.",
        user_id=finding.user_id,
        github_account_id=finding.github_account_id,
        finding_id=finding.id,
        actor=actor,
        metadata={"to_status": status.value, "reason": reason},
    )
    db.commit()


def _presence_from_flags(current: bool, history: bool) -> Presence:
    if current and history:
        return Presence.current_and_history
    if current:
        return Presence.current
    if history:
        return Presence.history_only
    return Presence.absent


def _merge_presence(existing: Presence, is_current: bool) -> Presence:
    current = existing in {Presence.current, Presence.current_and_history}
    history = existing in {Presence.history_only, Presence.current_and_history}
    if is_current:
        current = True
    else:
        history = True
    return _presence_from_flags(current, history)


def _max_severity(a: Severity, b: Severity) -> Severity:
    order = [Severity.low, Severity.medium, Severity.high, Severity.critical]
    return order[max(order.index(a), order.index(b))]


def _current_revision_sha(gist_payload: dict[str, Any]) -> str:
    history = gist_payload.get("history") or []
    if history and history[0].get("version"):
        return str(history[0]["version"])
    if gist_payload.get("id"):
        updated = gist_payload.get("updated_at") or datetime.now(timezone.utc).isoformat()
        return f"current-{gist_payload['id']}-{updated}"
    return "current"


def _files_summary(payload: dict[str, Any]) -> dict[str, Any]:
    files = payload.get("files") or {}
    return {
        name: {
            "filename": meta.get("filename") or name,
            "language": meta.get("language"),
            "size": meta.get("size"),
            "truncated": bool(meta.get("truncated")),
        }
        for name, meta in files.items()
    }
