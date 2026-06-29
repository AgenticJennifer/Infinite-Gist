"""
Service for scanning GitHub gists for secrets.

Orchestrates regex scanning, TruffleHog (when available), severity scoring,
evidence masking, triage, and persistence of Findings.
"""

import asyncio
import hashlib
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from sqlalchemy.orm import Session

from src.backend.db.models import (
    Gist, GistFile, GistRevision, Finding,
    SeverityLevel, FindingStatus,
)
from src.backend.db.session import get_db
from src.backend.core.config import settings
from src.backend.services.github_service import GitHubService
from src.backend.services.secret_scanner import SecretScanner, SecretMatch, SecretType
from src.backend.services.trufflehog_scanner import TruffleHogScanner
from src.backend.services.severity_scorer import SeverityScorer, ConfidenceLevel
from src.backend.services.evidence_masker import EvidenceMasker
from src.backend.services.triage_service import TriageService, TriageVerdict

logger = logging.getLogger(__name__)


class GistScannerService:
    """Service for scanning GitHub gists for secrets."""

    def __init__(self, db: Session):
        self.db = db
        self.regex_scanner = SecretScanner()
        self.scorer = SeverityScorer()
        self.masker = EvidenceMasker()
        self.triage = TriageService()
        self._trufflehog: Optional[TruffleHogScanner] = None

    @property
    def trufflehog(self) -> Optional[TruffleHogScanner]:
        if self._trufflehog is None and settings.ENABLE_TRUFFLEHOG:
            self._trufflehog = TruffleHogScanner(settings.TRUFFLEHOG_PATH)
        return self._trufflehog

    async def scan_github_account(self, github_account_id: int) -> List[Finding]:
        """Scan all gists for a GitHub account."""
        from src.backend.db.models import GitHubAccount

        github_account = self.db.query(GitHubAccount).filter(
            GitHubAccount.id == github_account_id
        ).first()

        if not github_account:
            raise ValueError(f"GitHub account with ID {github_account_id} not found")

        user = github_account.user
        github_service = GitHubService(github_account.access_token_encrypted)
        gists = await github_service.get_user_gists()

        all_findings: List[Finding] = []

        for gist_data in gists:
            findings = await self._scan_gist(gist_data, github_account, user, github_service)
            all_findings.extend(findings)

        return all_findings

    async def _scan_gist(
        self,
        gist_data: dict,
        github_account,
        user,
        github_service: GitHubService,
    ) -> List[Finding]:
        """Scan a single gist for secrets, persisting Findings to DB."""
        gist_id = gist_data["id"]

        gist = self._upsert_gist(gist_data, user.id)
        findings: List[Finding] = []

        try:
            files = gist_data.get("files", {})
            files_scanned = 0

            for filename, file_data in files.items():
                content = file_data.get("content")
                if not content:
                    continue

                files_scanned += 1
                gist_file = self._upsert_gist_file(gist.id, filename, file_data)
                file_findings = await self._scan_file(content, filename, gist, gist_file)
                findings.extend(file_findings)

            gist.last_synced_at = datetime.utcnow()
            self.db.add(gist)
            self.db.commit()

        except Exception as e:
            logger.error("Scan failed for gist %s: %s", gist_id, e)
            self.db.rollback()
            raise

        return findings

    async def _scan_file(
        self,
        content: str,
        filename: str,
        gist: Gist,
        gist_file: GistFile,
    ) -> List[Finding]:
        """Scan a single file's content and persist Findings."""
        regex_matches = self.regex_scanner.scan_text(content, filename)

        trufflehog_matches: List[SecretMatch] = []
        if self.trufflehog:
            try:
                trufflehog_matches = await self.trufflehog.scan_content(content, filename)
            except Exception as e:
                logger.warning("TruffleHog scan failed for %s: %s", filename, e)

        combined = self._merge_matches(regex_matches, trufflehog_matches)

        persisted: List[Finding] = []

        for match in combined:
            confidence = match.confidence

            verdict = self.triage.triage(match)
            if verdict == TriageVerdict.REJECT:
                continue

            if verdict == TriageVerdict.ESCALATE:
                confidence *= 0.9

            severity, confidence_level = self.scorer.score(match)
            value_hash = SeverityScorer.compute_value_hash(match.matched_text)

            existing = self.db.query(Finding).filter(
                Finding.value_hash == value_hash,
                Finding.gist_id == gist.id,
            ).first()

            if existing:
                continue

            masked_value = self.masker.mask_value(match.matched_text)
            masked_context = self.masker.mask_context(match.context, match.matched_text)

            finding = Finding(
                gist_id=gist.id,
                gist_file_id=gist_file.id,
                file_path=match.file_path,
                line_start=match.line_number,
                line_end=match.line_number,
                content_snippet=masked_context[:500],
                finding_type=match.type.value,
                secret_type=match.type.value,
                severity=severity.value if hasattr(severity, 'value') else str(severity),
                confidence=int(confidence * 100),
                masked_value=masked_value,
                value_hash=value_hash,
                detected_at=datetime.utcnow(),
                status=FindingStatus.NEW,
            )
            self.db.add(finding)
            persisted.append(finding)

        if persisted:
            self.db.commit()
            for f in persisted:
                self.db.refresh(f)

        return persisted

    def _upsert_gist(self, gist_data: dict, user_id: int) -> Gist:
        """Get or create a Gist DB record from GitHub API data."""
        github_id = gist_data["id"]

        gist = self.db.query(Gist).filter(
            Gist.github_id == github_id,
            Gist.user_id == user_id,
        ).first()

        if not gist:
            gist = Gist(
                github_id=github_id,
                user_id=user_id,
                description=gist_data.get("description"),
                public=gist_data.get("public", False),
                created_at=gist_data.get("created_at"),
                updated_at=gist_data.get("updated_at"),
                pushed_at=gist_data.get("pushed_at"),
            )
            self.db.add(gist)
            self.db.commit()
            self.db.refresh(gist)
        else:
            gist.description = gist_data.get("description")
            gist.public = gist_data.get("public", gist.public)
            gist.updated_at = gist_data.get("updated_at", gist.updated_at)
            self.db.add(gist)
            self.db.commit()
            self.db.refresh(gist)

        return gist

    def _upsert_gist_file(self, gist_id: int, filename: str, file_data: dict) -> GistFile:
        """Get or create a GistFile DB record."""
        gist_file = self.db.query(GistFile).filter(
            GistFile.gist_id == gist_id,
            GistFile.filename == filename,
        ).first()

        if not gist_file:
            gist_file = GistFile(
                gist_id=gist_id,
                filename=filename,
                language=file_data.get("language"),
                size=file_data.get("size", 0),
            )
            self.db.add(gist_file)
            self.db.commit()
            self.db.refresh(gist_file)
        else:
            gist_file.language = file_data.get("language")
            gist_file.size = file_data.get("size", gist_file.size)
            gist_file.content = file_data.get("content", gist_file.content)
            self.db.add(gist_file)
            self.db.commit()
            self.db.refresh(gist_file)

        return gist_file

    @staticmethod
    def _merge_matches(
        regex_matches: List[SecretMatch],
        trufflehog_matches: List[SecretMatch],
    ) -> List[SecretMatch]:
        """Merge matches from both scanners, deduplicating by position."""
        seen: set = set()
        merged: List[SecretMatch] = []

        for match in trufflehog_matches:
            key = (match.file_path, match.line_number, match.column_start)
            if key not in seen:
                seen.add(key)
                merged.append(match)

        for match in regex_matches:
            key = (match.file_path, match.line_number, match.column_start)
            if key not in seen:
                seen.add(key)
                merged.append(match)

        return merged


async def scan_github_account(github_account_id: int) -> List[Finding]:
    """Convenience function — scan all gists for a GitHub account."""
    db = next(get_db())
    try:
        scanner = GistScannerService(db)
        return await scanner.scan_github_account(github_account_id)
    finally:
        db.close()
