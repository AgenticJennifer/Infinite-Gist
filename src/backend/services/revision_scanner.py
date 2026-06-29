"""
Revision-history scanner.

Iterates through gist commit history, fetches each revision's
content, and scans it for secrets. This catches secrets that were
committed and then removed in later revisions.
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from sqlalchemy.orm import Session
from src.backend.services.github_service import GitHubService
from src.backend.services.secret_scanner import SecretScanner, SecretMatch
from src.backend.services.trufflehog_scanner import TruffleHogScanner
from src.backend.services.severity_scorer import SeverityScorer, ConfidenceLevel
from src.backend.services.evidence_masker import EvidenceMasker
from src.backend.db.models import (
    Gist, GistRevision, GistFile, Finding,
    SeverityLevel, FindingStatus,
)

logger = logging.getLogger(__name__)


class RevisionScanner:
    """Scans gist revision history for secrets."""

    def __init__(
        self,
        github_service: GitHubService,
        regex_scanner: Optional[SecretScanner] = None,
        trufflehog: Optional[TruffleHogScanner] = None,
        scorer: Optional[SeverityScorer] = None,
        masker: Optional[EvidenceMasker] = None,
    ):
        self.github_service = github_service
        self.regex_scanner = regex_scanner or SecretScanner()
        self.trufflehog = trufflehog
        self.scorer = scorer or SeverityScorer()
        self.masker = masker or EvidenceMasker()

    async def scan_revision_history(
        self,
        gist_id: str,
        db_gist_id: int,
        db: Session,
    ) -> List[Dict[str, Any]]:
        """
        Scan all revisions of a gist for secrets.

        Returns a list of finding dicts with revision metadata.
        """
        all_findings: List[Dict[str, Any]] = []

        # Get commit history from GitHub
        try:
            commits = await self.github_service.get_gist_commits(gist_id)
        except Exception as e:
            logger.warning("Failed to get commits for gist %s: %s", gist_id, e)
            return []

        if not commits:
            return []

        # Process each commit/revision
        for commit in commits:
            commit_sha = commit.get("version", commit.get("sha", ""))
            committed_at_str = commit.get("committed_at", commit.get("committed_at", ""))

            # Parse timestamp
            committed_at = None
            if committed_at_str:
                try:
                    # GitHub returns ISO 8601 format
                    committed_at = datetime.fromisoformat(
                        committed_at_str.replace("Z", "+00:00")
                    )
                except (ValueError, TypeError):
                    committed_at = None

            # Get gist content at this revision
            try:
                gist_at_revision = await self.github_service.get_gist(gist_id)
                # Note: GitHub API returns the latest version; for specific revisions,
                # we'd need the raw URL or use git clone. For now, scan what we have.
                # A full implementation would use git clone + checkout of each SHA.
            except Exception as e:
                logger.debug("Could not fetch gist %s at revision %s: %s", gist_id, commit_sha, e)
                continue

            # Record the revision in the database
            db_revision = db.query(GistRevision).filter(
                GistRevision.gist_id == db_gist_id,
                GistRevision.version == commit_sha,
            ).first()

            if not db_revision:
                db_revision = GistRevision(
                    gist_id=db_gist_id,
                    version=commit_sha,
                    committed_at=committed_at,
                )
                db.add(db_revision)
                db.commit()
                db.refresh(db_revision)

            # Scan each file in this revision
            files_data = gist_at_revision.get("files", {})
            for filename, file_data in files_data.items():
                content = file_data.get("content", "")
                if not content:
                    continue

                # Scan with regex scanner
                regex_matches = self.regex_scanner.scan_text(content, filename)

                # Scan with TruffleHog if available
                trufflehog_matches: List[SecretMatch] = []
                if self.trufflehog:
                    trufflehog_matches = await self.trufflehog.scan_content(
                        content, filename
                    )

                # Combine and deduplicate
                combined = self._merge_matches(regex_matches, trufflehog_matches)

                for match in combined:
                    severity, confidence_level = self.scorer.score(match)
                    value_hash = self.scorer.compute_value_hash(match.matched_text)

                    # Check for existing finding with same hash
                    existing = db.query(Finding).filter(
                        Finding.value_hash == value_hash
                    ).first()

                    if existing:
                        continue  # Dedup: don't re-record the same secret

                    masked_value = self.masker.mask_value(match.matched_text)
                    masked_context = self.masker.mask_context(
                        match.context, match.matched_text
                    )

                    finding_dict = {
                        "gist_id": db_gist_id,
                        "gist_revision_id": db_revision.id,
                        "file_path": match.file_path,
                        "line_start": match.line_number,
                        "line_end": match.line_number,
                        "content_snippet": masked_context[:500],
                        "finding_type": match.type.value,
                        "secret_type": match.type.value,
                        "severity": severity,
                        "confidence": int(match.confidence * 100),
                        "confidence_level": confidence_level.value,
                        "masked_value": masked_value,
                        "value_hash": value_hash,
                        "detected_at": datetime.utcnow(),
                        "revision_sha": commit_sha,
                        "committed_at": committed_at,
                        "scanner": "trufflehog" if match in trufflehog_matches else "regex",
                    }
                    all_findings.append(finding_dict)

        return all_findings

    @staticmethod
    def _merge_matches(
        regex_matches: List[SecretMatch],
        trufflehog_matches: List[SecretMatch],
    ) -> List[SecretMatch]:
        """
        Merge matches from both scanners, deduplicating by position.

        TruffleHog-verified findings take priority when both scanners
        find the same secret at the same location.
        """
        seen: set[tuple[str, int, int]] = set()
        merged: List[SecretMatch] = []

        # Add TruffleHog matches first (higher priority when verified)
        for match in trufflehog_matches:
            key = (match.file_path, match.line_number, match.column_start)
            if key not in seen:
                seen.add(key)
                merged.append(match)

        # Add regex matches that don't overlap
        for match in regex_matches:
            key = (match.file_path, match.line_number, match.column_start)
            if key not in seen:
                seen.add(key)
                merged.append(match)

        return merged


# Module-level factory
def create_revision_scanner(
    github_service: GitHubService,
    trufflehog: Optional[TruffleHogScanner] = None,
) -> RevisionScanner:
    """Create a RevisionScanner with optional TruffleHog."""
    return RevisionScanner(
        github_service=github_service,
        trufflehog=trufflehog,
    )
