"""
Cross-gist finding correlation service.

Groups related findings by value hash across multiple gists, enabling users
to see all locations where a compromised credential appears.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from src.backend.db.models import Finding, Gist

logger = logging.getLogger(__name__)


def _value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


class CorrelationGroup:
    """A group of findings that share the same secret value."""

    def __init__(self, value_hash: str, secret_type: str):
        self.value_hash = value_hash
        self.secret_type = secret_type
        self.finding_ids: List[int] = []
        self.gist_ids: List[int] = []
        self.gist_descriptions: Dict[int, str] = {}
        self.severities: List[str] = []
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.max_severity = "low"

    @property
    def finding_count(self) -> int:
        return len(self.finding_ids)

    @property
    def severity(self) -> str:
        return self.max_severity

    @property
    def first_detected(self) -> Optional[datetime]:
        return self.first_seen

    @property
    def last_detected(self) -> Optional[datetime]:
        return self.last_seen

    def add_finding(self, finding: Finding, gist: Optional[Gist] = None) -> None:
        self.finding_ids.append(finding.id)
        if finding.gist_id not in self.gist_ids:
            self.gist_ids.append(finding.gist_id)

        if gist and gist.id not in self.gist_descriptions:
            self.gist_descriptions[gist.id] = gist.description or ""

        severity = _value(finding.severity)
        if severity:
            self.severities.append(str(severity))

        if finding.detected_at:
            if not self.first_seen or finding.detected_at < self.first_seen:
                self.first_seen = finding.detected_at
            if not self.last_seen or finding.detected_at > self.last_seen:
                self.last_seen = finding.detected_at

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        self.max_severity = max(
            self.severities,
            key=lambda item: severity_order.get(item, 0),
            default="low",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value_hash": self.value_hash,
            "secret_type": self.secret_type,
            "finding_count": self.finding_count,
            "finding_ids": self.finding_ids,
            "gist_count": len(self.gist_ids),
            "gist_ids": self.gist_ids,
            "gist_descriptions": self.gist_descriptions,
            "max_severity": self.max_severity,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class FindingCorrelator:
    """Correlates findings across gists."""

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def _session(self, db: Optional[Session] = None) -> Session:
        session = db or self.db
        if session is None:
            raise ValueError("A database session is required")
        return session

    def _build_groups(
        self,
        findings: List[Finding],
        db: Session,
    ) -> List[CorrelationGroup]:
        if not findings:
            return []

        gist_ids = {finding.gist_id for finding in findings}
        gists = db.query(Gist).filter(Gist.id.in_(gist_ids)).all()
        gist_map = {gist.id: gist for gist in gists}

        groups: Dict[str, CorrelationGroup] = {}
        for finding in findings:
            if not finding.value_hash:
                continue

            if finding.value_hash not in groups:
                groups[finding.value_hash] = CorrelationGroup(
                    value_hash=finding.value_hash,
                    secret_type=finding.secret_type or finding.finding_type or "unknown",
                )

            groups[finding.value_hash].add_finding(
                finding,
                gist_map.get(finding.gist_id),
            )

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return sorted(
            groups.values(),
            key=lambda group: (
                severity_order.get(group.max_severity, 0),
                group.finding_count,
            ),
            reverse=True,
        )

    def correlate_user_findings(
        self,
        user_id: int,
        db: Optional[Session] = None,
    ) -> List[CorrelationGroup]:
        """Group all findings for a user by shared secret value."""
        session = self._session(db)
        findings = (
            session.query(Finding)
            .join(Gist)
            .filter(Gist.user_id == user_id)
            .order_by(Finding.detected_at.asc())
            .all()
        )
        return self._build_groups(findings, session)

    def find_correlations(
        self,
        user_id: int,
        finding_id: Optional[int] = None,
        db: Optional[Session] = None,
    ) -> List[CorrelationGroup]:
        """Find all correlation groups, optionally scoped to one finding."""
        session = self._session(db)
        query = session.query(Finding).join(Gist).filter(Gist.user_id == user_id)

        if finding_id is not None:
            target = query.filter(Finding.id == finding_id).first()
            if not target or not target.value_hash:
                return []
            query = session.query(Finding).join(Gist).filter(
                Gist.user_id == user_id,
                Finding.value_hash == target.value_hash,
            )

        findings = query.order_by(Finding.detected_at.asc()).all()
        return self._build_groups(findings, session)

    def find_duplicate_secrets(
        self,
        user_id: int,
        db: Optional[Session] = None,
    ) -> List[Dict[str, Any]]:
        """Find secrets that appear in multiple gists."""
        return [
            group.to_dict()
            for group in self.correlate_user_findings(user_id, db)
            if len(group.gist_ids) >= 2
        ]

    def identify_correlation_patterns(
        self,
        user_id: int,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """Summarize correlation patterns for a user's findings."""
        groups = self.correlate_user_findings(user_id, db)

        dominant_secret_types: Dict[str, int] = {}
        severity_distribution: Dict[str, int] = {}
        multi_gist_count = 0

        for group in groups:
            if group.secret_type:
                dominant_secret_types[group.secret_type] = (
                    dominant_secret_types.get(group.secret_type, 0) + 1
                )

            severity_distribution[group.max_severity] = (
                severity_distribution.get(group.max_severity, 0) + 1
            )

            if len(group.gist_ids) > 1:
                multi_gist_count += 1

        related_groups = [group for group in groups if group.finding_count > 1]
        return {
            "total_related_findings": len(related_groups),
            "highly_correlated_groups": len(groups),
            "patterns": {
                "dominant_secret_types": dominant_secret_types,
                "severity_distribution": severity_distribution,
            },
            "cross_gist_patterns": {"multi_gist_count": multi_gist_count},
            "correlation_campaigns": len(related_groups),
        }

    def get_finding_context(
        self,
        finding_id: int,
        db: Optional[Session] = None,
    ) -> Optional[Dict[str, Any]]:
        """Get full context for a finding including same-secret occurrences."""
        session = self._session(db)
        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding or not finding.value_hash:
            return None

        correlated = (
            session.query(Finding)
            .filter(Finding.value_hash == finding.value_hash)
            .all()
        )

        gist_ids = {item.gist_id for item in correlated}
        gists = session.query(Gist).filter(Gist.id.in_(gist_ids)).all()
        gist_map = {gist.id: gist for gist in gists}

        return {
            "finding_id": finding.id,
            "value_hash": finding.value_hash,
            "secret_type": finding.secret_type or finding.finding_type,
            "masked_value": finding.masked_value,
            "severity": _value(finding.severity),
            "confidence": finding.confidence,
            "correlated_findings": [
                {
                    "finding_id": item.id,
                    "gist_id": item.gist_id,
                    "gist_description": (
                        gist_map[item.gist_id].description
                        if item.gist_id in gist_map
                        else None
                    ),
                    "file_path": item.file_path,
                    "line_start": item.line_start,
                    "detected_at": (
                        item.detected_at.isoformat() if item.detected_at else None
                    ),
                }
                for item in correlated
            ],
            "total_occurrences": len(correlated),
            "gist_count": len(gist_ids),
        }


finding_correlator = FindingCorrelator()
