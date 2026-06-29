"""
Cross-gist finding correlation service.

Groups related findings by value hash and secret type across
multiple gists, enabling users to see all locations where a
compromised credential appears.
"""

import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime

from sqlalchemy.orm import Session
from src.backend.db.models import Finding, Gist, GistFile, GistRevision

logger = logging.getLogger(__name__)


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
        self.max_severity: str = "low"

    def add_finding(self, finding: Finding, gist: Optional[Gist] = None):
        self.finding_ids.append(finding.id)
        if finding.gist_id not in self.gist_ids:
            self.gist_ids.append(finding.gist_id)

        if gist and gist.id not in self.gist_descriptions:
            self.gist_descriptions[gist.id] = gist.description or ""

        if finding.severity:
            self.severities.append(finding.severity.value)

        if finding.detected_at:
            if not self.first_seen or finding.detected_at < self.first_seen:
                self.first_seen = finding.detected_at
            if not self.last_seen or finding.detected_at > self.last_seen:
                self.last_seen = finding.detected_at

        # Compute max severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        self.max_severity = max(
            self.severities, key=lambda s: severity_order.get(s, 0), default="low"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value_hash": self.value_hash,
            "secret_type": self.secret_type,
            "finding_count": len(self.finding_ids),
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

    def __init__(self, db: Session = None):
        self.db = db

    def correlate_user_findings(
        self,
        user_id: int,
        db: Session,
    ) -> List[CorrelationGroup]:
        """
        Group all findings for a user by shared secret value.

        Returns correlation groups sorted by severity (highest first).
        """
        # Get all findings for this user's gists
        findings = (
            db.query(Finding)
            .join(Gist)
            .filter(Gist.user_id == user_id)
            .order_by(Finding.detected_at.asc())
            .all()
        )

        if not findings:
            return []

        # Load gist descriptions
        gist_ids = set(f.gist_id for f in findings)
        gists = db.query(Gist).filter(Gist.id.in_(gist_ids)).all()
        gist_map = {g.id: g for g in gists}

        # Group by value_hash
        groups: Dict[str, CorrelationGroup] = {}

        for finding in findings:
            if not finding.value_hash:
                continue

            if finding.value_hash not in groups:
                groups[finding.value_hash] = CorrelationGroup(
                    value_hash=finding.value_hash,
                    secret_type=finding.secret_type or finding.finding_type or "unknown",
                )

            gist = gist_map.get(finding.gist_id)
            groups[finding.value_hash].add_finding(finding, gist)

        # Sort by severity (highest first), then by count of findings
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        sorted_groups = sorted(
            groups.values(),
            key=lambda g: (
                severity_order.get(g.max_severity, 0),
                len(g.finding_ids),
            ),
            reverse=True,
        )

        return sorted_groups

    def find_duplicate_secrets(
        self,
        user_id: int,
        db: Session,
    ) -> List[Dict[str, Any]]:
        """
        Find secrets that appear in multiple gists (cross-gist duplicates).

        Returns only groups with findings in 2+ distinct gists.
        """
        groups = self.correlate_user_findings(user_id, db)
        return [
            g.to_dict() for g in groups
            if len(g.gist_ids) >= 2
        ]

    def identify_correlation_patterns(
        self,
        user_id: int,
        db: Session,
    ) -> Dict[str, Any]:
        """
        Identify correlation patterns for a user.
        
        Returns patterns including total correlated findings,
        highly correlated groups, secret type patterns, etc.
        """
        groups = self.correlate_user_findings(user_id, db)
        
        total_related_findings = len([g for g in groups if g.finding_count > 1])
        
        # Aggregate patterns
        dominant_secret_types = {}
        severity_distribution = {}
        cross_gist_patterns = {}
        
        for group in groups:
            # Count secret types
            if group.secret_type:
                dominant_secret_types[group.secret_type] = dominant_secret_types.get(group.secret_type, 0) + 1
            
            # Count severities
            severity_distribution[group.max_severity] = severity_distribution.get(group.max_severity, 0) + 1
            
            # Multi-gist patterns
            if len(group.gist_ids) > 1:
                cross_gist_patterns["multi_gist_count"] = cross_gist_patterns.get("multi_gist_count", 0) + 1
        
        return {
            "total_related_findings": total_related_findings,
            "highly_correlated_groups": len(groups),
            "patterns": {
                "dominant_secret_types": dominant_secret_types,
                "severity_distribution": severity_distribution
            },
            "cross_gist_patterns": cross_gist_patterns,
            "correlation_campaigns": len([g for g in groups if g.finding_count > 1]),
        }

    def get_finding_context(
        self,
        finding_id: int,
        db: Session,
    ) -> Optional[Dict[str, Any]]:
        """
        Get full context for a finding including cross-gist correlation.

        Includes all gists where the same secret value appears.
        """
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding or not finding.value_hash:
            return None

        # Find all findings with the same hash
        correlated = (
            db.query(Finding)
            .filter(Finding.value_hash == finding.value_hash)
            .all()
        )

        gist_ids = set(f.gist_id for f in correlated)
        gists = db.query(Gist).filter(Gist.id.in_(gist_ids)).all()
        gist_map = {g.id: g for g in gists}

    def find_duplicate_secrets(
        self,
        user_id: int,
        db: Session,
    ) -> List[Dict[str, Any]]:
        """
        Find secrets that appear in multiple gists (cross-gist duplicates).

        Returns only groups with findings in 2+ distinct gists.
        """
        groups = self.correlate_user_findings(user_id, db)
        return [
            g.to_dict() for g in groups
            if len(g.gist_ids) >= 2
        ]

    def identify_correlation_patterns(
        self,
        user_id: int,
        db: Session,
    ) -> Dict[str, Any]:
        """
        Identify correlation patterns for a user.
        
        Returns patterns including total correlated findings,
        highly correlated groups, secret type patterns, etc.
        """
        groups = self.correlate_user_findings(user_id, db)
        
        total_related_findings = len([g for g in groups if g.finding_count > 1])
        
        # Aggregate patterns
        dominant_secret_types = {}
        severity_distribution = {}
        cross_gist_patterns = {}
        
        for group in groups:
            # Count secret types
            if group.secret_type:
                dominant_secret_types[group.secret_type] = dominant_secret_types.get(group.secret_type, 0) + 1
            
            # Count severities
            severity_distribution[group.max_severity] = severity_distribution.get(group.max_severity, 0) + 1
            
            # Multi-gist patterns
            if len(group.gist_ids) > 1:
                cross_gist_patterns["multi_gist_count"] = cross_gist_patterns.get("multi_gist_count", 0) + 1
        
        return {
            "total_related_findings": total_related_findings,
            "highly_correlated_groups": len(groups),
            "patterns": {
                "dominant_secret_types": dominant_secret_types,
                "severity_distribution": severity_distribution
            },
            "cross_gist_patterns": cross_gist_patterns,
            "correlation_campaigns": len([g for g in groups if g.finding_count > 1]),
        }

    def get_finding_context(
        self,
        finding_id: int,
        db: Session,
    ) -> Optional[Dict[str, Any]]:
        """
        Get full context for a finding including cross-gist correlation.

        Includes all gists where the same secret value appears.
        """
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding or not finding.value_hash:
            return None

        # Find all findings with the same hash
        correlated = (
            db.query(Finding)
            .filter(Finding.value_hash == finding.value_hash)
            .all()
        )

        gist_ids = set(f.gist_id for f in correlated)
        gists = db.query(Gist).filter(Gist.id.in_(gist_ids)).all()
        gist_map = {g.id: g for g in gists}

        return {
            "finding_id": finding.id,
            "value_hash": finding.value_hash,
            "secret_type": finding.secret_type or finding.finding_type,
            "masked_value": finding.masked_value,
            "severity": finding.severity.value if finding.severity else None,
            "confidence": finding.confidence,
            "correlated_findings": [
                {
                    "finding_id": f.id,
                    "gist_id": f.gist_id,
                    "gist_description": gist_map[f.gist_id].description if f.gist_id in gist_map else None,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "detected_at": f.detected_at.isoformat() if f.detected_at else None,
                }
                for f in correlated
            ],
            "total_occurrences": len(correlated),
            "gist_count": len(gist_ids),
        }
        groups = self.correlate_user_findings(user_id, db)
        return [
            g.to_dict() for g in groups
            if len(g.gist_ids) >= 2
        ]

    def identify_correlation_patterns(
        self,
        user_id: int,
        db: Session,
    ) -> Dict[str, Any]:
        """
        Identify correlation patterns for a user.
        
        Returns patterns including total correlated findings,
        highly correlated groups, secret type patterns, etc.
        """
        groups = self.correlate_user_findings(user_id, db)
        
        total_related_findings = len([g for g in groups if g.finding_count > 1])
        
        # Aggregate patterns
        dominant_secret_types = {}
        severity_distribution = {}
        cross_gist_patterns = {}
        
        for group in groups:
            # Count secret types
            if group.secret_type:
                dominant_secret_types[group.secret_type] = dominant_secret_types.get(group.secret_type, 0) + 1
            
            # Count severities
            severity_distribution[group.max_severity] = severity_distribution.get(group.max_severity, 0) + 1
            
            # Multi-gist patterns
            if len(group.gist_ids) > 1:
                cross_gist_patterns["multi_gist_count"] = cross_gist_patterns.get("multi_gist_count", 0) + 1
        
        return {
            "total_related_findings": total_related_findings,
            "highly_correlated_groups": len(groups),
            "patterns": {
                "dominant_secret_types": dominant_secret_types,
                "severity_distribution": severity_distribution
            },
            "cross_gist_patterns": cross_gist_patterns,
            "correlation_campaigns": len([g for g in groups if g.finding_count > 1]),
        }

    def get_finding_context(
        self,
        finding_id: int,
        db: Session,
    ) -> Optional[Dict[str, Any]]:
        """
        Get full context for a finding including cross-gist correlation.

        Includes all gists where the same secret value appears.
        """
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding or not finding.value_hash:
            return None

        # Find all findings with the same hash
        correlated = (
            db.query(Finding)
            .filter(Finding.value_hash == finding.value_hash)
            .all()
        )

        gist_ids = set(f.gist_id for f in correlated)
        gists = db.query(Gist).filter(Gist.id.in_(gist_ids)).all()
        gist_map = {g.id: g for g in gists}

        return {
            "finding_id": finding.id,
            "value_hash": finding.value_hash,
            "secret_type": finding.secret_type or finding.finding_type,
            "masked_value": finding.masked_value,
            "severity": finding.severity.value if finding.severity else None,
            "confidence": finding.confidence,
            "correlated_findings": [
                {
                    "finding_id": f.id,
                    "gist_id": f.gist_id,
                    "gist_description": gist_map[f.gist_id].description if f.gist_id in gist_map else None,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "detected_at": f.detected_at.isoformat() if f.detected_at else None,
                }
                for f in correlated
            ],
            "total_occurrences": len(correlated),
            "gist_count": len(gist_ids),
        }


# Module-level instance
finding_correlator = FindingCorrelator()
