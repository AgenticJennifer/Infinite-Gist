"""
Temporal analysis service.

Tracks leak patterns over time: when secrets first appeared,
whether they were re-exposed after removal, and how the
security posture of a gist evolved across revisions.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict

from sqlalchemy.orm import Session
from src.backend.db.models import Finding, Gist

logger = logging.getLogger(__name__)


class TemporalEvent:
    """Represents a point-in-time event for a finding."""
    def __init__(
        self,
        finding_id: int,
        value_hash: str,
        event_type: str,  # "first_seen", "re_exposed", "removed", "persisted"
        timestamp: datetime,
        gist_id: int,
        revision_sha: Optional[str] = None,
        severity: Optional[str] = None,
    ):
        self.finding_id = finding_id
        self.value_hash = value_hash
        self.event_type = event_type
        self.timestamp = timestamp
        self.gist_id = gist_id
        self.revision_sha = revision_sha
        self.severity = severity


class TemporalAnalysis:
    """Result of temporal analysis for a gist or set of gists."""

    def __init__(self):
        self.events: List[TemporalEvent] = []
        self.re_exposures: List[Dict[str, Any]] = []
        self.persistence_counts: Dict[str, int] = {}  # value_hash → revision count
        self.first_seen: Dict[str, datetime] = {}  # value_hash → first detection
        self.last_seen: Dict[str, datetime] = {}   # value_hash → last detection

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_events": len(self.events),
            "re_exposures": self.re_exposures,
            "persistence_counts": self.persistence_counts,
            "first_seen": {k: v.isoformat() for k, v in self.first_seen.items()},
            "last_seen": {k: v.isoformat() for k, v in self.last_seen.items()},
        }


class TemporalAnalyzer:
    """Analyzes findings across time to detect patterns."""

    def analyze_gist_history(
        self,
        gist_id: int,
        db: Session,
    ) -> TemporalAnalysis:
        """
        Analyze temporal patterns of findings for a single gist.

        Detects:
        - First/last seen timestamps per secret
        - Re-exposure events (secret removed then re-appears)
        - Persistence counts (how many revisions the secret survived)
        """
        analysis = TemporalAnalysis()

        # Get all findings for this gist, ordered by detection time
        findings = (
            db.query(Finding)
            .filter(Finding.gist_id == gist_id)
            .order_by(Finding.detected_at.asc())
            .all()
        )

        if not findings:
            return analysis

        # Track state per value_hash
        seen_hashes: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            if not finding.value_hash:
                continue

            entry = {
                "finding_id": finding.id,
                "detected_at": finding.detected_at,
                "revision_id": finding.gist_revision_id,
                "severity": finding.severity.value if finding.severity else None,
                "status": finding.status.value if finding.status else None,
            }
            seen_hashes[finding.value_hash].append(entry)

        for value_hash, entries in seen_hashes.items():
            # Sort by detection time
            entries.sort(key=lambda e: e["detected_at"] or datetime.min)

            # First and last seen
            first = entries[0]["detected_at"]
            last = entries[-1]["detected_at"]
            if first:
                analysis.first_seen[value_hash] = first
            if last:
                analysis.last_seen[value_hash] = last

            # Persistence count = number of distinct revisions where this appeared
            revision_ids = set(e["revision_id"] for e in entries if e["revision_id"])
            analysis.persistence_counts[value_hash] = len(revision_ids) or len(entries)

            # Detect re-exposure: if status changed to "fixed" then a new
            # finding with same hash appears later
            fixed_time = None
            for entry in entries:
                if entry["status"] == "fixed" and entry["detected_at"]:
                    fixed_time = entry["detected_at"]

                if fixed_time and entry["detected_at"] and entry["detected_at"] > fixed_time:
                    # Secret re-appeared after being fixed
                    analysis.re_exposures.append({
                        "value_hash": value_hash,
                        "original_fixed_at": fixed_time.isoformat(),
                        "re_exposed_at": entry["detected_at"].isoformat(),
                        "finding_id": entry["finding_id"],
                        "severity": entry["severity"],
                    })
                    # Record event
                    analysis.events.append(TemporalEvent(
                        finding_id=entry["finding_id"],
                        value_hash=value_hash,
                        event_type="re_exposed",
                        timestamp=entry["detected_at"],
                        gist_id=gist_id,
                        severity=entry["severity"],
                    ))
                    fixed_time = None  # Only record the first re-exposure

            # Record first_seen event
            if entries[0]["detected_at"]:
                analysis.events.append(TemporalEvent(
                    finding_id=entries[0]["finding_id"],
                    value_hash=value_hash,
                    event_type="first_seen",
                    timestamp=entries[0]["detected_at"],
                    gist_id=gist_id,
                    severity=entries[0]["severity"],
                ))

        return analysis

    def analyze_user_posture(
        self,
        user_id: int,
        db: Session,
    ) -> Dict[str, Any]:
        """
        Analyze security posture trends across all user gists.

        Returns overall statistics and trend indicators.
        """
        # Get all user's gists
        gists = db.query(Gist).filter(Gist.user_id == user_id).all()
        gist_ids = [g.id for g in gists]

        if not gist_ids:
            return {"gists_count": 0, "findings_trend": "stable", "summary": {}}

        # Aggregate findings across gists
        all_findings = (
            db.query(Finding)
            .filter(Finding.gist_id.in_(gist_ids))
            .order_by(Finding.detected_at.asc())
            .all()
        )

        # Group findings by date for trend analysis
        findings_by_date: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)

        for finding in all_findings:
            if finding.detected_at:
                date_key = finding.detected_at.strftime("%Y-%m-%d")
                findings_by_date[date_key] += 1
            if finding.severity:
                severity_counts[finding.severity.value] += 1

        # Detect trend (last 7 days vs. previous 7 days)
        dates_sorted = sorted(findings_by_date.keys())
        trend = "stable"
        if len(dates_sorted) >= 2:
            recent_dates = dates_sorted[-7:]
            older_dates = dates_sorted[-14:-7] if len(dates_sorted) >= 14 else dates_sorted[:len(dates_sorted)//2]

            recent_count = sum(findings_by_date[d] for d in recent_dates)
            older_count = sum(findings_by_date[d] for d in older_dates) if older_dates else 0

            if recent_count > older_count * 1.5 and older_count > 0:
                trend = "worsening"
            elif older_count > recent_count * 1.5 and recent_count > 0:
                trend = "improving"

        return {
            "gists_count": len(gist_ids),
            "total_findings": len(all_findings),
            "severity_counts": dict(severity_counts),
            "findings_by_date": dict(findings_by_date),
            "findings_trend": trend,
        }


# Module-level instance
temporal_analyzer = TemporalAnalyzer()
