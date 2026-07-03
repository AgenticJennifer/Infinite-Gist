"""
Enhanced findings correlation service for Infinite Gist Phase 2.

Advanced correlation service that groups related findings across multiple
gists using multiple analysis techniques: temporal, content-based, and
contextual correlation to identify patterns and shared secrets.
"""

import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from collections import defaultdict, Counter

from sqlalchemy.orm import Session
from src.backend.db.models import Finding, Gist

logger = logging.getLogger(__name__)


class TemporalCorrelationGroup:
    """
    Correlation group with temporal analysis.

    Groups findings by value hash and analyzes temporal patterns.
    """

    def __init__(self, value_hash: str, secret_type: str):
        self.value_hash = value_hash
        self.secret_type = secret_type
        self.finding_ids: List[int] = []
        self.gist_ids: Set[int] = set()
        self.gist_descriptions: Dict[int, str] = {}
        self.severities: List[str] = []
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.revision_count: int = 0
        self.gist_count: int = 0
        self.last_gist_id: Optional[int] = None
        self.temporal_patterns: Dict[str, Any] = {}
        self.cross_gist_spread: Dict[int, int] = {}  # gist_id -> finding_count

    def add_finding(self, finding: Finding, gist: Optional[Gist] = None):
        """Add a finding to the correlation group."""
        self.finding_ids.append(finding.id)
        self.gist_ids.add(finding.gist_id)

        if gist and gist.id not in self.gist_descriptions:
            self.gist_descriptions[gist.id] = gist.description or ""

        if finding.severity:
            self.severities.append(finding.severity.value)

        if finding.detected_at:
            if not self.first_seen or finding.detected_at < self.first_seen:
                self.first_seen = finding.detected_at
            if not self.last_seen or finding.detected_at > self.last_seen:
                self.last_seen = finding.detected_at

        self.gist_count = len(self.gist_ids)
        self.revision_count += 1
        self.cross_gist_spread[finding.gist_id] = self.cross_gist_spread.get(finding.gist_id, 0) + 1

    def detect_temporal_patterns(self) -> Dict[str, Any]:
        """
        Detect temporal patterns in the correlation group.

        Returns:
            Dict containing temporal analysis results.
        """
        patterns = {
            "spread_rate": 0.0,
            "growth_phase": "stable",
            "re_exposure_probability": 0.0,
            "consistency_score": 0.0,
        }

        if not self.first_seen or not self.last_seen or self.gist_count <= 1:
            return patterns

        # Calculate spread rate (findings over time)
        days_span = max((self.last_seen - self.first_seen).days, 1)
        patterns["spread_rate"] = len(self.finding_ids) / days_span

        # Determine growth phase based on finding density
        if patterns["spread_rate"] > 0.5:
            patterns["growth_phase"] = "rapid"
        elif patterns["spread_rate"] > 0.2:
            patterns["growth_phase"] = "moderate"
        elif patterns["spread_rate"] > 0.1:
            patterns["growth_phase"] = "slow"
        else:
            patterns["growth_rate"] = "stable"

        # Calculate consistency (how evenly distributed across gists)
        if self.gist_count > 0:
            distribution = [self.cross_gist_spread[gist_id] for gist_id in self.gist_ids]
            avg_per_gist = sum(distribution) / len(distribution)
            variance = sum((x - avg_per_gist) ** 2 for x in distribution) / len(distribution)
            patterns["consistency_score"] = max(0.0, 1.0 - (variance / (avg_per_gist * avg_per_gist))) if avg_per_gist > 0 else 0.0

        # Re-exposure probability based on spread across multiple gists
        if len(self.gist_ids) > 1 and self.revision_count > 1:
            patterns["re_exposure_probability"] = min(1.0, len(self.gist_ids) / 5.0)

        return patterns

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API serialization."""
        temporal_patterns = self.detect_temporal_patterns()

        return {
            "value_hash": self.value_hash,
            "secret_type": self.secret_type,
            "finding_count": len(self.finding_ids),
            "finding_ids": self.finding_ids,
            "gist_count": self.gist_count,
            "gist_ids": list(self.gist_ids),
            "gist_descriptions": self.gist_descriptions,
            "severities": self.severities,
            "max_severity": self._calculate_max_severity(),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "revision_count": self.revision_count,
            "temporal_patterns": temporal_patterns,
            "cross_gist_spread": self.cross_gist_spread,
        }

    def _calculate_max_severity(self) -> str:
        """Calculate maximum severity across all findings."""
        if not self.severities:
            return "low"

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return max(self.severities, key=lambda s: severity_order.get(s, 0))


class ContentSimilarityAnalyzer:
    """Analyzes content similarity between findings."""

    @staticmethod
    def analyze_file_path_patterns(
        finding_ids: List[int],
        db: Session,
    ) -> Dict[str, Any]:
        """
        Analyze file path patterns in correlated findings.

        Identifies if findings are concentrated in specific file types,
        directories, or follow characteristic patterns.
        """
        findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()

        if not findings:
            return {"pattern_type": "none", "confidence": 0.0}

        # Extract file paths and extensions
        file_paths = [f.file_path for f in findings if f.file_path]
        if not file_paths:
            return {"pattern_type": "none", "confidence": 0.0}

        # Analyze file extensions
        extensions = []
        directories = []
        for path in file_paths:
            if "." in path:
                ext = path.split(".")[1].lower()
                extensions.append(f".{ext}")
            dir_part = path.rsplit("/", 1)[0] if "/" in path else ""
            if dir_part:
                directories.append(dir_part)

        # Determine characteristic patterns
        ext_counter = Counter(extensions)
        dir_counter = Counter(directories)

        most_common_ext = ext_counter.most_common(1)
        most_common_dir = dir_counter.most_common(1)

        result = {
            "pattern_type": "none",
            "confidence": 0.0,
            "dominant_extensions": list(ext_counter.keys())[:5],
            "dominant_directories": list(dir_counter.keys())[:5],
            "target_file_count": len(file_paths),
        }

        # Determine if there's a clear pattern
        if most_common_ext and most_common_ext[0][1] >= len(extensions) * 0.6:
            result["pattern_type"] = "extension_pattern"
            result["confidence"] = most_common_ext[0][1] / len(extensions)

        if most_common_dir and most_common_dir[0][1] >= len(directories) * 0.6:
            result["pattern_type"] = "directory_pattern"
            result["confidence"] = most_common_dir[0][1] / len(directories)

        if (
            most_common_ext
            and most_common_ext[0][1] >= len(extensions) * 0.4
            and most_common_dir
            and most_common_dir[0][1] >= len(directories) * 0.4
        ):
            result["pattern_type"] = "combined_pattern"
            result["confidence"] = (most_common_ext[0][1] + most_common_dir[0][1]) / (len(extensions) + len(directories))

        return result

    @staticmethod
    def analyze_temporal_patterns(
        findings: List[Finding], db: Session
    ) -> Dict[str, Any]:
        """
        Analyze temporal distribution and patterns.

        Groups findings by time periods and analyzes spread patterns.
        """
        if not findings:
            return {"distribution": {}, "peak_period": None, "spread_rate": 0.0}

        # Group by day
        daily_counts = defaultdict(int)
        for finding in findings:
            if finding.detected_at:
                day = finding.detected_at.strftime("%Y-%m-%d")
                daily_counts[day] += 1

        if not daily_counts:
            return {"distribution": {}, "peak_period": None, "spread_rate": 0.0}

        # Find peak period
        peak_day = max(daily_counts.items(), key=lambda x: x[1])

        # Calculate spread rate (how many days with findings)
        total_days_with_findings = len(daily_counts)
        total_findings = len(findings)
        spread_rate = total_findings / max(total_days_with_findings, 1)

        return {
            "distribution": dict(daily_counts),
            "peak_period": {"day": peak_day[0], "count": peak_day[1]},
            "spread_rate": spread_rate,
            "total_findings": total_findings,
            "active_days": total_days_with_findings,
        }


class CorrelationAnalysisOrchestrator:
    """
    Advanced correlation analysis using multiple techniques.

    Combines temporal, content-based, and contextual correlation to
    identify complex patterns across findings.
    """

    def __init__(self):
        self.content_analyzer = ContentSimilarityAnalyzer()
        self.temporal_analyzer = ContentSimilarityAnalyzer()  # Reuse for temporal

    def analyze_correlation_opportunities(
        self, user_id: int, db: Session
    ) -> List[Dict[str, Any]]:
        """
        Analyze all findings for correlation opportunities.

        Returns enriched correlation groups with temporal and content analysis.
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

        # Load gist descriptions and metadata
        gist_ids = set(f.gist_id for f in findings)
        gists = db.query(Gist).filter(Gist.id.in_(gist_ids)).all()
        gist_map = {g.id: g for g in gists}

        # Primary correlation by value_hash (most important)
        groups: Dict[str, TemporalCorrelationGroup] = {}

        for finding in findings:
            if not finding.value_hash:
                continue

            if finding.value_hash not in groups:
                groups[finding.value_hash] = TemporalCorrelationGroup(
                    value_hash=finding.value_hash,
                    secret_type=finding.secret_type or finding.finding_type or "unknown",
                )

            gist = gist_map.get(finding.gist_id)
            groups[finding.value_hash].add_finding(finding, gist)

        # Perform additional analysis for each group
        enriched_groups = []
        for group in groups.values():
            # Content similarity analysis
            content_analysis = self.content_analyzer.analyze_file_path_patterns(
                group.finding_ids, db
            )

            # Temporal analysis
            temp_analysis = self.temporal_analyzer.analyze_temporal_patterns(
                [f for f in findings if f.id in group.finding_ids], db
            )

            # Enrich group with analysis results
            group.temporal_patterns.update(content_analysis)
            group.temporal_patterns.update({"temporal_analysis": temp_analysis})

            enriched_groups.append(group)

        # Sort by severity, finding count, and temporal importance
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        enriched_groups.sort(
            key=lambda g: (
                severity_order.get(g._calculate_max_severity(), 0),
                len(g.finding_ids),
                g.last_seen or datetime.min,
            ),
            reverse=True,
        )

        return [group.to_dict() for group in enriched_groups]

    def identify_correlation_patterns(
        self, user_id: int, db: Session
    ) -> Dict[str, Any]:
        """
        Identify high-level correlation patterns across all findings.

        Returns statistics about correlation patterns that can inform
        prioritization and investigation strategies.
        """
        groups = self.analyze_correlation_opportunities(user_id, db)

        if not groups:
            return {
                "total_correlation_groups": 0,
                "total_related_findings": 0,
                "patterns": {},
                "prioritization_risks": [],
            }

        patterns = {
            "dominant_secret_types": {},
            "temporal_distribution": {},
            "severity_distribution": {},
            "cross_gist_patterns": {},
        }

        # Analyze secret type distribution
        secret_type_counter = Counter(g["secret_type"] for g in groups)
        patterns["dominant_secret_types"] = dict(secret_type_counter)

        # Temporal distribution
        all_first_seen = []
        for group in groups:
            first_seen = group.get("first_seen")
            if first_seen:
                all_first_seen.append(first_seen)

        if all_first_seen:
            # Group by day of week, month, etc.
            day_counter = Counter()
            for date_str in all_first_seen:
                try:
                    date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    day_of_week = date.strftime("%A")
                    day_counter[day_of_week] += 1
                except (ValueError, TypeError):
                    pass

            patterns["temporal_distribution"] = dict(day_counter)

        # Severity distribution
        severity_counter = Counter()
        for group in groups:
            max_severity = group.get("max_severity", "low")
            severity_counter[max_severity] += 1

        patterns["severity_distribution"] = dict(severity_counter)

        # Cross-gist patterns
        multi_gist_groups = [g for g in groups if g.get("gist_count", 0) > 1]
        patterns["cross_gist_patterns"] = {
            "multi_gist_count": len(multi_gist_groups),
            "multi_gist_percentage": (len(multi_gist_groups) / len(groups)) * 100 if groups else 0,
            "average_findings_per_group": sum(g.get("finding_count", 0) for g in groups) / len(groups) if groups else 0,
        }

        # Calculate prioritization risks
        prioritization_risks = []
        for group in groups:
            if group.get("finding_count", 0) >= 5 and group.get("max_severity", "low") in ["critical", "high"]:
                prioritization_risks.append({
                    "value_hash": group["value_hash"],
                    "risk_level": "high",
                    "reason": f"Large campaign: {group.get('finding_count', 0)} findings with {group.get('max_severity')} severity",
                })
            elif group.get("max_severity", "low") == "critical" and group.get("gist_count", 0) >= 3:
                prioritization_risks.append({
                    "value_hash": group["value_hash"],
                    "risk_level": "high",
                    "reason": f"Multi-gist critical leak: {group.get('gist_count', 0)} gists with critical severity",
                })

        return {
            "total_correlation_groups": len(groups),
            "total_related_findings": sum(g.get("finding_count", 0) for g in groups),
            "patterns": patterns,
            "prioritization_risks": prioritization_risks,
            "highly_correlated_groups": [
                {
                    "value_hash": g["value_hash"],
                    "secret_type": g["secret_type"],
                    "finding_count": g["finding_count"],
                    "gist_count": g["gist_count"],
                    "max_severity": g["max_severity"],
                    "risk_level": self._calculate_risk_level(g),
                }
                for g in groups
                if g.get("finding_count", 0) >= 3
            ],
        }

    def _calculate_risk_level(self, group: Dict[str, Any]) -> str:
        """Calculate overall risk level for a correlation group."""
        finding_count = group.get("finding_count", 0)
        gist_count = group.get("gist_count", 0)
        max_severity = group.get("max_severity", "low")

        if max_severity == "critical" and gist_count >= 3:
            return "CRITICAL"
        elif max_severity == "critical" and finding_count >= 5:
            return "HIGH"
        elif max_severity == "high" and finding_count >= 10:
            return "HIGH"
        elif max_severity == "high" and gist_count >= 2:
            return "MEDIUM"
        elif finding_count >= 5:
            return "MEDIUM"
        else:
            return "LOW"


# Module-level instance
correlation_analyzer = CorrelationAnalysisOrchestrator()
