"""
Enhanced severity scoring with confidence levels and temporal importance.

Extensions to the basic SeverityScorer for Phase 2 of the Infinite Gist project.
This module adds high/medium/low confidence classification and temporal
ranking of secret findings.
"""

from typing import Tuple
from enum import IntEnum

from src.backend.services.severity_scorer import SeverityScorer, ConfidenceLevel, SeverityLevel
from src.backend.services.secret_scanner import SecretMatch


class ConfidenceCategory(IntEnum):
    """High/Medium/Low confidence levels for Phase 2 workflow."""
    HIGH = 3     # 0.85-1.0 confidence (DEFINITE)
    MEDIUM = 2   # 0.65-0.84 confidence (PROBABLE)
    LOW = 1      # < 0.65 confidence (POSSIBLE)


class ScoringType:
    """Scoring categories for risk assessment."""
    IMMEDIATE_THREAT = "immediate_threat"
    SIGNIFICANT_RISK = "significant_risk"
    LOW_PRIORITY = "low_priority"
    FALSE_POSITIVE = "false_positive"


class EnhancedSeverityScorer(SeverityScorer):
    """Extended severity scorer with comprehensive risk assessment."""

    def score_with_category(
        self, match: SecretMatch
    ) -> Tuple[SeverityLevel, ConfidenceLevel, ConfidenceCategory, str]:
        """
        Complete scoring with all assessment categories.

        Returns:
            Tuple of (severity_level, confidence_level, confidence_category, score_type)
        """
        base_severity, confidence_level = super().score(match)
        confidence_category = self._classify_confidence_category(match.confidence)
        score_type = self._determine_score_type(base_severity, confidence_category)

        # Adjust severity based on both context and confidence category for enhanced scoring
        severity = self._adjust_severity_enhanced(base_severity, match, confidence_category, score_type)

        return severity, confidence_level, confidence_category, score_type

    def _classify_confidence_category(self, confidence: float) -> ConfidenceCategory:
        """Map float confidence to high/medium/low category."""
        if confidence >= 0.85:
            return ConfidenceCategory.HIGH
        elif confidence >= 0.65:
            return ConfidenceCategory.MEDIUM
        else:
            return ConfidenceCategory.LOW

    def _determine_score_type(
        self, severity: SeverityLevel, category: ConfidenceCategory
    ) -> str:
        """Determine overall score type based on severity and confidence."""
        if severity == SeverityLevel.CRITICAL and category in (ConfidenceCategory.HIGH, ConfidenceCategory.MEDIUM):
            return ScoringType.IMMEDIATE_THREAT
        elif severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) and category == ConfidenceCategory.HIGH:
            return ScoringType.IMMEDIATE_THREAT
        elif severity in (SeverityLevel.HIGH, SeverityLevel.MEDIUM):
            return ScoringType.SIGNIFICANT_RISK
        elif severity == SeverityLevel.MEDIUM and category == ConfidenceCategory.MEDIUM:
            return ScoringType.SIGNIFICANT_RISK
        elif category == ConfidenceCategory.LOW:
            return ScoringType.LOW_PRIORITY
        else:
            return ScoringType.FALSE_POSITIVE

    def _adjust_severity_enhanced(
        self,
        base: SeverityLevel,
        match: SecretMatch,
        confidence_category: ConfidenceCategory,
        score_type: str,
    ) -> SeverityLevel:
        """Enhanced severity adjustment incorporating confidence categories."""
        severity = base

        # More aggressive demotion for low confidence
        if confidence_category == ConfidenceCategory.LOW:
            if severity == SeverityLevel.CRITICAL:
                severity = SeverityLevel.HIGH
            elif severity == SeverityLevel.HIGH:
                severity = SeverityLevel.MEDIUM
            elif severity == SeverityLevel.MEDIUM:
                severity = SeverityLevel.LOW

        # Special handling for immediate threats
        if score_type == ScoringType.IMMEDIATE_THREAT:
            if severity == SeverityLevel.MEDIUM:
                severity = SeverityLevel.HIGH
            elif severity == SeverityLevel.LOW:
                severity = SeverityLevel.MEDIUM

        return severity

    def calculate_risk_score(
        self,
        severity: SeverityLevel,
        confidence_category: ConfidenceCategory,
        score_type: str,
    ) -> float:
        """Calculate a numeric risk score (0-100)."""
        # Base score from severity
        severity_scores = {
            SeverityLevel.CRITICAL: 90,
            SeverityLevel.HIGH: 70,
            SeverityLevel.MEDIUM: 40,
            SeverityLevel.LOW: 10,
        }
        score = severity_scores.get(severity, 0)

        # Confidence multiplier
        confidence_multipliers = {
            ConfidenceCategory.HIGH: 1.2,
            ConfidenceCategory.MEDIUM: 1.0,
            ConfidenceCategory.LOW: 0.7,
        }
        score *= confidence_multipliers.get(confidence_category, 1.0)

        # Score type multipliers
        type_multipliers = {
            ScoringType.IMMEDIATE_THREAT: 1.5,
            ScoringType.SIGNIFICANT_RISK: 1.2,
            ScoringType.LOW_PRIORITY: 0.8,
            ScoringType.FALSE_POSITIVE: 0.3,
        }
        score *= type_multipliers.get(score_type, 1.0)

        return min(score, 100.0)


# Module-level instance
enhanced_scorer = EnhancedSeverityScorer()
