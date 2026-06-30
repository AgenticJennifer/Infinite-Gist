"""
Severity scoring service with confidence levels.

Maps secret types to severity tiers and classifies findings into
confidence levels: definite, probable, possible.

This module provides enhanced severity scoring with multiple confidence
levels including high/medium/low classification for Phase 2 workflow.
"""

import hashlib
from enum import Enum

from src.backend.services.secret_scanner import SecretType, SecretMatch
from src.backend.db.models import SeverityLevel


class ConfidenceLevel(str, Enum):
    """Classification of finding confidence."""
    DEFINITE = "definite"     # Verified or pattern-matched with high entropy
    PROBABLE = "probable"     # Strong pattern match with context support
    POSSIBLE = "possible"    # Weak pattern match, may be false positive


# Secret type → severity tier mapping
SEVERITY_MAP: dict[SecretType, SeverityLevel] = {
    SecretType.AWS_ACCESS_KEY: SeverityLevel.CRITICAL,
    SecretType.AWS_SECRET_KEY: SeverityLevel.CRITICAL,
    SecretType.GITHUB_TOKEN: SeverityLevel.CRITICAL,
    SecretType.SSH_PRIVATE_KEY: SeverityLevel.CRITICAL,
    SecretType.PRIVATE_KEY: SeverityLevel.CRITICAL,
    SecretType.SLACK_TOKEN: SeverityLevel.HIGH,
    SecretType.CREDIT_CARD: SeverityLevel.HIGH,
    SecretType.SOCIAL_SECURITY: SeverityLevel.HIGH,
    SecretType.API_KEY: SeverityLevel.MEDIUM,
    SecretType.PASSWORD: SeverityLevel.MEDIUM,
    SecretType.EMAIL: SeverityLevel.LOW,
}

# Confidence thresholds
CONFIDENCE_DEFINITE_THRESHOLD = 0.85
CONFIDENCE_PROBABLE_THRESHOLD = 0.65
# Below PROBABLE → POSSIBLE


class SeverityScorer:
    """Scores finding severity and assigns confidence levels."""

    def score(self, match: SecretMatch) -> tuple[SeverityLevel, ConfidenceLevel]:
        """
        Return (severity, confidence_level) for a given match.

        Severity is based primarily on secret type, with adjustments
        for context. Confidence level is based on the float confidence score.
        """
        base_severity = SEVERITY_MAP.get(match.type, SeverityLevel.MEDIUM)
        confidence_level = self._classify_confidence(match.confidence)

        # Adjust severity based on context
        severity = self._adjust_severity(base_severity, match, confidence_level)

        return severity, confidence_level

    def _classify_confidence(self, confidence: float) -> ConfidenceLevel:
        """Map float confidence to a discrete confidence level."""
        if confidence >= CONFIDENCE_DEFINITE_THRESHOLD:
            return ConfidenceLevel.DEFINITE
        elif confidence >= CONFIDENCE_PROBABLE_THRESHOLD:
            return ConfidenceLevel.PROBABLE
        else:
            return ConfidenceLevel.POSSIBLE

    def _adjust_severity(
        self,
        base: SeverityLevel,
        match: SecretMatch,
        confidence_level: ConfidenceLevel,
    ) -> SeverityLevel:
        """
        Adjust severity based on context and confidence.

        - Definite + CRITICAL → stays CRITICAL
        - Possible + CRITICAL → demote to HIGH
        - Possible + HIGH → demote to MEDIUM
        - Public gist → promote one level (exposure surface)
        """
        severity = base

        # Demote if confidence is only possible
        if confidence_level == ConfidenceLevel.POSSIBLE:
            if severity == SeverityLevel.CRITICAL:
                severity = SeverityLevel.HIGH
            elif severity == SeverityLevel.HIGH:
                severity = SeverityLevel.MEDIUM

        return severity

    @staticmethod
    def compute_value_hash(value: str) -> str:
        """Compute SHA-256 hash of a secret value for deduplication."""
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def mask_value(value: str, visible_chars: int = 4) -> str:
        """
        Mask a secret value showing only first/last few chars.

        Example: "ghp_abc123def456" → "ghp_************456"
        """
        if len(value) <= visible_chars * 2:
            # Too short to meaningfully mask — show only first 2 chars
            return value[:2] + "*" * max(len(value) - 2, 3)

        prefix = value[:visible_chars]
        suffix = value[-visible_chars:]
        masked_len = len(value) - visible_chars * 2
        return f"{prefix}{'*' * masked_len}{suffix}"


# Module-level instance
severity_scorer = SeverityScorer()
