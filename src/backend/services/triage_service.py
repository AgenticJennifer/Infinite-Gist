"""
Model-based triage service for borderline findings.

Applies heuristic rules to findings in the 0.5-0.7 confidence range
to classify them as likely true positives or false positives.
Findings below 0.5 are already filtered; findings above 0.7 are
accepted without triage.
"""

import logging
import re
from typing import List
from enum import Enum

from src.backend.services.secret_scanner import SecretMatch, SecretType

logger = logging.getLogger(__name__)


class TriageVerdict(str, Enum):
    """Result of triage for a borderline finding."""
    ACCEPT = "accept"           # Likely true positive
    REJECT = "reject"           # Likely false positive
    ESCALATE = "escalate"       # Cannot determine automatically


# Triage thresholds
TRIAGE_LOW = 0.5
TRIAGE_HIGH = 0.7

# Known false-positive patterns
FALSE_POSITIVE_PATTERNS = [
    re.compile(r"example|sample|test|dummy|fake|placeholder|todo", re.IGNORECASE),
    re.compile(r"^\s*#\s*(comment|todo|fixme)", re.IGNORECASE),
    re.compile(r"<[^>]+>"),     # HTML/template placeholders
    re.compile(r"\$\{[^}]+\}"),  # Template variables like ${API_KEY}
    re.compile(r"xxx+|aaa+|bbb+|123+|000+"),  # Placeholder sequences
]

# Known true-positive indicators in surrounding context
TRUE_POSITIVE_INDICATORS = {
    SecretType.AWS_ACCESS_KEY: ["aws_access_key_id", "aws_key", "akid"],
    SecretType.AWS_SECRET_KEY: ["aws_secret_access_key", "aws_secret", "secret_key"],
    SecretType.GITHUB_TOKEN: ["github_token", "gh_token", "octokit"],
    SecretType.SLACK_TOKEN: ["slack_token", "slack_webhook", "slack_hook"],
    SecretType.API_KEY: ["api_key", "apikey", "api-secret", "secret_key", "auth_token"],
    SecretType.PASSWORD: ["password", "passwd", "pwd", "pass"],
    SecretType.PRIVATE_KEY: ["private_key", "privkey", "rsa_key"],
}

# File extensions where secrets are more likely to be real
HIGH_RISK_EXTENSIONS = {".env", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".toml"}

# File extensions where secrets are often placeholders
LOW_RISK_EXTENSIONS = {".md", ".txt", ".rst", ".doc", ".example", ".sample"}


class TriageService:
    """Triage borderline findings (confidence 0.5-0.7)."""

    def triage(self, match: SecretMatch) -> TriageVerdict:
        """
        Apply triage heuristics to a borderline finding.

        Returns:
        - ACCEPT: likely a true positive
        - REJECT: likely a false positive
        - ESCALATE: needs human review
        """
        # If outside triage range, fast-path
        if match.confidence >= TRIAGE_HIGH:
            return TriageVerdict.ACCEPT
        if match.confidence < TRIAGE_LOW:
            return TriageVerdict.REJECT

        score = 0.0  # Running triage score

        # 1. Check for false-positive patterns in the matched text
        if any(p.search(match.matched_text) for p in FALSE_POSITIVE_PATTERNS):
            score -= 2.0

        # 2. Check for true-positive indicators in context
        indicators = TRUE_POSITIVE_INDICATORS.get(match.type, [])
        context_lower = match.context.lower() if match.context else ""
        matched_lower = match.matched_text.lower()

        for indicator in indicators:
            if indicator in context_lower or indicator in matched_lower:
                score += 1.5
                break

        # 3. Check file extension
        if match.file_path:
            ext = self._get_extension(match.file_path)
            if ext in HIGH_RISK_EXTENSIONS:
                score += 1.0
            elif ext in LOW_RISK_EXTENSIONS:
                score -= 1.0

        # 4. Entropy check for certain secret types
        if match.type in (
            SecretType.AWS_SECRET_KEY,
            SecretType.API_KEY,
            SecretType.PASSWORD,
        ):
            entropy = self._shannon_entropy(match.matched_text)
            if entropy > 4.0:
                score += 0.5  # High entropy = likely real
            elif entropy < 2.0:
                score -= 1.0  # Very low entropy = likely placeholder

        # 5. Length heuristics
        if match.type == SecretType.PASSWORD:
            if len(match.matched_text) < 6:
                score -= 1.0  # Very short "passwords" are often placeholders

        # Apply verdict
        if score >= 1.0:
            return TriageVerdict.ACCEPT
        elif score <= -1.0:
            return TriageVerdict.REJECT
        else:
            return TriageVerdict.ESCALATE

    def triage_batch(
        self, matches: List[SecretMatch]
    ) -> dict[str, List[SecretMatch]]:
        """
        Triage a batch of borderline findings.

        Returns:
        {
            "accept": [...matches...],
            "reject": [...matches...],
            "escalate": [...matches...],
            "auto": [...matches outside triage range...]
        }
        """
        result: dict[str, List[SecretMatch]] = {
            "accept": [],
            "reject": [],
            "escalate": [],
            "auto": [],
        }

        for match in matches:
            if match.confidence >= TRIAGE_HIGH or match.confidence < TRIAGE_LOW:
                result["auto"].append(match)
                continue

            verdict = self.triage(match)
            result[verdict.value].append(match)

        return result

    @staticmethod
    def _get_extension(file_path: str) -> str:
        """Extract file extension, lowercase."""
        if "." in file_path:
            return "." + file_path.rsplit(".", 1)[-1].lower()
        return ""

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        from collections import Counter
        counts = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * (p.bit_length() - 1)  # log2 approximation

        # More accurate calculation
        import math
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy


# Module-level instance
triage_service = TriageService()
