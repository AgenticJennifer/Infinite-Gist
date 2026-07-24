from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable

from app.models import Severity
from app.security import is_probably_fake

DETECTOR_VERSION = "2026.06.30-v1"


@dataclass(frozen=True)
class DetectorMatch:
    detector_id: str
    detector_version: str
    finding_type: str
    secret_value: str
    severity: Severity
    confidence: int
    line_start: int
    line_end: int
    line_text: str
    explanation: str
    validity_state: str = "unverified"


@dataclass(frozen=True)
class RegexRule:
    detector_id: str
    finding_type: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: int
    explanation: str
    value_group: int = 1
    fake_downrank: bool = True


RULES: list[RegexRule] = [
    RegexRule(
        detector_id="github_token_classic",
        finding_type="github_token",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"),
        severity=Severity.critical,
        confidence=95,
        explanation="Matched a GitHub token-shaped value.",
    ),
    RegexRule(
        detector_id="github_token_fine_grained",
        finding_type="github_token",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{30,})\b"),
        severity=Severity.critical,
        confidence=95,
        explanation="Matched a fine-grained GitHub personal access token-shaped value.",
    ),
    RegexRule(
        detector_id="aws_access_key_id",
        finding_type="aws_access_key_id",
        pattern=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        severity=Severity.high,
        confidence=95,
        explanation="Matched an AWS access key id-shaped value.",
    ),
    RegexRule(
        detector_id="aws_secret_access_key_assignment",
        finding_type="aws_secret_access_key",
        pattern=re.compile(
            r"(?i)\b(?:aws_?)?(?:secret|private)?_?access_?key(?:_id)?\b\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        severity=Severity.critical,
        confidence=90,
        explanation="Matched an AWS secret access key assignment pattern.",
    ),
    RegexRule(
        detector_id="openai_api_key",
        finding_type="openai_api_key",
        pattern=re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"),
        severity=Severity.high,
        confidence=85,
        explanation="Matched an OpenAI-style API key pattern.",
    ),
    RegexRule(
        detector_id="stripe_live_secret_key",
        finding_type="stripe_secret_key",
        pattern=re.compile(r"\b(sk_live_[A-Za-z0-9]{16,})\b"),
        severity=Severity.critical,
        confidence=95,
        explanation="Matched a live-mode Stripe secret key pattern.",
    ),
    RegexRule(
        detector_id="stripe_test_secret_key",
        finding_type="stripe_secret_key",
        pattern=re.compile(r"\b(sk_test_[A-Za-z0-9]{16,})\b"),
        severity=Severity.medium,
        confidence=90,
        explanation="Matched a test-mode Stripe secret key pattern.",
    ),
    RegexRule(
        detector_id="slack_token",
        finding_type="slack_token",
        pattern=re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{16,})\b"),
        severity=Severity.high,
        confidence=90,
        explanation="Matched a Slack token-shaped value.",
    ),
    RegexRule(
        detector_id="database_url_with_password",
        finding_type="database_connection_string",
        pattern=re.compile(
            r"\b((?:postgresql|postgres|mysql|mongodb(?:\+srv)?)://[^:\s/]+:[^@\s]+@[^\s]+)",
            re.IGNORECASE,
        ),
        severity=Severity.critical,
        confidence=90,
        explanation="Matched a database URL that contains credential material before the host.",
    ),
    RegexRule(
        detector_id="password_or_token_assignment",
        finding_type="credential_assignment",
        pattern=re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*[\"']?([^\s\"'`,;]{12,})[\"']?"
        ),
        severity=Severity.medium,
        confidence=65,
        explanation="Matched a credential-like assignment. This is heuristic and needs review.",
    ),
]

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+)?PRIVATE KEY-----",
    re.MULTILINE,
)


def scan_content(content: str) -> list[DetectorMatch]:
    matches: list[DetectorMatch] = []
    strong_values: set[str] = set()
    heuristic_rule_ids = {"password_or_token_assignment"}
    for rule in RULES:
        for regex_match in rule.pattern.finditer(content):
            value = regex_match.group(rule.value_group)
            if rule.detector_id in heuristic_rule_ids and value in strong_values:
                continue
            line_no = _line_number(content, regex_match.start(rule.value_group))
            line_text = _line_at(content, line_no)
            severity = rule.severity
            confidence = rule.confidence
            if rule.fake_downrank and is_probably_fake(value, line_text):
                severity = _downrank(severity)
                confidence = min(confidence, 35)
            matches.append(
                DetectorMatch(
                    detector_id=rule.detector_id,
                    detector_version=DETECTOR_VERSION,
                    finding_type=rule.finding_type,
                    secret_value=value,
                    severity=severity,
                    confidence=confidence,
                    line_start=line_no,
                    line_end=line_no,
                    line_text=line_text,
                    explanation=rule.explanation,
                )
            )
            if rule.detector_id not in heuristic_rule_ids and confidence >= 85:
                strong_values.add(value)

    matches.extend(_scan_private_keys(content))
    entropy_matches = [
        match for match in _scan_high_entropy_assignments(content) if match.secret_value not in strong_values
    ]
    matches.extend(entropy_matches)
    return _dedupe_matches(matches)


def detector_rule_catalog() -> Iterable[dict[str, object]]:
    for rule in RULES:
        yield {
            "detector_id": rule.detector_id,
            "version": DETECTOR_VERSION,
            "finding_type": rule.finding_type,
            "default_severity": rule.severity,
            "description": rule.explanation,
        }
    yield {
        "detector_id": "private_key_block",
        "version": DETECTOR_VERSION,
        "finding_type": "private_key",
        "default_severity": Severity.critical,
        "description": "Matched a PEM/OpenSSH private key block.",
    }
    yield {
        "detector_id": "high_entropy_assignment",
        "version": DETECTOR_VERSION,
        "finding_type": "high_entropy_secret",
        "default_severity": Severity.medium,
        "description": "Matched a high-entropy value assigned to a sensitive variable name.",
    }


def recommended_action(finding_type: str, severity: Severity) -> str:
    if finding_type in {
        "github_token",
        "aws_access_key_id",
        "aws_secret_access_key",
        "openai_api_key",
        "stripe_secret_key",
        "slack_token",
        "database_connection_string",
        "private_key",
    }:
        return (
            "Rotate or revoke the credential first. Then remove it from current Gist content. "
            "After cleanup, run verification. Treat history exposure as residual risk until the secret is rotated."
        )
    if severity in {Severity.critical, Severity.high}:
        return (
            "Review immediately. Remove exposed sensitive material, rotate any related credential, "
            "and run verification."
        )
    return "Review context. If benign, mark false positive or accepted risk with a reason."


def residual_risk_for_presence(presence: str) -> str:
    if presence == "history_only":
        return "Current content appears clean, but accessible revision history still contains the finding."
    if presence == "current_and_history":
        return "The finding appears in current content and accessible revision history."
    if presence == "current":
        return "The finding appears in current content. Historical exposure was not observed in this scan."
    return "No current or historical evidence was observed in the latest verification scan."


def _scan_private_keys(content: str) -> list[DetectorMatch]:
    matches: list[DetectorMatch] = []
    for regex_match in PRIVATE_KEY_PATTERN.finditer(content):
        value = regex_match.group(0)
        line_start = _line_number(content, regex_match.start())
        line_end = _line_number(content, regex_match.end())
        line_text = _line_at(content, line_start)
        matches.append(
            DetectorMatch(
                detector_id="private_key_block",
                detector_version=DETECTOR_VERSION,
                finding_type="private_key",
                secret_value=value,
                severity=Severity.critical,
                confidence=98,
                line_start=line_start,
                line_end=line_end,
                line_text=line_text,
                explanation="Matched a PEM/OpenSSH private key block.",
            )
        )
    return matches


def _scan_high_entropy_assignments(content: str) -> list[DetectorMatch]:
    matches: list[DetectorMatch] = []
    pattern = re.compile(
        r"(?i)\b(?:secret|token|api[_-]?key|client[_-]?secret|auth)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{24,})[\"']?"
    )
    for regex_match in pattern.finditer(content):
        value = regex_match.group(1)
        if is_probably_fake(value, _line_at(content, _line_number(content, regex_match.start(1)))):
            continue
        entropy = shannon_entropy(value)
        if entropy < 4.2:
            continue
        line_no = _line_number(content, regex_match.start(1))
        matches.append(
            DetectorMatch(
                detector_id="high_entropy_assignment",
                detector_version=DETECTOR_VERSION,
                finding_type="high_entropy_secret",
                secret_value=value,
                severity=Severity.medium,
                confidence=70,
                line_start=line_no,
                line_end=line_no,
                line_text=_line_at(content, line_no),
                explanation="Matched a high-entropy value assigned to a sensitive variable name.",
            )
        )
    return matches


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _line_number(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def _line_at(content: str, line_number: int) -> str:
    lines = content.splitlines()
    if not lines:
        return ""
    if line_number < 1:
        line_number = 1
    if line_number > len(lines):
        line_number = len(lines)
    return lines[line_number - 1]


def _downrank(severity: Severity) -> Severity:
    order = [Severity.low, Severity.medium, Severity.high, Severity.critical]
    idx = order.index(severity)
    return order[max(0, idx - 2)]


def _dedupe_matches(matches: list[DetectorMatch]) -> list[DetectorMatch]:
    seen: set[tuple[str, str, int, int]] = set()
    deduped: list[DetectorMatch] = []
    for match in matches:
        key = (match.detector_id, match.secret_value, match.line_start, match.line_end)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return deduped
