"""Focused unit tests for secret-scanning support services."""

import asyncio
import hashlib
import hmac
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.backend.db.models import SeverityLevel
from src.backend.services.evidence_masker import EvidenceMasker
from src.backend.services.secret_scanner import SecretMatch, SecretType
from src.backend.services.severity_scorer import ConfidenceLevel, SeverityScorer
from src.backend.services.triage_service import TriageService, TriageVerdict
from src.backend.services.trufflehog_scanner import TruffleHogScanner


def make_match(
    *,
    secret_type: SecretType = SecretType.API_KEY,
    value: str = "aB3$dE5&gH7*jK9!mN2@pQ4#",
    confidence: float = 0.6,
    file_path: str = "config.py",
    context: str = "",
) -> SecretMatch:
    return SecretMatch(
        type=secret_type,
        value=value,
        file_path=file_path,
        line_number=3,
        column_start=4,
        column_end=4 + len(value),
        confidence=confidence,
        matched_text=value,
        context=context,
    )


class TestTruffleHogScanner:
    def test_detector_mapping_supports_direct_partial_and_default_matches(self):
        assert TruffleHogScanner._map_detector_type("AWS") is SecretType.AWS_ACCESS_KEY
        assert (
            TruffleHogScanner._map_detector_type("GitHubOAuthV2")
            is SecretType.GITHUB_TOKEN
        )
        assert TruffleHogScanner._map_detector_type("UnknownDetector") is SecretType.API_KEY

    def test_normalize_finding_maps_metadata_and_verified_confidence(self):
        scanner = TruffleHogScanner("unused-trufflehog")
        finding = {
            "DetectorName": "Slack",
            "Raw": "xoxb-secret-value",
            "Verified": True,
            "Context": "SLACK_TOKEN=xoxb-secret-value",
            "SourceMetadata": {
                "File": {"path": "secrets.env", "line_start": 17}
            },
        }

        match = scanner._normalize_finding(finding, "fallback.txt")

        assert match is not None
        assert match.type is SecretType.SLACK_TOKEN
        assert match.value == "xoxb-secret-value"
        assert match.file_path == "secrets.env"
        assert match.line_number == 17
        assert match.column_end == len("xoxb-secret-value")
        assert match.confidence == 0.95
        assert match.context == finding["Context"]

    def test_is_available_uses_mocked_subprocess_and_caches_result(self):
        process = Mock(returncode=0)
        process.wait = AsyncMock()
        scanner = TruffleHogScanner("mock-trufflehog")

        with patch(
            "src.backend.services.trufflehog_scanner.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=process),
        ) as create_process:
            assert asyncio.run(scanner.is_available()) is True
            assert asyncio.run(scanner.is_available()) is True

        create_process.assert_awaited_once_with(
            "mock-trufflehog",
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    def test_scan_content_skips_without_creating_files_when_unavailable(self):
        scanner = TruffleHogScanner("missing-trufflehog")
        scanner.is_available = AsyncMock(return_value=False)

        with patch("src.backend.services.trufflehog_scanner.tempfile.TemporaryDirectory") as tempdir:
            result = asyncio.run(scanner.scan_content("raw secret", "config.env"))

        assert result == []
        tempdir.assert_not_called()


class TestSeverityScorer:
    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            (0.85, ConfidenceLevel.DEFINITE),
            (0.65, ConfidenceLevel.PROBABLE),
            (0.6499, ConfidenceLevel.POSSIBLE),
        ],
    )
    def test_confidence_threshold_boundaries(self, confidence, expected):
        assert SeverityScorer()._classify_confidence(confidence) is expected

    @pytest.mark.parametrize(
        ("secret_type", "confidence", "expected_severity"),
        [
            (SecretType.AWS_ACCESS_KEY, 0.9, SeverityLevel.CRITICAL),
            (SecretType.AWS_ACCESS_KEY, 0.4, SeverityLevel.HIGH),
            (SecretType.SLACK_TOKEN, 0.4, SeverityLevel.MEDIUM),
            (SecretType.EMAIL, 0.4, SeverityLevel.LOW),
        ],
    )
    def test_score_maps_types_and_demotes_only_low_confidence_risks(
        self, secret_type, confidence, expected_severity
    ):
        severity, _ = SeverityScorer().score(
            make_match(secret_type=secret_type, confidence=confidence)
        )
        assert severity is expected_severity

    def test_compute_value_hash_uses_configured_secret_key(self):
        with patch("src.backend.services.severity_scorer.settings.SECRET_KEY", "unit-key"):
            result = SeverityScorer.compute_value_hash("sensitive-value")

        expected = hmac.new(
            b"unit-key", b"sensitive-value", hashlib.sha256
        ).hexdigest()
        assert result == expected
        assert result != hashlib.sha256(b"sensitive-value").hexdigest()

    def test_mask_value_handles_short_and_long_values(self):
        assert SeverityScorer.mask_value("abc") == "ab***"
        assert SeverityScorer.mask_value("abcdefghij", visible_chars=2) == "ab******ij"


class TestEvidenceMasker:
    def test_mask_context_replaces_every_secret_occurrence(self):
        masker = EvidenceMasker(visible_prefix=2, visible_suffix=2)
        secret = "abcdefghij"
        context = f"first={secret}\nsecond={secret}"

        masked = masker.mask_context(context, secret)

        assert secret not in masked
        assert masked.count("ab******ij") == 2

    def test_create_masked_evidence_redacts_context_and_selects_secret_line(self):
        masker = EvidenceMasker()
        secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        context = f"# configuration\nTOKEN={secret}\nDEBUG=false"

        evidence = masker.create_masked_evidence(
            value=secret,
            matched_text=secret,
            context=context,
            value_hash="safe-hash",
            secret_type="github_token",
            severity="critical",
            confidence=0.95,
        )

        assert secret not in evidence.masked_value
        assert secret not in evidence.context_masked
        assert secret not in evidence.snippet
        assert evidence.snippet == f"TOKEN={evidence.masked_value}"
        assert evidence.value_hash == "safe-hash"
        assert evidence.confidence == 0.95

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("", "***"), ("key123", "ke****"), ("12345678", "12******")],
    )
    def test_mask_value_empty_and_short_values(self, value, expected):
        assert EvidenceMasker().mask_value(value) == expected


class TestTriageService:
    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [(0.7, TriageVerdict.ACCEPT), (0.4999, TriageVerdict.REJECT)],
    )
    def test_triage_range_boundaries_fast_path(self, confidence, expected):
        assert TriageService().triage(make_match(confidence=confidence)) is expected

    def test_high_risk_file_and_matching_context_are_accepted(self):
        match = make_match(
            confidence=0.6,
            file_path="production.env",
            context="API_KEY is loaded at startup",
        )
        assert TriageService().triage(match) is TriageVerdict.ACCEPT

    def test_placeholder_in_documentation_is_rejected(self):
        match = make_match(
            value="example-api-key-123456",
            confidence=0.6,
            file_path="README.md",
        )
        assert TriageService().triage(match) is TriageVerdict.REJECT

    def test_neutral_borderline_finding_is_escalated(self):
        match = make_match(
            secret_type=SecretType.GITHUB_TOKEN,
            value="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            confidence=0.6,
            file_path="module.py",
            context="token loaded here",
        )
        assert TriageService().triage(match) is TriageVerdict.ESCALATE

    def test_triage_batch_separates_auto_and_each_borderline_verdict(self):
        service = TriageService()
        auto_high = make_match(confidence=0.8)
        auto_low = make_match(confidence=0.4)
        accepted = make_match(confidence=0.6, file_path="app.env", context="api_key")
        rejected = make_match(
            confidence=0.6, value="dummy-key-123456789", file_path="README.md"
        )
        escalated = make_match(
            secret_type=SecretType.GITHUB_TOKEN,
            confidence=0.6,
            value="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        )

        result = service.triage_batch(
            [auto_high, auto_low, accepted, rejected, escalated]
        )

        assert result == {
            "accept": [accepted],
            "reject": [rejected],
            "escalate": [escalated],
            "auto": [auto_high, auto_low],
        }

    def test_helpers_handle_case_no_extension_and_entropy_extremes(self):
        assert TriageService._get_extension("CONFIG.YAML") == ".yaml"
        assert TriageService._get_extension("Makefile") == ""
        assert TriageService._shannon_entropy("") == 0.0
        assert TriageService._shannon_entropy("aaaaaaaa") == 0.0
        assert TriageService._shannon_entropy("abcdefgh") == pytest.approx(3.0)
