"""Integration-style security tests for the scanner orchestration pipeline."""

import asyncio
import hashlib
import hmac
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

from src.backend.services.gist_scanner import GistScannerService
from src.backend.services.secret_scanner import SecretMatch, SecretType
from src.backend.services.triage_service import TriageVerdict


def make_db(existing=None):
    db = Mock()
    db.query.return_value.filter.return_value.first.return_value = existing
    return db


def make_match(value, *, confidence=0.95, column_start=0):
    return SecretMatch(
        type=SecretType.GITHUB_TOKEN,
        value=value,
        file_path="config.py",
        line_number=2,
        column_start=column_start,
        column_end=column_start + len(value),
        confidence=confidence,
        matched_text=value,
        context=f'github_token = "{value}"',
    )


def test_pipeline_masks_and_hmacs_secret_before_persistence():
    token = "ghp_" + "D" * 36
    db = make_db()
    service = GistScannerService(db)
    gist = cast(Any, SimpleNamespace(id=11))
    gist_file = cast(Any, SimpleNamespace(id=22))

    with (
        patch("src.backend.services.gist_scanner.settings.ENABLE_TRUFFLEHOG", False),
        patch("src.backend.services.severity_scorer.settings.SECRET_KEY", "pipeline-key"),
    ):
        findings = asyncio.run(
            service._scan_file(
                f'# settings\ngithub_token = "{token}"',
                "config.py",
                gist,
                gist_file,
            )
        )

    assert len(findings) == 1
    finding = cast(Any, findings[0])
    expected_hash = hmac.new(
        b"pipeline-key", token.encode(), hashlib.sha256
    ).hexdigest()
    assert finding.value_hash == expected_hash
    assert finding.value_hash != hashlib.sha256(token.encode()).hexdigest()
    assert token not in finding.masked_value
    assert token not in finding.content_snippet
    assert token not in repr({key: value for key, value in vars(finding).items() if not key.startswith("_sa_")})
    assert finding.gist_id == 11
    assert finding.gist_file_id == 22
    db.add.assert_called_once_with(finding)
    db.commit.assert_called_once()


def test_pipeline_does_not_persist_rejected_findings():
    token = "ghp_" + "E" * 36
    db = make_db()
    service = GistScannerService(db)
    service.regex_scanner.scan_text = Mock(return_value=[make_match(token, confidence=0.6)])
    service.triage.triage = Mock(return_value=TriageVerdict.REJECT)

    with patch("src.backend.services.gist_scanner.settings.ENABLE_TRUFFLEHOG", False):
        findings = asyncio.run(
            service._scan_file(
                token,
                "README.md",
                cast(Any, SimpleNamespace(id=1)),
                cast(Any, SimpleNamespace(id=2)),
            )
        )

    assert findings == []
    db.query.assert_not_called()
    db.add.assert_not_called()
    db.commit.assert_not_called()


def test_pipeline_skips_existing_hmac_fingerprint():
    token = "ghp_" + "F" * 36
    existing = SimpleNamespace(id=99)
    db = make_db(existing=existing)
    service = GistScannerService(db)

    with (
        patch("src.backend.services.gist_scanner.settings.ENABLE_TRUFFLEHOG", False),
        patch("src.backend.services.severity_scorer.settings.SECRET_KEY", "dedupe-key"),
    ):
        findings = asyncio.run(
            service._scan_file(
                f'github_token = "{token}"',
                "config.py",
                cast(Any, SimpleNamespace(id=1)),
                cast(Any, SimpleNamespace(id=2)),
            )
        )

    assert findings == []
    db.add.assert_not_called()
    db.commit.assert_not_called()


def test_merge_prefers_trufflehog_at_same_position_and_keeps_unique_matches():
    shared_regex = make_match("ghp_" + "G" * 36, column_start=4)
    shared_trufflehog = make_match("ghp_" + "H" * 36, column_start=4)
    unique_regex = make_match("ghp_" + "I" * 36, column_start=60)

    merged = GistScannerService._merge_matches(
        [shared_regex, unique_regex],
        [shared_trufflehog],
    )

    assert merged == [shared_trufflehog, unique_regex]
