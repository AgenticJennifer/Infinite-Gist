"""Focused unit tests for the regex-based secret scanner."""

import hashlib

import pytest

from src.backend.services.secret_scanner import (
    SecretMatch,
    SecretScanner,
    SecretType,
    scan_content,
)


@pytest.fixture
def scanner() -> SecretScanner:
    return SecretScanner()


def test_secret_match_masks_short_and_long_values():
    short = SecretMatch(
        type=SecretType.PASSWORD,
        value="abc123",
        file_path=".env",
        line_number=1,
        column_start=0,
        column_end=6,
        confidence=0.8,
        matched_text="abc123",
        context="password=abc123",
    )
    long_value = "ghp_" + "A" * 36
    long = SecretMatch(
        type=SecretType.GITHUB_TOKEN,
        value=long_value,
        file_path="config.py",
        line_number=1,
        column_start=0,
        column_end=len(long_value),
        confidence=0.95,
        matched_text=long_value,
        context=long_value,
    )

    assert short.masked_value == "ab****"
    assert long.masked_value == "ghp_" + "*" * 32 + "AAAA"
    assert long.value_hash == hashlib.sha256(long_value.encode()).hexdigest()


def test_detects_github_token_with_location_metadata(scanner):
    token = "ghp_" + "A" * 36
    matches = scanner.scan_text(f'AUTH_TOKEN = "{token}"', "config.py")

    assert len(matches) == 1
    match = matches[0]
    assert match.type == SecretType.GITHUB_TOKEN
    assert match.value == token
    assert match.file_path == "config.py"
    assert match.line_number == 1
    assert match.column_start == 14
    assert match.column_end == 54
    assert match.confidence == 1.0


def test_extracts_only_aws_secret_capture_group(scanner):
    secret = "aB3/" * 10
    matches = scanner.scan_text(
        f'aws_secret_access_key = "{secret}"',
        ".env",
    )

    assert len(matches) == 1
    assert matches[0].type == SecretType.AWS_SECRET_KEY
    assert matches[0].value == secret
    assert matches[0].matched_text == secret


def test_suppresses_placeholder_context_but_not_value_substrings(scanner):
    token = "ghp_" + "A" * 36
    assert scanner.scan_text(f'example_token = "{token}"', "README.md") == []

    published_aws_example = "AKIAIOSFODNN7EXAMPLE"
    matches = scanner.scan_text(
        f'aws_access_key_id = "{published_aws_example}"',
        ".env",
    )
    assert len(matches) == 1


def test_scans_multiline_unicode_content(scanner):
    token = "ghp_" + "B" * 36
    matches = scanner.scan_text(f"说明 = 'safe'\ngithub_token = '{token}'", "配置.py")

    assert len(matches) == 1
    assert matches[0].line_number == 2
    assert matches[0].file_path == "配置.py"


def test_empty_content_has_no_matches(scanner):
    assert scanner.scan_text("") == []


def test_scan_content_exposes_only_masked_secret_data():
    token = "ghp_" + "C" * 36
    result = scan_content(f'github_token = "{token}"', "settings.py")[0]

    assert result["type"] == SecretType.GITHUB_TOKEN.value
    assert result["value"] == result["masked_value"]
    assert result["matched_text"] == result["masked_value"]
    assert token not in result["context"]
    assert result["masked_value"] in result["context"]
    assert token not in repr(result)
    assert len(result["value_hash"]) == 64
