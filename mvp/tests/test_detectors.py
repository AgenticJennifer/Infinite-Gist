from app.detectors import scan_content
from app.models import Severity


def test_detects_github_token() -> None:
    token = "ghp_" + "2Zx9qLm7Pr8St6Uv4Wx5Yz7Aa9Bb0Cc1Dd2E"
    content = f"GITHUB_TOKEN={token}\n"
    matches = scan_content(content)
    assert any(match.finding_type == "github_token" for match in matches)
    match = next(match for match in matches if match.finding_type == "github_token")
    assert match.severity == Severity.critical
    assert match.confidence >= 90


def test_downranks_obvious_placeholder() -> None:
    content = "api_key=your_api_key_placeholder_1234567890\n"
    matches = scan_content(content)
    assert matches
    assert all(match.confidence <= 65 for match in matches)


def test_detects_private_key_block() -> None:
    content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----
"""
    matches = scan_content(content)
    assert any(match.finding_type == "private_key" for match in matches)
