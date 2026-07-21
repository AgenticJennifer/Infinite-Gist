from app.security import mask_secret, redact_line, secret_fingerprint


def test_mask_secret_preserves_shape_without_full_value() -> None:
    secret = "ghp_" + "2Zx9qLm7Pr8St6Uv4Wx5Yz7Aa9Bb0Cc1Dd2E"
    masked = mask_secret(secret)
    assert masked.startswith("ghp_")
    assert masked.endswith("Dd2E")
    assert secret not in masked


def test_fingerprint_is_stable_and_family_scoped() -> None:
    secret = "same-secret-value"
    assert secret_fingerprint(secret, "github") == secret_fingerprint(secret, "github")
    assert secret_fingerprint(secret, "github") != secret_fingerprint(secret, "aws")


def test_redact_line_removes_raw_secret() -> None:
    secret = "sk_live_" + "51N3qW8P9aBcD4eFgH5iJ6kLmN7oP8qRs"
    line = f"STRIPE_SECRET={secret}"
    redacted = redact_line(line, secret)
    assert secret not in redacted
    assert "sk_l" in redacted
