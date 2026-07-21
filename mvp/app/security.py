from __future__ import annotations

import hashlib
import hmac
import re
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


@lru_cache
def _fernet() -> Fernet:
    settings = get_settings()
    return Fernet(settings.resolved_fernet_key())


def encrypt_token(token: str) -> str:
    if not token:
        raise ValueError("token is required")
    return _fernet().encrypt(token.encode("utf-8")).decode("utf-8")


def decrypt_token(token_encrypted: str) -> str:
    try:
        return _fernet().decrypt(token_encrypted.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Could not decrypt GitHub token. Check FERNET_KEY.") from exc


def secret_fingerprint(secret_value: str, secret_family: str = "unknown") -> str:
    settings = get_settings()
    key_material = f"{settings.hmac_secret}:{secret_family}".encode("utf-8")
    return hmac.new(key_material, secret_value.encode("utf-8"), hashlib.sha256).hexdigest()


def destination_hash(destination: str) -> str:
    settings = get_settings()
    return hmac.new(settings.hmac_secret.encode("utf-8"), destination.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_secret(secret_value: str) -> str:
    if not secret_value:
        return ""
    clean = secret_value.strip()
    if len(clean) <= 8:
        return "*" * len(clean)
    if len(clean) <= 16:
        return f"{clean[:2]}...{clean[-2:]}"
    return f"{clean[:4]}...{clean[-4:]}"


def redact_line(line: str, secret_value: str) -> str:
    if not line:
        return ""
    if secret_value and secret_value in line:
        return line.replace(secret_value, mask_secret(secret_value))
    return _redact_probable_secret(line)


def _redact_probable_secret(line: str) -> str:
    patterns = [
        r"(gh[pousr]_[A-Za-z0-9_]{20,})",
        r"(github_pat_[A-Za-z0-9_]{20,})",
        r"(sk-[A-Za-z0-9]{20,})",
        r"(AKIA[0-9A-Z]{16})",
        r"(ASIA[0-9A-Z]{16})",
        r"(sk_live_[A-Za-z0-9]{16,})",
        r"(xox[baprs]-[A-Za-z0-9-]{16,})",
    ]
    redacted = line
    for pattern in patterns:
        redacted = re.sub(pattern, lambda m: mask_secret(m.group(1)), redacted)
    return redacted


def stable_finding_id(*parts: object) -> str:
    joined = "|".join(str(part) for part in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]


def is_probably_fake(value: str, context: str = "") -> bool:
    haystack = f"{value} {context}".lower()
    fake_terms = [
        "example",
        "sample",
        "dummy",
        "placeholder",
        "changeme",
        "change_me",
        "replace_me",
        "your_",
        "not_real",
        "not-a-real",
        "fake",
        "testonly",
        "test_only",
        "xxxxx",
        "zzzzz",
    ]
    if any(term in haystack for term in fake_terms):
        return True
    stripped = re.sub(r"[^A-Za-z0-9]", "", value)
    if stripped and len(set(stripped)) <= 3 and len(stripped) >= 12:
        return True
    return False
