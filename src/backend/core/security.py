"""
Authentication utilities and dependencies.

Security Notes:
- JWT tokens use HS256 with configurable secret key
- GitHub tokens are encrypted with Fernet before database storage
- Key derivation uses PBKDF2 with 600,000 iterations (OWASP 2023 recommendation)
"""

import base64
import hashlib
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.fernet import Fernet
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from src.backend.core.config import settings
from src.backend.db.session import get_db
from src.backend.db.models import User

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


# In-memory store of issued OAuth state nonces (single-process MVP).
# Maps nonce -> expiry epoch. Consumed (single-use) on successful verification
# so a state token cannot be replayed. A multi-worker deployment would need a
# shared store (e.g. Redis) instead.
_oauth_state_store: dict[str, float] = {}


def create_oauth_state_token(expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed, expiring, single-use state token for OAuth CSRF protection."""
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=10))
    nonce = base64.urlsafe_b64encode(os.urandom(16)).decode()

    # Prune expired entries to bound memory.
    now_ts = time.time()
    for expired_nonce in [n for n, e in _oauth_state_store.items() if e < now_ts]:
        del _oauth_state_store[expired_nonce]

    _oauth_state_store[nonce] = expire.timestamp()
    to_encode = {"nonce": nonce, "exp": expire, "purpose": "oauth_state"}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_oauth_state_token(state: str) -> bool:
    """Verify a state token returned from the OAuth callback.

    Returns True only if the token is valid, unexpired, and corresponds to a
    state we actually issued (the nonce is consumed, so it is single-use).
    """
    try:
        payload = jwt.decode(
            state, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
    except JWTError:
        return False
    if payload.get("purpose") != "oauth_state":
        return False
    nonce = payload.get("nonce")
    if not isinstance(nonce, str):
        return False
    expiry = _oauth_state_store.pop(nonce, None)
    if expiry is None:
        return False
    if expiry < time.time():
        return False
    return True


def _derive_fernet_key(raw_key: str) -> bytes:
    """
    Derive a valid 32-byte urlsafe-base64 Fernet key from an arbitrary secret.

    Uses PBKDF2-HMAC-SHA256 with:
    - 600,000 iterations (OWASP 2023 recommendation)
    - Fixed salt derived from the key itself (deterministic for consistent encryption)

    This is significantly more secure than single-pass SHA-256 against rainbow table attacks.
    """
    # Use a fixed salt derived from the key name for determinism
    # This is acceptable because the key itself is secret
    salt = b"infinite-gist-encryption-salt-v1"

    # PBKDF2 with 600,000 iterations (OWASP 2023 recommendation)
    dk = hashlib.pbkdf2_hmac(
        "sha256", raw_key.encode("utf-8"), salt, iterations=600000, dklen=32
    )
    return base64.urlsafe_b64encode(dk)


def _get_fernet() -> Fernet:
    """Build a Fernet instance from the configured encryption key."""
    configured_key = settings.ENCRYPTION_KEY.encode()
    try:
        return Fernet(configured_key)
    except ValueError:
        return Fernet(_derive_fernet_key(settings.ENCRYPTION_KEY))


def encrypt_token(token: str) -> str:
    """Encrypt a GitHub token before database storage."""
    return _get_fernet().encrypt(token.encode()).decode()


def decrypt_token(encrypted_token: str) -> str:
    """Decrypt a GitHub token for outbound GitHub API calls."""
    return _get_fernet().decrypt(encrypted_token.encode()).decode()


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
):
    if not current_user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")
    return current_user
