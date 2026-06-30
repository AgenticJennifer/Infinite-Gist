"""
Security utilities for password hashing and JWT tokens.
"""

import base64
from datetime import datetime, timedelta
from typing import Optional

from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.backend.core.config import settings
from src.backend.db.models import User


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(*, data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def get_current_user(token: str, db: Session):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


def get_encryption_key():
    """Get or create encryption key for token encryption."""
    key = settings.ENCRYPTION_KEY
    # Ensure it's 32 bytes for Fernet
    if len(key) < 32:
        # Pad or hash to 32 bytes
        key = base64.urlsafe_b64encode(key.ljust(32)[:32].encode())
    elif len(key) > 32:
        key = base64.urlsafe_b64encode(key[:32].encode())
    else:
        key = key.encode()
    return Fernet(key)


def encrypt_token(token: str) -> str:
    """Encrypt a token for storage."""
    f = get_encryption_key()
    encrypted = f.encrypt(token.encode())
    return encrypted.decode()


def decrypt_token(encrypted_token: str) -> str:
    """Decrypt a token from storage."""
    f = get_encryption_key()
    decrypted = f.decrypt(encrypted_token.encode())
    return decrypted.decode()
