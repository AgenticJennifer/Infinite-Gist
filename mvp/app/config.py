from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Infinite Gist MVP"
    app_secret: str = "dev-only-change-me"
    database_url: str = "sqlite:///./infinite_gist.db"
    fernet_key: Optional[str] = None
    hmac_secret: str = "dev-only-hmac-change-me"
    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    github_callback_url: str = "http://127.0.0.1:8000/auth/github/callback"
    allow_dev_pat_connect: bool = True
    raw_secret_reveal_enabled: bool = False
    max_revisions_per_gist: int = Field(default=100, ge=0, le=10000)
    github_api_base_url: str = "https://api.github.com"
    github_oauth_authorize_url: str = "https://github.com/login/oauth/authorize"
    github_oauth_token_url: str = "https://github.com/login/oauth/access_token"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    def resolved_fernet_key(self) -> bytes:
        if self.fernet_key:
            return self.fernet_key.encode("utf-8")
        # Stable in dev only. Production must set FERNET_KEY.
        digest = hashlib.sha256(self.app_secret.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)


@lru_cache
def get_settings() -> Settings:
    return Settings()
