"""
Application configuration and settings.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
import secrets


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Infinite Gist"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    ALGORITHM: str = "HS256"
    
    # Database
    DATABASE_URL: str = "sqlite:///./infinite_gist.db"
    
    # GitHub OAuth
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_AUTHORIZATION_URL: str = "https://github.com/login/oauth/authorize"
    GITHUB_TOKEN_URL: str = "https://github.com/login/oauth/access_token"
    GITHUB_API_BASE_URL: str = "https://api.github.com"
    GITHUB_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/github/callback"
    GITHUB_SCOPES: List[str] = ["read:gist", "user:email"]
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    
    # Phase 2: Detection settings
    TRUFFLEHOG_PATH: str = "trufflehog"
    ENABLE_TRUFFLEHOG: bool = True
    TRIAGE_CONFIDENCE_LOW: float = 0.5
    TRIAGE_CONFIDENCE_HIGH: float = 0.7

    # Rate limiting
    GITHUB_API_RATE_LIMIT_PER_HOUR: int = 5000

    # Security settings
    ENCRYPTION_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    
    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()