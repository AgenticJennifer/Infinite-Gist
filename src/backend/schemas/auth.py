"""
Pydantic models for authentication.
"""

from pydantic import BaseModel, EmailStr
from typing import Optional


class Token(BaseModel):
    access_token: str
    token_type: str

    class Config:
        from_attributes = True


class TokenData(BaseModel):
    username: str
    password: str


class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None


class UserInDBBase(UserBase):
    id: int
    is_active: bool

    class Config:
        from_attributes = True


class UserInDB(UserInDBBase):
    hashed_password: str


class User(UserInDBBase):
    pass


class GitHubAccountBase(BaseModel):
    github_id: str
    username: str


class GitHubAccountCreate(GitHubAccountBase):
    access_token_encrypted: str
    refresh_token_encrypted: Optional[str] = None
    token_expires_at: Optional[str] = None
    scope: str


class GitHubAccountUpdate(BaseModel):
    access_token_encrypted: Optional[str] = None
    refresh_token_encrypted: Optional[str] = None
    token_expires_at: Optional[str] = None
    scope: Optional[str] = None


class GitHubAccountInDBBase(GitHubAccountBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True


class GitHubAccountInDB(GitHubAccountInDBBase):
    access_token_encrypted: str
    refresh_token_encrypted: Optional[str] = None
    token_expires_at: Optional[str] = None
    scope: str


class GitHubAccount(GitHubAccountInDBBase):
    access_token_encrypted: str
    refresh_token_encrypted: Optional[str] = None
    token_expires_at: Optional[str] = None
    scope: str