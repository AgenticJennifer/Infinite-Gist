"""
Authentication endpoints for GitHub OAuth.
"""

import httpx
import secrets
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from urllib.parse import urlencode

from src.backend.core.config import settings
from src.backend.core.security import (
    create_access_token,
    create_oauth_state_token,
    encrypt_token,
    verify_oauth_state_token,
    verify_password,
)
from src.backend.db.session import get_db
from src.backend.db.models import User, GitHubAccount
from src.backend.core.rate_limit import enforce_login_rate_limit
from src.backend.schemas.auth import Token, User as UserSchema
from src.backend.api.deps import get_current_active_user

router = APIRouter()


@router.get("/github/login")
async def github_login():
    """
    Redirect user to GitHub OAuth authorization page.
    """
    state = create_oauth_state_token()
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": " ".join(settings.GITHUB_SCOPES),
        "state": state,
    }
    github_auth_url = f"{settings.GITHUB_AUTHORIZATION_URL}?{urlencode(params)}"
    return RedirectResponse(github_auth_url)


@router.get("/github/callback")
async def github_callback(code: str, state: str, db: Session = Depends(get_db)):
    """
    Handle GitHub OAuth callback.
    """
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code not provided",
        )

    if not state or not verify_oauth_state_token(state):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state parameter",
        )

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            settings.GITHUB_TOKEN_URL,
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_REDIRECT_URI,
            },
            headers={"Accept": "application/json"},
        )

        if token_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to obtain access token from GitHub",
            )

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Access token not found in response",
            )

        # Get user information from GitHub
        user_response = await client.get(
            f"{settings.GITHUB_API_BASE_URL}/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

        if user_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch user information from GitHub",
            )

        github_user = user_response.json()

        # Get user emails (need email scope for this)
        emails_response = await client.get(
            f"{settings.GITHUB_API_BASE_URL}/user/emails",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

        primary_email = None
        if emails_response.status_code == 200:
            emails = emails_response.json()
            for email_obj in emails:
                if email_obj.get("primary", False) and email_obj.get("verified", False):
                    primary_email = email_obj.get("email")
                    break

        # If no verified primary email, use the first verified email
        if not primary_email and emails_response.status_code == 200:
            emails = emails_response.json()
            for email_obj in emails:
                if email_obj.get("verified", False):
                    primary_email = email_obj.get("email")
                    break

        if not primary_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not retrieve verified email from GitHub",
            )

    github_id = str(github_user.get("id") or "")
    github_username = github_user.get("login")
    if not github_id or not github_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub profile did not include a stable identity",
        )

    # Resolve an existing GitHub identity before email. This preserves the same
    # local account when a user changes their primary email on GitHub.
    github_account = (
        db.query(GitHubAccount).filter(GitHubAccount.github_id == github_id).first()
    )
    if github_account:
        user = github_account.user
        email_owner = db.query(User).filter(User.email == primary_email).first()
        if not email_owner or email_owner.id == user.id:
            user.email = primary_email
        user.full_name = github_user.get("name") or github_username
    else:
        user = db.query(User).filter(User.email == primary_email).first()

    if not user:
        user = User(
            email=primary_email,
            username=github_username,
            full_name=github_user.get("name") or github_username,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    encrypted_access_token = encrypt_token(access_token)

    if not github_account:
        github_account = GitHubAccount(
            user_id=user.id,
            github_id=github_id,
            username=github_username,
            access_token_encrypted=encrypted_access_token,
            refresh_token_encrypted=None,
            token_expires_at=None,
            scope=token_data.get("scope") or ",".join(settings.GITHUB_SCOPES),
        )
        db.add(github_account)
        db.commit()
        db.refresh(github_account)
    else:
        github_account.access_token_encrypted = encrypted_access_token
        github_account.username = github_username
        github_account.scope = token_data.get("scope") or github_account.scope
        db.commit()
        db.refresh(github_account)

    # Create access token for our application
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    app_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    callback_url = f"{settings.FRONTEND_URL.rstrip('/')}/#/dashboard"
    response = RedirectResponse(callback_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        "session_token",
        app_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
    )
    response.set_cookie(
        "csrf_token",
        secrets.token_urlsafe(32),
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
    )
    return response


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    _: None = Depends(enforce_login_rate_limit),
    db: Session = Depends(get_db),
):
    """
    OAuth2 compatible token login, get an access token for future requests.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    # Reject missing/invalid password and OAuth-only accounts (no password set).
    if (
        not user
        or not user.hashed_password
        or not verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me", response_model=UserSchema)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """
    Get current user.
    """
    return current_user


@router.get("/github/accounts")
async def list_github_accounts(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """List linked accounts without exposing encrypted credentials."""
    accounts = (
        db.query(GitHubAccount)
        .filter(GitHubAccount.user_id == current_user.id)
        .order_by(GitHubAccount.created_at)
        .all()
    )
    return [
        {
            "id": account.id,
            "github_id": account.github_id,
            "username": account.username,
            "scope": account.scope,
        }
        for account in accounts
    ]


@router.post("/logout")
async def logout():
    response = JSONResponse({"detail": "Signed out"})
    response.delete_cookie(
        "session_token", secure=settings.COOKIE_SECURE, samesite="lax"
    )
    response.delete_cookie(
        "csrf_token", secure=settings.COOKIE_SECURE, samesite="strict"
    )
    return response
