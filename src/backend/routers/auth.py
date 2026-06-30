"""
Authentication routes for GitHub OAuth.
"""

from datetime import timedelta
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from urllib.parse import urlencode

from src.backend.core.config import settings
from src.backend.core.security import create_access_token, encrypt_token, verify_password
from src.backend.db.session import get_db
from src.backend.db.models import User, GitHubAccount
from src.backend.schemas.auth import Token

router = APIRouter()


@router.get("/github/login")
async def github_login():
    """
    Redirect user to GitHub OAuth authorization page.
    """
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": "read:gist,user:email",
        "state": "random_state_string",  # In production, use a secure random state
    }
    github_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(github_auth_url)


@router.get("/github/callback")
async def github_callback(
    request: Request, 
    code: str, 
    state: str,
    db: Session = Depends(get_db)
):
    """
    Handle GitHub OAuth callback.
    """
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code not provided"
        )
    
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
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
                detail="Failed to obtain access token from GitHub"
            )
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Access token not found in response"
            )
        
        # Get user information from GitHub
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/json",
            },
        )
        
        if user_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch user information from GitHub"
            )
        
        github_user = user_response.json()
        
        # Get user emails (need email scope for this)
        emails_response = await client.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/json",
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
                detail="Could not retrieve verified email from GitHub"
            )
    
    # Check if user already exists in our database
    user = db.query(User).filter(User.email == primary_email).first()
    
    if not user:
        # Create new user
        user = User(
            email=primary_email,
            username=github_user.get("login"),
            full_name=github_user.get("name") or github_user.get("login"),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    
    # Check if GitHub account already linked
    github_account = (
        db.query(GitHubAccount)
        .filter(GitHubAccount.user_id == user.id)
        .filter(GitHubAccount.github_id == str(github_user.get("id")))
        .first()
    )
    
    encrypted_access_token = encrypt_token(access_token)

    if not github_account:
        # Create new GitHub account association
        github_account = GitHubAccount(
            user_id=user.id,
            github_id=str(github_user.get("id")),
            username=github_user.get("login"),
            access_token_encrypted=encrypted_access_token,
            refresh_token_encrypted=None,  # GitHub doesn't provide refresh tokens by default
            token_expires_at=None,  # GitHub tokens don't expire by default unless you use a GitHub App
            scope=token_data.get("scope") or "read:gist,user:email",
        )
        db.add(github_account)
        db.commit()
        db.refresh(github_account)
    else:
        # Update existing token
        github_account.access_token_encrypted = encrypted_access_token
        github_account.scope = token_data.get("scope") or github_account.scope
        db.commit()
        db.refresh(github_account)
    
    # Create access token for our application
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Redirect to frontend with token
    frontend_url = "http://localhost:3000/auth/callback"
    params = urlencode({"access_token": access_token, "token_type": "bearer"})
    return RedirectResponse(f"{frontend_url}?{params}")


@router.post("/token", response_model=Token)
async def login_for_access_token(
    username: str, password: str, db: Session = Depends(get_db)
):
    """
    OAuth2 compatible token login, get an access token for future requests.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
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
