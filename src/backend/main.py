"""
Main FastAPI application entry point for Infinite Gist.
"""

import logging
from contextlib import contextmanager
from typing import Generator

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from sqlalchemy import text
from fastapi.responses import JSONResponse

from src.backend.api.v1.api import api_router
from src.backend.core.config import settings
from src.backend.db.session import get_db
from src.backend.core.security import get_current_active_user
from src.backend.services.github_service import GitHubService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Infinite Gist API",
    description="Security monitoring and remediation platform for GitHub Gists",
    version="0.1.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Set up CORS middleware
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

frontend_path = "src/frontend"
app.mount("/static", StaticFiles(directory=frontend_path), name="static")


@app.get("/")
async def root():
    from fastapi.responses import FileResponse
    import os
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Welcome to Infinite Gist API"}


@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint with database connectivity verification."""
    try:
        # Test database connectivity
        db.execute(text("SELECT 1")).fetchone()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail="Database connection error"
        )


@contextmanager
def application_scope():
    """Application lifecycle management context manager."""
    logger.info("Starting application lifecycle")
    try:
        yield
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        raise
    finally:
        logger.info("Application lifecycle completed")


# Add exception handlers
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})