"""
Database session and engine configuration.
"""

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker, Session
from src.backend.core.config import settings
from src.backend.db.models import Base


def _engine_kwargs(database_url: str) -> dict:
    """Return SQLAlchemy engine options appropriate for the configured backend."""
    url = make_url(database_url)
    if url.drivername.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {}


# Create database engine
engine = create_engine(
    settings.DATABASE_URL, **_engine_kwargs(settings.DATABASE_URL)
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Session:
    """
    Dependency function to get DB session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """
    Create all database tables.
    """
    Base.metadata.create_all(bind=engine)
