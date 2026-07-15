"""
Dependencies for API endpoints.

Auth dependencies are defined in ``src.backend.core.security`` and re-exported
here so endpoint modules can import them from a single, stable location.
"""

from src.backend.core.security import get_current_user, get_current_active_user

__all__ = ["get_current_user", "get_current_active_user"]
