"""
API v1 router configuration.
"""

from fastapi import APIRouter

from src.backend.api.v1.endpoints import auth, gists, remediation, schedules, policies, digests, trends

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(gists.router, prefix="/gists", tags=["gists"])
api_router.include_router(remediation.router, prefix="/remediation", tags=["remediation"])
api_router.include_router(schedules.router, prefix="/schedules", tags=["schedules"])
api_router.include_router(policies.router, prefix="/policies", tags=["policies"])
api_router.include_router(digests.router, prefix="/digests", tags=["digests"])
api_router.include_router(trends.router, prefix="/trends", tags=["trends"])
