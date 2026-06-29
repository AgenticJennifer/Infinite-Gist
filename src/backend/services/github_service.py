"""
Service for interacting with GitHub API.
"""

import httpx
from typing import List, Optional, Dict, Any
from datetime import datetime

from src.backend.core.config import settings
from src.backend.db.models import GitHubAccount


class GitHubService:
    BASE_URL = "https://api.github.com"

    def __init__(self, access_token: str):
        self.access_token = access_token
        self.headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    async def get_user(self) -> dict:
        """Get authenticated user information."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/user",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def get_user_gists(self, username: Optional[str] = None) -> List[dict]:
        """
        Get gists for the authenticated user or a specific user.
        If username is None, gets gists for the authenticated user.
        """
        if username:
            url = f"{self.BASE_URL}/users/{username}/gists"
        else:
            url = f"{self.BASE_URL}/gists"
        
        all_gists = []
        page = 1
        per_page = 100  # Maximum per page
        
        while True:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers=self.headers,
                    params={"page": page, "per_page": per_page},
                )
                response.raise_for_status()
                gists = response.json()
                
                if not gists:
                    break
                    
                all_gists.extend(gists)
                
                # Check if we got fewer than requested (last page)
                if len(gists) < per_page:
                    break
                    
                page += 1
                
        return all_gists

    async def get_gist(self, gist_id: str) -> dict:
        """Get a specific gist by ID."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/gists/{gist_id}",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def get_gist_commits(self, gist_id: str) -> List[dict]:
        """Get commit history for a specific gist."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/gists/{gist_id}/commits",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def get_gist_forks(self, gist_id: str) -> List[dict]:
        """Get forks for a specific gist."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/gists/{gist_id}/forks",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def check_rate_limit(self) -> dict:
        """Check current rate limit status."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/rate_limit",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def make_gist_private(self, gist_id: str) -> dict:
        """Make a gist private by updating its public status."""
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.BASE_URL}/gists/{gist_id}",
                headers=self.headers,
                json={"public": False},
            )
            response.raise_for_status()
            return response.json()

    async def delete_gist(self, gist_id: str) -> dict:
        """Delete a gist permanently."""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.BASE_URL}/gists/{gist_id}",
                headers=self.headers,
            )
            response.raise_for_status()
            # GitHub returns 204 No Content on successful delete
            if response.status_code == 204:
                return {"status": "deleted", "gist_id": gist_id}
            return response.json()


# Factory function to create GitHubService from database record
def get_github_service_for_account(github_account: GitHubAccount) -> GitHubService:
    """Create a GitHubService instance from a GitHubAccount database record."""
    # In a real implementation, you would decrypt the token here
    # For now, we're assuming the token is stored unencrypted (not recommended for production)
    return GitHubService(github_account.access_token)