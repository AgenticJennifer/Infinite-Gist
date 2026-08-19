"""Service for interacting with the GitHub Gist API."""

import httpx
import asyncio
import os
import tempfile
from cryptography.fernet import InvalidToken
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from src.backend.core.config import settings
from src.backend.core.security import decrypt_token
from src.backend.db.models import GitHubAccount


class GitHubService:
    BASE_URL = "https://api.github.com"

    def __init__(self, access_token: str):
        self.access_token = access_token
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
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

    async def get_gist_revision(self, gist_id: str, sha: str) -> dict:
        """Get one documented Gist revision by commit SHA."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/gists/{gist_id}/{sha}",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def get_file_content(self, file_data: dict) -> str:
        """Return complete file content while constraining raw URL fetches."""
        content = file_data.get("content")
        if content is not None and not file_data.get("truncated", False):
            return str(content)

        raw_url = file_data.get("raw_url")
        if not raw_url:
            return str(content or "")

        parsed = urlparse(raw_url)
        if parsed.scheme != "https" or parsed.hostname != "gist.githubusercontent.com":
            raise ValueError("GitHub returned an untrusted raw Gist URL")

        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await client.get(raw_url, headers=self.headers)
            response.raise_for_status()
            if len(response.content) > settings.MAX_GIST_FILE_BYTES:
                raise ValueError(
                    "Gist file exceeds the configured in-memory scan limit"
                )
            return response.text

    async def get_complete_files(
        self, gist_data: dict, revision: Optional[str] = None
    ) -> dict[str, dict]:
        """Resolve complete file bodies, cloning only when REST truncates the list."""
        if gist_data.get("truncated", False):
            return await self._clone_gist_files(gist_data, revision)

        complete: dict[str, dict] = {}
        for filename, file_data in gist_data.get("files", {}).items():
            resolved = dict(file_data)
            resolved["content"] = await self.get_file_content(file_data)
            resolved["truncated"] = False
            complete[filename] = resolved
        return complete

    async def _clone_gist_files(
        self, gist_data: dict, revision: Optional[str]
    ) -> dict[str, dict]:
        clone_url = gist_data.get("git_pull_url")
        if not isinstance(clone_url, str):
            raise ValueError("GitHub did not return a Gist clone URL")
        parsed = urlparse(clone_url)
        if parsed.scheme != "https" or parsed.hostname != "gist.github.com":
            raise ValueError("GitHub returned an untrusted Gist clone URL")

        env = os.environ.copy()
        env.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {self.access_token}",
            }
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "gist"
            await self._run_git(
                "git",
                "clone",
                "--quiet",
                "--no-checkout",
                clone_url,
                str(target),
                env=env,
            )
            await self._run_git(
                "git",
                "-C",
                str(target),
                "checkout",
                "--quiet",
                revision or "HEAD",
                env=env,
            )

            files: dict[str, dict] = {}
            for path in target.rglob("*"):
                if not path.is_file() or path.is_symlink() or ".git" in path.parts:
                    continue
                size = path.stat().st_size
                if size > settings.MAX_GIST_FILE_BYTES:
                    raise ValueError(
                        f"Gist file {path.name} exceeds the configured scan limit"
                    )
                filename = path.relative_to(target).as_posix()
                files[filename] = {
                    "filename": filename,
                    "size": size,
                    "content": path.read_text(encoding="utf-8", errors="replace"),
                    "truncated": False,
                }
            return files

    @staticmethod
    async def _run_git(*args: str, env: dict[str, str]) -> None:
        process = await asyncio.create_subprocess_exec(
            *args,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"Git clone failed: {stderr.decode()[:300]}")

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

    async def replace_public_gist_with_secret(self, gist_id: str) -> dict:
        """Create a secret replacement, then delete the original public Gist.

        GitHub does not support changing a public Gist to secret in place. This
        explicit replacement flow changes the Gist URL and does not preserve its
        revision history.
        """
        original = await self.get_gist(gist_id)
        complete_files = await self.get_complete_files(original)
        files: dict[str, dict[str, str]] = {}
        for filename, file_data in complete_files.items():
            files[filename] = {"content": str(file_data.get("content", ""))}
        if not files:
            raise ValueError("Cannot replace a Gist with no readable files")

        async with httpx.AsyncClient() as client:
            create_response = await client.post(
                f"{self.BASE_URL}/gists",
                headers=self.headers,
                json={
                    "description": original.get("description"),
                    "public": False,
                    "files": files,
                },
            )
            create_response.raise_for_status()
            replacement = create_response.json()

        replacement_id = str(replacement["id"])
        try:
            await self.delete_gist(gist_id)
        except Exception:
            try:
                await self.delete_gist(replacement_id)
            except Exception:
                pass
            raise

        return {
            "status": "replaced",
            "original_gist_id": gist_id,
            "replacement_gist_id": replacement_id,
            "replacement_url": replacement.get("html_url"),
            "public": bool(replacement.get("public", True)),
        }


# Factory function to create GitHubService from database record
def get_github_service_for_account(github_account: GitHubAccount) -> GitHubService:
    """Create a GitHubService instance from a GitHubAccount database record."""
    try:
        access_token = decrypt_token(github_account.access_token_encrypted)
    except InvalidToken:
        # Encryption key changed or token corrupted — do NOT fall back to the
        # encrypted blob (it would be sent to GitHub as plaintext). Fail loudly.
        raise ValueError(
            "Could not decrypt GitHub access token for account "
            f"{github_account.id}. The ENCRYPTION_KEY may have changed."
        )
    return GitHubService(access_token)
