from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from app.config import get_settings


class GitHubApiError(RuntimeError):
    pass


class GitHubRateLimitError(GitHubApiError):
    pass


@dataclass(frozen=True)
class GistFileContent:
    filename: str
    content: str
    raw_url: str | None
    truncated: bool
    size: int | None
    language: str | None


class GitHubClient:
    def __init__(self, token: str, api_base_url: str | None = None) -> None:
        self.settings = get_settings()
        self.token = token
        self.api_base_url = (api_base_url or self.settings.github_api_base_url).rstrip("/")
        self.client = httpx.Client(timeout=30.0)

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "infinite-gist-mvp/0.1",
        }

    def _request(self, method: str, path_or_url: str, **kwargs: Any) -> httpx.Response:
        url = path_or_url if path_or_url.startswith("http") else f"{self.api_base_url}{path_or_url}"
        headers = kwargs.pop("headers", {})
        merged_headers = {**self._headers(), **headers}
        response = self.client.request(method, url, headers=merged_headers, **kwargs)
        if response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0":
            reset = response.headers.get("x-ratelimit-reset")
            raise GitHubRateLimitError(f"GitHub API rate limit exceeded. Reset epoch: {reset}")
        if response.status_code >= 400:
            body = _safe_body(response)
            raise GitHubApiError(f"GitHub API error {response.status_code}: {body}")
        return response

    def get_authenticated_user(self) -> dict[str, Any]:
        return self._request("GET", "/user").json()

    def list_authenticated_gists(self) -> list[dict[str, Any]]:
        return self._paginate("/gists?per_page=100")

    def get_gist(self, gist_id: str) -> dict[str, Any]:
        return self._request("GET", f"/gists/{gist_id}").json()

    def list_gist_commits(self, gist_id: str, max_items: int | None = None) -> list[dict[str, Any]]:
        commits = self._paginate(f"/gists/{gist_id}/commits?per_page=100")
        if max_items is not None:
            return commits[:max_items]
        return commits

    def get_gist_revision(self, gist_id: str, revision_sha: str) -> dict[str, Any]:
        return self._request("GET", f"/gists/{gist_id}/{revision_sha}").json()

    def fetch_raw_file(self, raw_url: str) -> str:
        # raw_url is still fetched with auth so private or secret Gists work when the token permits it.
        return self._request("GET", raw_url).text

    def _paginate(self, first_path: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        next_url: str | None = first_path
        while next_url:
            response = self._request("GET", next_url)
            data = response.json()
            if not isinstance(data, list):
                raise GitHubApiError("Expected a list response from GitHub pagination endpoint")
            results.extend(data)
            next_url = _parse_next_link(response.headers.get("link"))
        return results


def extract_gist_files(gist_payload: dict[str, Any], client: GitHubClient | None = None) -> list[GistFileContent]:
    files = gist_payload.get("files") or {}
    extracted: list[GistFileContent] = []
    for fallback_name, metadata in files.items():
        filename = metadata.get("filename") or fallback_name
        raw_url = metadata.get("raw_url")
        truncated = bool(metadata.get("truncated"))
        content = metadata.get("content") or ""
        if truncated and raw_url and client is not None:
            content = client.fetch_raw_file(raw_url)
        extracted.append(
            GistFileContent(
                filename=filename,
                content=content,
                raw_url=raw_url,
                truncated=truncated,
                size=metadata.get("size"),
                language=metadata.get("language"),
            )
        )
    return extracted


def parse_github_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            return parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None


def exchange_oauth_code(code: str) -> dict[str, Any]:
    settings = get_settings()
    if not settings.github_client_id or not settings.github_client_secret:
        raise RuntimeError("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are required for OAuth")
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            settings.github_oauth_token_url,
            headers={"Accept": "application/json", "User-Agent": "infinite-gist-mvp/0.1"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": settings.github_callback_url,
            },
        )
        if response.status_code >= 400:
            raise GitHubApiError(f"OAuth token exchange failed: {_safe_body(response)}")
        payload = response.json()
        if "access_token" not in payload:
            raise GitHubApiError(f"OAuth token exchange failed: {_safe_body(response)}")
        return payload


def _parse_next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        if not section.startswith("<") or ">" not in section:
            continue
        url = section[1 : section.index(">")]
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        # Return the full URL to preserve all query params and avoid base path mistakes.
        if parsed.scheme and parsed.netloc:
            return url
        if "page" in query:
            return f"{parsed.path}?{parsed.query}"
    return None


def _safe_body(response: httpx.Response) -> str:
    text = response.text[:500]
    return text.replace("\n", " ")
