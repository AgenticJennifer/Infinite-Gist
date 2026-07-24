from __future__ import annotations

from typing import Any

FAKE_GITHUB_TOKEN = "ghp_" + "2Zx9qLm7Pr8St6Uv4Wx5Yz7Aa9Bb0Cc1Dd2E"

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Finding, GitHubAccount, ScanRun, User
from app.scanner import GistScanner
from app.security import encrypt_token


class FakeGitHubClient:
    def list_authenticated_gists(self) -> list[dict[str, Any]]:
        return [{"id": "gist-1"}]

    def get_gist(self, gist_id: str) -> dict[str, Any]:
        return {
            "id": gist_id,
            "owner": {"login": "tester"},
            "description": "test",
            "html_url": "https://gist.github.com/gist-1",
            "public": True,
            "created_at": "2026-06-30T00:00:00Z",
            "updated_at": "2026-06-30T00:00:00Z",
            "history": [{"version": "current-sha", "committed_at": "2026-06-30T00:00:00Z"}],
            "files": {
                "clean.py": {
                    "filename": "clean.py",
                    "language": "Python",
                    "size": 20,
                    "truncated": False,
                    "content": "print('clean')\n",
                }
            },
        }

    def list_gist_commits(self, gist_id: str, max_items: int | None = None) -> list[dict[str, Any]]:
        return [{"version": "old-sha", "committed_at": "2026-06-29T00:00:00Z"}]

    def get_gist_revision(self, gist_id: str, revision_sha: str) -> dict[str, Any]:
        return {
            "id": gist_id,
            "owner": {"login": "tester"},
            "description": "test",
            "html_url": "https://gist.github.com/gist-1",
            "public": True,
            "history": [{"version": revision_sha, "committed_at": "2026-06-29T00:00:00Z"}],
            "files": {
                "settings.py": {
                    "filename": "settings.py",
                    "language": "Python",
                    "size": 90,
                    "truncated": False,
                    "content": f"GITHUB_TOKEN='{FAKE_GITHUB_TOKEN}'\n",
                }
            },
        }

    def fetch_raw_file(self, raw_url: str) -> str:
        return ""


def test_scanner_creates_history_only_masked_finding() -> None:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as db:
        user = User(id=1, display_name="test")
        db.add(user)
        account = GitHubAccount(
            user_id=1,
            github_login="tester",
            github_user_id="1",
            token_encrypted=encrypt_token("test-token"),
            scopes="test",
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        scan = ScanRun(user_id=1, github_account_id=account.id)
        db.add(scan)
        db.commit()
        db.refresh(scan)

        scanner = GistScanner(db, account, FakeGitHubClient(), max_revisions=10)
        scanner.run_scan(scan)

        finding = db.scalar(select(Finding))
        assert finding is not None
        assert finding.presence.value == "history_only"
        assert finding.evidences
        assert finding.evidences[0].masked_preview != FAKE_GITHUB_TOKEN
        assert FAKE_GITHUB_TOKEN not in finding.evidences[0].context_excerpt
