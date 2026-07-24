from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from typing import Any

FAKE_DB_URL = "postgres://app:" + "ProdPassw0rd123456" + "@db.internal/prod"
FAKE_GITHUB_TOKEN = "ghp_" + "2Zx9qLm7Pr8St6Uv4Wx5Yz7Aa9Bb0Cc1Dd2E"

from app.db import SessionLocal, init_db
from app.main import ensure_default_user
from app.models import GitHubAccount, ScanRun
from app.scanner import GistScanner, sync_detector_rules
from app.security import encrypt_token


class DemoGitHubClient:
    def list_authenticated_gists(self) -> list[dict[str, Any]]:
        return [{"id": "demo-current"}, {"id": "demo-history"}]

    def get_gist(self, gist_id: str) -> dict[str, Any]:
        if gist_id == "demo-current":
            return {
                "id": "demo-current",
                "owner": {"login": "demo-user"},
                "description": "Current-content exposure demo",
                "html_url": "https://gist.github.com/demo-current",
                "public": True,
                "created_at": "2026-06-30T00:00:00Z",
                "updated_at": "2026-06-30T00:00:00Z",
                "history": [{"version": "sha-current-1", "committed_at": "2026-06-30T00:00:00Z"}],
                "files": {
                    "app.env": {
                        "filename": "app.env",
                        "language": "Shell",
                        "size": 140,
                        "truncated": False,
                        "content": f"DATABASE_URL={FAKE_DB_URL}\n",
                    }
                },
            }
        return {
            "id": "demo-history",
            "owner": {"login": "demo-user"},
            "description": "History-only exposure demo",
            "html_url": "https://gist.github.com/demo-history",
            "public": True,
            "created_at": "2026-06-30T00:00:00Z",
            "updated_at": "2026-06-30T00:00:00Z",
            "history": [{"version": "sha-history-current", "committed_at": "2026-06-30T00:00:00Z"}],
            "files": {
                "snippet.py": {
                    "filename": "snippet.py",
                    "language": "Python",
                    "size": 20,
                    "truncated": False,
                    "content": "print('clean now')\n",
                }
            },
        }

    def list_gist_commits(self, gist_id: str, max_items: int | None = None) -> list[dict[str, Any]]:
        if gist_id == "demo-current":
            return [{"version": "sha-current-1", "committed_at": "2026-06-30T00:00:00Z"}]
        return [
            {"version": "sha-history-current", "committed_at": "2026-06-30T00:00:00Z"},
            {"version": "sha-history-old", "committed_at": "2026-06-29T00:00:00Z"},
        ][:max_items]

    def get_gist_revision(self, gist_id: str, revision_sha: str) -> dict[str, Any]:
        if gist_id == "demo-history" and revision_sha == "sha-history-old":
            return {
                "id": gist_id,
                "owner": {"login": "demo-user"},
                "description": "History-only exposure demo",
                "html_url": "https://gist.github.com/demo-history",
                "public": True,
                "history": [{"version": revision_sha, "committed_at": "2026-06-29T00:00:00Z"}],
                "files": {
                    "snippet.py": {
                        "filename": "snippet.py",
                        "language": "Python",
                        "size": 120,
                        "truncated": False,
                        "content": f"token = '{FAKE_GITHUB_TOKEN}'\n",
                    }
                },
            }
        return self.get_gist(gist_id)

    def fetch_raw_file(self, raw_url: str) -> str:
        return ""


def main() -> None:
    init_db()
    with SessionLocal() as db:
        user = ensure_default_user(db)
        sync_detector_rules(db)
        account = db.query(GitHubAccount).filter_by(user_id=user.id, github_login="demo-user").first()
        if account is None:
            account = GitHubAccount(
                user_id=user.id,
                github_login="demo-user",
                github_user_id="0",
                token_encrypted=encrypt_token("demo-token"),
                scopes="demo",
            )
            db.add(account)
            db.commit()
            db.refresh(account)
        scan = ScanRun(user_id=user.id, github_account_id=account.id, scan_type="demo")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scanner = GistScanner(db, account, DemoGitHubClient(), max_revisions=100)
        scanner.run_scan(scan)
    print("Demo data seeded.")


if __name__ == "__main__":
    main()
