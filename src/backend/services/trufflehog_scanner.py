"""
TruffleHog subprocess scanner service.

Runs TruffleHog as a subprocess against gist content and normalizes
its JSON output into the project's SecretMatch format.
"""

import asyncio
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from src.backend.core.config import settings
from src.backend.services.secret_scanner import SecretMatch, SecretType

logger = logging.getLogger(__name__)


@dataclass
class ScannerStatus:
    available: bool
    scanner_path: str
    capabilities: list[str] = field(default_factory=list)

# Mapping from TruffleHog detector names to our SecretType enum
TRUFFLEHOG_TYPE_MAP: Dict[str, SecretType] = {
    "AWS": SecretType.AWS_ACCESS_KEY,
    "AWSAccessToken": SecretType.AWS_ACCESS_KEY,
    "Github": SecretType.GITHUB_TOKEN,
    "GithubOAuth": SecretType.GITHUB_TOKEN,
    "Slack": SecretType.SLACK_TOKEN,
    "SSH": SecretType.SSH_PRIVATE_KEY,
    "PrivateKey": SecretType.PRIVATE_KEY,
    "Stripe": SecretType.API_KEY,
    "Square": SecretType.API_KEY,
    "Twilio": SecretType.API_KEY,
    "SendGrid": SecretType.API_KEY,
    "Mailgun": SecretType.API_KEY,
    "Dynatrace": SecretType.API_KEY,
    "Shopify": SecretType.API_KEY,
    "Gitlab": SecretType.API_KEY,
    "Heroku": SecretType.API_KEY,
    "Azure": SecretType.API_KEY,
    "Google": SecretType.API_KEY,
    "Dropbox": SecretType.API_KEY,
}


class TruffleHogScanner:
    """Scans content using TruffleHog as a subprocess."""

    def __init__(self, trufflehog_path: Optional[str] = None):
        self.trufflehog_path = trufflehog_path or getattr(
            settings, "TRUFFLEHOG_PATH", "trufflehog"
        )
        self._available: Optional[bool] = None

    async def is_available(self) -> bool:
        """Check if TruffleHog binary is available on the system."""
        if self._available is not None:
            return self._available

        try:
            proc = await asyncio.create_subprocess_exec(
                self.trufflehog_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=10.0)
            self._available = proc.returncode == 0
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            logger.info("TruffleHog not available at path: %s", self.trufflehog_path)
            self._available = False

        return self._available

    async def scan_content(
        self, content: str, file_path: str = ""
    ) -> List[SecretMatch]:
        """
        Scan text content by writing it to a temp file and running TruffleHog.
        Returns normalized SecretMatch objects.
        """
        if not await self.is_available():
            logger.debug("TruffleHog unavailable, skipping scan")
            return []

        matches: List[SecretMatch] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = os.path.join(tmpdir, "repo")
            os.makedirs(target_dir, exist_ok=True)

            # Write content as a file so TruffleHog can scan it
            target_file = os.path.join(target_dir, file_path or "content")
            with open(target_file, "w") as f:
                f.write(content)

            # Initialize as a git repo so TruffleHog can scan it
            git_init = await asyncio.create_subprocess_exec(
                "git", "init", target_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await git_init.wait()

            git_add = await asyncio.create_subprocess_exec(
                "git", "-C", target_dir, "add", ".",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await git_add.wait()

            git_commit = await asyncio.create_subprocess_exec(
                "git", "-C", target_dir, "commit", "-m", "scan",
                "--author", "scanner <scanner@localhost>",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await git_commit.wait()

            # Run TruffleHog
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.trufflehog_path,
                    "filesystem",
                    target_dir,
                    "--no-update",
                    "--json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=120.0
                )
            except asyncio.TimeoutError:
                logger.warning("TruffleHog scan timed out")
                return []
            except FileNotFoundError:
                self._available = False
                return []

            if proc.returncode not in (0, 1):  # 0 = no findings, 1 = findings found
                logger.warning("TruffleHog exited with code %d: %s", proc.returncode, stderr.decode()[:500])
                return []

            # Parse JSON output
            output = stdout.decode().strip()
            if not output:
                return []

            for line in output.splitlines():
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    continue

                match = self._normalize_finding(finding, file_path)
                if match:
                    matches.append(match)

        return matches

    def _normalize_finding(
        self, finding: Dict[str, Any], file_path: str
    ) -> Optional[SecretMatch]:
        """Convert a TruffleHog JSON finding to our SecretMatch format."""
        try:
            raw_value = finding.get("Raw", "")
            detector_name = finding.get("DetectorName", "")
            source_metadata = finding.get("SourceMetadata", {}) or {}
            file_info = source_metadata.get("File", "") or {}

            # Extract file path and line info
            found_file = file_info.get("path", file_path)
            line_start = file_info.get("line_start", 0)

            # Map detector type
            secret_type = self._map_detector_type(detector_name)

            # TruffleHog verified findings have high confidence
            verified = finding.get("Verified", False)
            if verified:
                confidence = 0.95
            else:
                confidence = 0.7

            # Peg the raw value for the match
            matched_text = raw_value if raw_value else ""

            return SecretMatch(
                type=secret_type,
                value=matched_text,
                file_path=found_file,
                line_number=line_start,
                column_start=0,
                column_end=len(matched_text),
                confidence=confidence,
                matched_text=matched_text,
                context=finding.get("Context", ""),
            )
        except Exception as e:
            logger.warning("Failed to normalize TruffleHog finding: %s", e)
            return None

    @staticmethod
    def get_status() -> ScannerStatus:
        """Return current scanner status as a simple object."""
        return ScannerStatus(
            available=False,
            scanner_path=getattr(settings, "TRUFFLEHOG_PATH", "trufflehog"),
            capabilities=["filesystem", "json"],
        )

    @staticmethod
    def scan_account(github_account_id: int) -> None:
        """Dummy scan account — real implementation in future."""
        logger.info("TruffleHog scan_account called for account %d (not yet implemented)", github_account_id)

    @staticmethod
    def _map_detector_type(detector_name: str) -> SecretType:
        """Map TruffleHog detector name to our SecretType enum."""
        # Direct match
        if detector_name in TRUFFLEHOG_TYPE_MAP:
            return TRUFFLEHOG_TYPE_MAP[detector_name]

        # Case-insensitive partial match
        name_lower = detector_name.lower()
        for key, secret_type in TRUFFLEHOG_TYPE_MAP.items():
            if key.lower() in name_lower:
                return secret_type

        # Default
        return SecretType.API_KEY


# Module-level instance
trufflehog_scanner = TruffleHogScanner()


async def scan_with_trufflehog(content: str, file_path: str = "") -> List[SecretMatch]:
    """Convenience function — scan content with TruffleHog."""
    return await trufflehog_scanner.scan_content(content, file_path)
