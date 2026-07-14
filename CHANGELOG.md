# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Initial release: Infinite Gist security monitoring and remediation platform
- GitHub OAuth 2.0 authentication with JWT sessions
- Gist enumeration and content scanning for 30+ secret patterns
- Confidence-based severity scoring (critical → low)
- Finding correlation across gists by value hash
- Temporal analysis of secret exposure across gist revisions
- Evidence masking (secrets redacted in UI/API responses)
- Remediation actions: make gist private, delete gist, with verification
- Scheduled scans (daily/weekly) with progress tracking
- Security trend tracking and digest reports
- Account policies for opt-in auto-remediation
- Triage workflow with confidence thresholds (0.5-0.7 gray zone)
- Structured JSON logging
- Rate limiting on destructive remediation actions
- Role-based access control (admin/user)
- Full audit trail for all actions

### Changed

- Migrated deprecated Pydantic V2 `class Config` to `model_config = ConfigDict()`
- Replaced manual `logging.basicConfig()` with structured `setup_logging()` from core
- Removed empty `routers/`, `utils/`, `models/`, `shared/` directories
- Pinned `lucide` CDN dependency to version `0.344.0`
- Added `ruff`, `pytest`, `pytest-asyncio` to `requirements.txt`
- Added GitHub Actions CI workflow (lint + test on push/PR)
- Updated `.gitignore` to exclude session artifacts (`codeburn-*.md`, `codeburn-*.json`)

### Fixed

- License copyright holder now specified
- `.env.example` database path aligned with application default
