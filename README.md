# Infinite Gist

**Security monitoring and remediation platform for GitHub Gists**

[![CI](https://github.com/AgenticJennifer/Infinite-Gist/actions/workflows/ci.yml/badge.svg)](https://github.com/AgenticJennifer/Infinite-Gist/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Does

Infinite Gist continuously discovers, scores, and remediates sensitive leaks and risky fragments in GitHub Gists. It gives developers and security teams visibility into exposed credentials, internal code, and risky snippets.

**Core loop:** Discover → Understand → Act → Verify

![Architecture](docs/architecture.png)

---

## Features

- **Secret Detection** — Scans Gists for AWS keys, GitHub tokens, private keys, passwords, and more
- **Severity Scoring** — Confidence-based risk assessment with correlation analysis
- **Remediation** — Make Gists private or delete them with one click
- **Audit Trail** — Complete logging of all security events
- **Scheduled Scans** — Automatic daily/weekly monitoring
- **Evidence Masking** — Secrets are redacted in the UI (never exposed in full)

---

## Quick Start

### Prerequisites

- Python 3.11+
- GitHub OAuth App ([create one here](https://github.com/settings/developers))

### Installation

```bash
# Clone the repository
git clone https://github.com/AgenticJennifer/Infinite-Gist.git
cd Infinite-Gist

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Copy the example env file
cp .env.example .env

# Generate secure keys
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
python3 -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))"

# Edit .env with your values
nano .env
```

Required `.env` variables:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Random string for JWT signing |
| `ENCRYPTION_KEY` | Random string for token encryption |
| `GITHUB_CLIENT_ID` | From GitHub OAuth App |
| `GITHUB_CLIENT_SECRET` | From GitHub OAuth App |

### Run

```bash
# Start the server
uvicorn src.backend.main:app --reload --port 8000

# Open in browser
open http://localhost:8000
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/gists` | List user's Gists |
| `POST` | `/api/v1/scan/account/{id}` | Scan a GitHub account |
| `GET` | `/api/v1/findings` | Get all findings |
| `GET` | `/api/v1/findings/stats` | Finding statistics |
| `PUT` | `/api/v1/findings/{id}/status` | Update finding status |
| `POST` | `/api/v1/triage` | Batch triage findings |
| `GET` | `/api/v1/correlations` | Find correlated secrets |
| `POST` | `/api/v1/remediation/make-private/{id}` | Make a Gist private |
| `DELETE` | `/api/v1/remediation/delete/{id}` | Delete a Gist |

Full API docs available at `http://localhost:8000/docs` when running.

---

## Project Structure

```
infinite-gist/
├── src/
│   ├── backend/
│   │   ├── api/v1/        # FastAPI endpoints
│   │   ├── core/          # Config, security, auth
│   │   ├── db/            # SQLAlchemy models
│   │   ├── services/      # Business logic
│   │   └── main.py        # App entry point
│   ├── frontend/          # Static HTML/CSS/JS
│   └── shared/            # Shared utilities
├── tests/                 # Pytest test suite
├── docs/                  # Documentation
├── .github/workflows/     # CI/CD
├── DESIGN.md              # Design tokens & theme
├── PRODUCT.md             # Product requirements
└── requirements.txt       # Python dependencies
```

---

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy, Pydantic
- **Database:** SQLite (dev) / PostgreSQL (prod)
- **Auth:** GitHub OAuth 2.0, JWT
- **Scanning:** Custom regex + [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- **Encryption:** Fernet (AES-128-CBC)

---

## Development

### Run Tests

```bash
pytest
```

### Run Linter

```bash
ruff check src/
```

### Database Migrations

```bash
alembic upgrade head
alembic revision --autogenerate -m "description"
```

---

## Security

### Reporting Vulnerabilities

Please report security issues privately via [GitHub Security Advisories](https://github.com/AgenticJennifer/Infinite-Gist/security/advisories/new).

### Design Principles

- **Secrets are masked** — Raw values never leave the scanning pipeline
- **Audit logging** — All actions are logged with timestamps
- **Ownership checks** — Users can only access their own Gists
- **Encrypted storage** — GitHub tokens encrypted at rest

---

## Status

**Backend: complete.** All 4 planned phases (detection, credible detection/correlation, remediation, continuous operation) are implemented — 138/138 tests passing. See `.planning/ROADMAP.md` for phase detail.

**Frontend: functional, accessibility-hardened.** `src/frontend/` is a vanilla JS single-page app (hash routing, API client, login/dashboard/findings/correlations/schedules/policies/digests/trends views) served by FastAPI at `/`. An `/impeccable audit` pass (15/20, "Good") found solid theming and zero AI-slop anti-patterns, with accessibility as the weak dimension; a follow-up harden pass added keyboard support for sortable columns, a focus-trapped/labeled modal, `aria-live` toasts, and 44px touch targets on icon buttons.

## Roadmap

- [ ] Visual/UX polish pass (`/impeccable polish`) — next up
- [ ] Secret rotation integration
- [ ] Slack/email notifications
- [ ] Team collaboration features
- [ ] Custom detection rules
- [ ] Webhook integrations

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Secret detection powered by regex patterns and [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- Design inspired by developer-first security tools
