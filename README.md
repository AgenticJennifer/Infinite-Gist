# Infinite Gist

<p align="center">
  <img src="docs/logo.png" alt="Infinite Gist logo" width="220">
</p>

**Security monitoring and remediation platform for GitHub Gists**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Does

Infinite Gist continuously discovers, scores, and remediates sensitive leaks and risky fragments in GitHub Gists. It gives developers and security teams visibility into exposed credentials, internal code, and risky snippets.

**Core loop:** Discover -> Understand -> Act -> Verify

![Architecture](docs/architecture.svg)

---

## Features

- **Secret Detection**: Scans Gists for AWS keys, GitHub tokens, private keys, passwords, and more
- **Severity Scoring**: Confidence-based risk assessment with correlation analysis
- **Remediation**: Make Gists private or delete them with one click
- **Audit Trail**: Complete logging of all security events
- **Scheduled Scans**: Automatic daily/weekly monitoring
- **Evidence Masking**: Secrets are redacted in the UI and never exposed in full

---

## Quick Start

```bash
git clone https://github.com/AgenticJennifer/Infinite-Gist.git
cd Infinite-Gist
cp .env.example .env
# Fill in SECRET_KEY, ENCRYPTION_KEY, GITHUB_CLIENT_ID, and GITHUB_CLIENT_SECRET in .env
docker compose up -d
```

Open `http://localhost:8000` after the containers start. Full API docs are available at `http://localhost:8000/docs`.

Required `.env` variables:

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Random string for JWT signing |
| `ENCRYPTION_KEY` | Random string for token encryption |
| `GITHUB_CLIENT_ID` | From GitHub OAuth App |
| `GITHUB_CLIENT_SECRET` | From GitHub OAuth App |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/gists/gists` | List user's Gists |
| `POST` | `/api/v1/gists/scan/account/{id}` | Scan a GitHub account |
| `GET` | `/api/v1/gists/findings` | Get all findings |
| `GET` | `/api/v1/gists/findings/stats` | Finding statistics |
| `PUT` | `/api/v1/gists/findings/{id}/status` | Update finding status |
| `POST` | `/api/v1/gists/triage` | Batch triage findings |
| `GET` | `/api/v1/gists/correlations` | Find correlated secrets |
| `POST` | `/api/v1/remediation/make-private?finding_id={id}` | Make a Gist private (rate-limited) |
| `POST` | `/api/v1/remediation/delete?finding_id={id}` | Delete a Gist (rate-limited) |

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
│   └── frontend/          # Static HTML/CSS/JS
├── tests/                 # Pytest test suite
├── docs/                  # Documentation
├── DESIGN.md              # Design tokens and theme
├── PRODUCT.md             # Product requirements
├── SECURITY.md            # Threat model and security posture
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
# Run from the repository root because the app mounts src/frontend at import time.
pytest -q

# Dependency-free frontend tests (Node.js 20+)
npm run test:frontend

# The historical MVP has its own isolated suite.
cd mvp && pytest -q
```

### Run Linter

```bash
ruff check src/
pyright
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

- **Secrets are masked:** Raw values never leave the scanning pipeline
- **Audit logging:** All actions are logged with timestamps
- **Ownership checks:** Users can only access their own Gists
- **Encrypted storage:** GitHub tokens encrypted at rest

---

## Status

**Backend: complete.** All 4 planned phases (detection, credible detection/correlation, remediation, continuous operation) are implemented. The suite has 200 passing tests, and Pyright reports zero errors. Coverage includes scanner-core and pipeline security behavior for masking, keyed fingerprints, correlation, temporal analysis, and remediation. See `.planning/ROADMAP.md` for phase detail.

**Frontend: functional, accessibility-hardened, and tested.** `src/frontend/` is a vanilla JS single-page app served by FastAPI at `/`. Ten dependency-free Node tests cover API behavior, OAuth callback gating, authentication cleanup, duplicate-action prevention, malformed responses, and XSS-sensitive rendering helpers.

## Roadmap

- [ ] UI polish and onboarding refinements
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
