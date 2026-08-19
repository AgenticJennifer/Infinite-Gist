# HANDOFF - Infinite Gist

Security monitoring/remediation for GitHub Gists (FastAPI + vanilla-JS SPA).
Repo: `github.com/AgenticJennifer/infinite-gist`

## Status
- Core backend, frontend, security remediation, and CI configuration are in place.
- **200 backend tests and 10 frontend tests passing locally.**
- Scanner-core coverage now includes `secret_scanner`, `trufflehog_scanner`,
  `severity_scorer`, `evidence_masker`, `triage_service`,
  `finding_correlator`, and `temporal_analyzer`.
- Pipeline security tests verify masking, keyed HMAC fingerprints,
  deduplication, rejected-finding behavior, and scanner-result merging.
- Frontend tests use Node's dependency-free built-in test runner and cover API
  behavior, OAuth callback gating, authentication cleanup, duplicate-action
  prevention, malformed responses, and XSS-sensitive rendering helpers.
- `SECURITY.md` documents the threat model, raw-secret lifecycle, keyed
  fingerprints, reporting process, and TruffleHog temporary-file boundary.
- Pydantic schemas use V2 `ConfigDict` configuration.
- `.github/workflows/ci.yml` requires lint, backend tests, frontend tests, and
  Pyright with zero errors.

## Run it
```bash
cd Infinite-Gist                       # pytest MUST run from repo root
pip install -r requirements.lock
cp .env.example .env            # set SECRET_KEY, ENCRYPTION_KEY, GitHub OAuth
pytest -q                                           # 200 pass
npm run test:frontend                              # 10 pass
pyright                                             # 0 errors
uvicorn src.backend.main:app --port 8000
```

Gotcha: tests import `src.backend.main`, which mounts `/static` from
`src/frontend`. Running pytest from any other cwd fails
(`Directory 'src/frontend' does not exist`).

## Release checklist
1. Review the working tree and create a Conventional Commit.
2. Push the changes and confirm the hosted `lint`, `test`, `frontend-test`, and
   `type-check` jobs pass.

## Architecture in one line
`gist_scanner` → per-file `secret_scanner` (regex) + optional
`trufflehog_scanner` → merge → `triage` → `severity_scorer` →
`evidence_masker` → dedupe by HMAC keyed-hash → persist `Finding`.

## Conventions
- Conventional Commits (`fix:`, `feat:`, `chore:`, `docs:`).
- Pydantic V2: `model_config = ConfigDict(from_attributes=True)` (no class `Config`).
- Never store raw secrets; store masked value + keyed hash only.
