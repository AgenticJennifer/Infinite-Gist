# Infinite Gist MVP

Evidence-safe, history-aware GitHub Gist audit and remediation queue.

This is a runnable MVP for the tightened PRD. It is intentionally narrow. It scans accessible user Gists, checks current content and accessible revision history, creates masked findings, stores HMAC fingerprints instead of raw secret values, provides a triage UI, and verifies whether a finding remains in current content or history.

## What is included

- FastAPI web app with Jinja UI.
- SQLite default for local development.
- SQLAlchemy data model aligned to the PRD.
- GitHub OAuth callback support.
- Developer token connect for local testing.
- Gist enumeration.
- Current Gist content scanning.
- Accessible revision-history scanning.
- Deterministic detector engine.
- Masked evidence records.
- HMAC secret fingerprints.
- Finding lifecycle states.
- Proof-of-fix verification.
- Audit events.
- Masked CSV export.
- Demo seed script.
- Unit tests.

## What is deliberately not included yet

- Full repository scanning.
- Organization-wide Gist governance.
- Async worker queue.
- Slack or webhook delivery.
- Email sending.
- Automated Gist edit/delete actions.
- Provider live-token validation.
- Billing.
- Multi-user auth and RBAC.

## Local setup

Create a virtual environment and install dependencies.

```bash
cd infinite-gist-mvp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create local configuration.

```bash
cp .env.example .env
python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

Put that generated value into `FERNET_KEY` in `.env`. Also replace `APP_SECRET` and `HMAC_SECRET` with long random values.

Initialize the database.

```bash
python scripts/init_db.py
```

Optional: seed synthetic demo data.

```bash
python scripts/seed_demo.py
```

Run the app.

```bash
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

## GitHub connection modes

### OAuth mode

Set these in `.env`:

```bash
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GITHUB_CALLBACK_URL=http://127.0.0.1:8000/auth/github/callback
```

The MVP requests the `gist` scope. GitHub documents the Gist REST endpoints for listing, getting, updating, deleting, listing commits, and getting revisions. GitHub also documents that reading or writing Gists on a user's behalf needs the `gist` OAuth scope.

### Developer token mode

For local testing, set:

```bash
ALLOW_DEV_PAT_CONNECT=true
```

Then paste a GitHub token with Gist access into the onboarding form. This path is for local development only. Do not use it as the production auth design.

## Evidence safety model

The scanner handles raw content only in memory during scanning. It stores:

- Detector id and version.
- Finding type.
- Severity and confidence.
- Gist id and file location.
- Revision pointer.
- Masked preview.
- Redacted context excerpt.
- HMAC fingerprint.
- Recommendation.
- Verification and residual-risk state.

It does not store by default:

- Raw secret values.
- Full Gist bodies.
- Full revision bodies.
- Raw secrets in audit events.
- Raw secrets in CSV export.

The HMAC fingerprint lets the verifier recognize the same secret later without storing the secret itself.

## Detector behavior

The detector engine is deterministic. Current detector families include:

- GitHub token-shaped values.
- AWS access key ids.
- AWS secret access key assignments.
- OpenAI-style API keys.
- Stripe secret keys.
- Slack token-shaped values.
- Database URLs containing credentials.
- Private key blocks.
- Generic credential assignments.
- High-entropy sensitive assignments.

Severity and confidence are separate. A high-severity match still shows confidence so users do not confuse heuristic matches with verified live credentials.

## Verification behavior

The proof-of-fix action rescans the affected Gist and accessible revisions. It compares detector id plus HMAC fingerprint.

Verification outcomes:

- `verified_fixed`: no current or historical evidence observed.
- `history_risk_remains`: current content appears clean, but revision history still contains evidence.
- `still_present`: current content or current plus history still contains evidence.

For secrets, cleanup of Gist content is not enough. The recommendation tells users to rotate or revoke the credential first.

## Tests

```bash
pytest -q
```

The tests cover masking, fingerprinting, redaction, detector output, and history-only scanner behavior.

## Production hardening checklist

Before production use:

- Replace SQLite with Postgres.
- Move scans to a queue-backed worker.
- Add real authentication and tenant isolation.
- Disable developer token connect.
- Use cloud KMS or envelope encryption for GitHub tokens.
- Add CSRF/session hardening appropriate to the chosen frontend stack.
- Add provider validation with strict privacy controls.
- Add rate-limit budgeting and incremental scans.
- Add detector regression corpus.
- Add structured logs that reject raw secret payloads.
- Add audit retention and evidence retention policies.
- Add security review for every remediation action.

## Known limitations

This MVP runs scans synchronously through the web request. That is acceptable for proving the workflow, not for production scale.

The GitHub auth model is practical for a user-level Gist audit. Organization-wide Gist governance is not implemented because ownership and access semantics need a separate feasibility spike.

The scanner fetches accessible revision history through the Gist API. If GitHub truncates content, the client follows `raw_url` when available.
