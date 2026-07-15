# Security

## Reporting a Vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/AgenticJennifer/infinite-gist/security/advisories/new) rather than a public issue.

## Threat Model

Infinite Gist holds two categories of sensitive data on behalf of users:

1. **GitHub OAuth tokens** — used to read a user's Gists on their behalf.
2. **Detected secrets** — the whole point of the app is finding leaked credentials, so the pipeline itself handles raw secret material in memory.

The design goal is: a compromise of the database or an API response should never hand an attacker a usable credential.

### Raw-secret lifecycle and trust boundary

Raw Gist content enters the scanner pipeline in process memory. Regex and optional TruffleHog scanners may hold a detected value long enough to classify, triage, score, mask, and fingerprint it. Raw values must not cross the pipeline boundary into database models, API responses, application logs, or browser-rendered evidence.

Before persistence, `GistScannerService` replaces the value and surrounding context with masked evidence and computes a keyed HMAC-SHA256 fingerprint using the server-side `SECRET_KEY`. Only the mask and fingerprint are stored. The HMAC supports correlation and deduplication without making low-entropy secrets practical to verify offline from a database dump.

When TruffleHog is enabled, the pipeline writes Gist content to a process-owned temporary directory because the scanner operates on filesystem input. The directory is deleted when the scan exits, including normal exception unwinding. During that scan, raw content temporarily exists on the application host's filesystem, so the host, temporary directory, backups, and swap are inside the trusted boundary. Production deployments should restrict host access, avoid collecting temporary directories in backups, and use encrypted storage or ephemeral disks where required by policy.

### Mitigations in place

| Risk | Mitigation |
|------|------------|
| Raw secrets at rest | Findings store a masked value (`evidence_masker`) and a keyed HMAC-SHA256 fingerprint (`severity_scorer.compute_value_hash`), never the raw secret, so correlation across Gists does not require persisting plaintext. |
| GitHub tokens at rest | Encrypted with Fernet before storage (`core/security.py`); the encryption key is derived via a SHA-256 KDF rather than truncated/zero-padded. |
| OAuth login CSRF | The `state` parameter is a signed, expiring JWT (`create_oauth_state_token`/`verify_oauth_state_token`), not a static string. |
| Cross-user data access (IDOR) | Every schedule/finding/remediation-action lookup is scoped to `user_id` at the query layer, not checked after the fact. |
| Cross-user data leak in aggregates | Digest reports join `Finding` → `Gist` on `Gist.user_id` so counts reflect only the requesting user's own Gists. |
| Destructive actions (make-private / delete / rotate) | Rate-limited per user (`core/rate_limit.py`) to blunt automated abuse or a compromised session hammering the API. |
| Stored XSS | Gist/finding-derived strings (file paths, content snippets, masked values, schedule names) are HTML-escaped before insertion into the DOM. |
| Session hijack via URL | The OAuth callback's access token is only accepted from the URL hash if the client itself just initiated the GitHub redirect (a short-lived `sessionStorage` flag), not from any arbitrary hash fragment on page load. |
| Concurrent scan double-execution | Schedule claiming is a single atomic `UPDATE ... WHERE <due condition>`, checked via rowcount, so two concurrent workers can't both "win" the same due schedule. |
| Error responses leaking internals | Exception handlers log the real exception server-side and return a generic message to the client, rather than interpolating `str(exception)` into the HTTP response. |

### Known limitations (accepted for this project's scope)

- **Bearer token in `localStorage`** (not an httpOnly cookie) — makes any surviving XSS a full session-takeover vector. Moving to cookie-based sessions is a backend+frontend architecture change, out of scope for a security-patch pass.
- **Account auto-linking by email** — if a GitHub email matches an existing user, the account link happens without a re-auth/confirmation challenge. Acceptable for a single-user/demo deployment; would need hardening for multi-tenant production use.
- **Single-process rate limiter** — in-memory, per-worker. Fine for the current single-uvicorn-worker deployment; a multi-worker or multi-instance deployment needs a shared store (e.g. Redis).
- **Ephemeral `SECRET_KEY`/`ENCRYPTION_KEY` defaults** — if not set via `.env`, both are randomly generated per process start (logged loudly at startup). Convenient for local dev, but means every restart invalidates existing sessions and encrypted tokens. Any real deployment must set both explicitly.
