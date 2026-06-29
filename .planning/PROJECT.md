# Infinite Gist

## What This Is
Infinite Gist is a security product that continuously discovers, scores, and remediates sensitive leaks and risky fragments in GitHub Gists. It provides developers and security teams with visibility into exposed credentials, internal code, and risky snippets shared through Gists, with a focus on detection, remediation guidance, and auditability.

## Core Value
Developers can discover and remediate sensitive leaks in their GitHub Gists with minimal friction and trustworthy results.

## Business Context
- **Customer**: Developers and engineering teams using GitHub who want visibility into accidental Gist exposure
- **Revenue model**: Subscription-based with tiered plans based on usage and features
- **Success metric**: Reduction in mean time to remediate (MTTR) for exposed secrets in Gists
- **Strategy notes**: Focus on developer experience and trust through transparent audit trails

## Completed Requirements (4 Phases)

### Phase 1 — Foundation
- GitHub OAuth authentication with minimum-scope token requests
- Gist enumeration with scan coverage tracking and configurable limits
- Current-content and revision-history scanning using regex + entropy detection
- Severity scoring (critical/high/medium/low) based on secret type, validity, exposure surface
- Findings persistence with audit trail, linked to Gist and revision
- Findings API with severity filtering and metadata
- Masked evidence for audit-safe display

### Phase 2 — Credible Detection
- TruffleHog subprocess integration for enhanced secret detection
- Enhanced severity scoring with confidence levels (immediate threat / significant risk / low priority / false positive)
- Cross-Gist correlation analysis with temporal grouping
- Model-based triage for borderline confidence findings
- Temporal analysis of leak patterns over time
- Comprehensive revision-history scanning

### Phase 3 — Remediation
- Remediation actions: make private, delete gist, rotate secrets
- Proof-of-fix verification after remediation
- Multi-channel notification system (email, webhook/Slack)
- Full audit event log for all remediation actions
- Remediation action tracking with status

### Phase 4 — Continuous Operation
- Scheduled periodic scans (daily/weekly/custom intervals)
- Recurring scan execution with error isolation
- Daily and weekly digest report generation
- Account-level policy settings (notification preferences, auto-remediation types, digest frequency)
- Trend analysis of security posture over time (improving/stable/degrading)
- Opt-in automated remediation gated by policy

## Context
- **Tech stack**: Python 3.11+ backend with FastAPI, SQLAlchemy ORM, Pydantic v2
- **Testing**: pytest with 123 tests, all passing
- **Project state**: Backend API complete across all 4 roadmap phases
- **Frontend**: Placeholder only (`src/frontend/__init__.py`) — needs implementation
- **Docker**: Dockerfile and docker-compose.yml exist
- **CI/CD**: Not configured

## Key Decisions
| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Python + FastAPI for backend | Team expertise, async support, strong typing with Pydantic | Adopted |
| Use deterministic rules first for detection | Ensure reproducibility and explainability for security use cases | Adopted |
| Store minimal encrypted metadata only | Reduce risk of accidental secret exposure | Adopted |
| Recommendation-first remediation approach | Build trust before enabling automated actions | Adopted |
| Opt-in auto-remediation (never default) | Safety-first: automated actions require explicit user consent | Adopted |
| Web application over desktop client | Broader accessibility and easier deployment | Adopted |

## Constraints
- **[Rate limits]**: GitHub API rate limits — optimizations needed for production
- **[Security]**: Must not expose secrets in logs or UI — zero-trust handling of sensitive data
- **[Frontend gap]**: API layer is complete, but no user-facing UI yet

---

*Last updated: 2026-06-29 after Phase 4 completion*
