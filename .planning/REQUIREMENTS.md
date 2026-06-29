# Requirements: Infinite Gist

**Defined:** 2026-06-29
**Core Value:** Developers can discover and remediate sensitive leaks in their GitHub Gists

## v1 Requirements

All v1 requirements implemented across 4 phases.

### Authentication
- [x] **AUTH-01**: User can authenticate with GitHub via OAuth
- [x] **AUTH-02**: User can re-authenticate or revoke access
- [x] **AUTH-03**: System requests minimum required permissions for Gist access

### Gist Discovery
- [x] **DISC-01**: Enumerate accessible Gists for authenticated user
- [x] **DISC-02**: Track scan coverage and last-seen state for each Gist
- [x] **DISC-03**: Support public Gist discovery within configured limits

### Content and History Scanning
- [x] **SCAN-01**: Scan current Gist files for secrets, credentials, keys, tokens
- [x] **SCAN-02**: Traverse accessible revision history for exposed material
- [x] **SCAN-03**: Classify findings using deterministic rules (regex, entropy checks)
- [x] **SCAN-04**: Tag findings with source file, line context, revision identifier

### Risk Scoring
- [x] **RISK-01**: Assign severity (critical, high, medium, low) to findings
- [x] **RISK-02**: Consider secret type, validity, exposure surface in scoring
- [x] **RISK-03**: Distinguish between credential exposure and informational leaks

### Findings Persistence
- [x] **PERS-01**: Store findings with detection timestamp and metadata
- [x] **PERS-02**: Maintain audit trail of detection events
- [x] **PERS-03**: Link findings to specific Gist and revision

### Findings Dashboard (API)
- [x] **DASH-01**: Display list of findings with severity and status (API complete, frontend pending)
- [x] **DASH-02**: Allow filtering findings by severity
- [x] **DASH-03**: Show basic finding metadata (Gist, detected at, type)

### Audit and Evidence
- [x] **AUDIT-01**: Log detection, classification, and remediation events
- [x] **AUDIT-02**: Mask secrets by default in UI and storage
- [x] **AUDIT-03**: Preserve evidence for post-hoc review without raw secrets
- [x] **AUDIT-04**: Record whether action was system-executed, suggested, or user-approved

## v2 Requirements

All v2 requirements implemented.

### Advanced Detection
- [x] **ADV-01**: Integrate with TruffleHog or equivalent for enhanced detection
- [x] **ADV-02**: Model-based triage for borderline cases
- [x] **ADV-03**: Correlation of findings across multiple Gists

### Remediation Actions
- [x] **REMED-01**: One-click remediation for supported actions
- [x] **REMED-02**: Generate credential rotation instructions
- [ ] **REMED-03**: Create structured issue reports for tracking

### Monitoring and Alerts
- [x] **MONIT-01**: Scheduled periodic rescans
- [x] **MONIT-02**: Real-time alerts for critical findings
- [x] **MONIT-03**: Weekly digest summaries

### Integration
- [x] **INTEG-01**: Slack webhook notifications
- [x] **INTEG-02**: Email notifications for high-priority findings
- [x] **INTEG-03**: API access for programmatic retrieval of findings

## Out of Scope

| Feature | Reason |
|---------|--------|
| Full repository scanning | Focus on Gists for v1, expand later |
| IDE/plugins | Web-first approach, native integrations later |
| Enterprise policy engine | Simple per-user controls in v1 |
| Full secret rotation | Complex integration, v2 feature |
| Advanced billing system | Simple plan gating for v1 |
| Real-time IDE copilots | Out of scope for security tool |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| AUTH-01 | Phase 1 | Implemented |
| AUTH-02 | Phase 1 | Implemented |
| AUTH-03 | Phase 1 | Implemented |
| DISC-01 | Phase 1 | Implemented |
| DISC-02 | Phase 1 | Implemented |
| DISC-03 | Phase 1 | Implemented |
| SCAN-01 | Phase 1 | Implemented |
| SCAN-02 | Phase 1 | Implemented |
| SCAN-03 | Phase 1 | Implemented |
| SCAN-04 | Phase 1 | Implemented |
| RISK-01 | Phase 1 | Implemented |
| RISK-02 | Phase 1 | Implemented |
| RISK-03 | Phase 1 | Implemented |
| PERS-01 | Phase 1 | Implemented |
| PERS-02 | Phase 1 | Implemented |
| PERS-03 | Phase 1 | Implemented |
| DASH-01 | Phase 1 | Implemented (API) |
| DASH-02 | Phase 1 | Implemented |
| DASH-03 | Phase 1 | Implemented |
| AUDIT-01 | Phase 1 | Implemented |
| AUDIT-02 | Phase 1 | Implemented |
| AUDIT-03 | Phase 1 | Implemented |
| AUDIT-04 | Phase 1 | Implemented |
| ADV-01 | Phase 2 | Implemented |
| ADV-02 | Phase 2 | Implemented |
| ADV-03 | Phase 2 | Implemented |
| REMED-01 | Phase 3 | Implemented |
| REMED-02 | Phase 3 | Implemented |
| REMED-03 | Phase 3 | Not implemented |
| MONIT-01 | Phase 4 | Implemented |
| MONIT-02 | Phase 4 | Implemented |
| MONIT-03 | Phase 4 | Implemented |
| INTEG-01 | Phase 3 | Implemented |
| INTEG-02 | Phase 3 | Implemented |
| INTEG-03 | Phase 4 | Implemented |

---

*Requirements defined: 2026-06-29*
*Last updated: 2026-06-29 after Phase 4 completion*
