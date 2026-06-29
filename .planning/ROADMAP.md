# Roadmap

## Phase 1: Foundation

**Status:** COMPLETE
**Objective:** Build the detection loop only.

**Completed:**
- [x] GitHub authentication
- [x] User-level Gist enumeration
- [x] Current-content scanning
- [x] Revision-history scanning where accessible
- [x] Severity scoring
- [x] Findings persistence
- [x] Minimal findings dashboard/table
- [x] Audit-safe masked evidence display

**Blocked:** None

## Phase 2: Credible Detection

**Status:** COMPLETE
**Objective:** Add stronger detection capabilities.

**Completed:**
- [x] Stronger secret detection (TruffleHog integration or equivalent)
- [x] Enhanced severity scoring model with confidence levels
- [x] Enhanced correlation of findings across multiple Gists
- [x] Model-based triage for borderline cases
- [x] Masked evidence display in UI
- [x] Comprehensive revision-history scanning
- [x] Basic temporal analysis of leaks

Do not include yet:
- Full repo scanning
- IDE/plugin work
- Broad enterprise policy engine
- Full secret rotation integrations
- Complex billing
- Aggressive auto-remediation

## Phase 3: Remediation

**Status:** COMPLETE
**Objective:** Enable remediation actions.

**Completed:**
- [x] Remediation action flows (make private, delete, rotate secrets)
- [x] Proof-of-fix verification for remediation actions
- [x] Notification system (email, webhook)
- [x] Audit events for all actions

## Phase 4: Continuous Operation

**Status:** COMPLETE
**Objective:** Enable automated, ongoing monitoring.

**Completed:**
- [x] Scheduler for periodic scans
- [x] Recurring scan execution
- [x] Digest generation (daily/weekly)
- [x] Account-level policy settings
- [x] Trend analysis of security posture
- [x] Automated remediation options (opt-in)