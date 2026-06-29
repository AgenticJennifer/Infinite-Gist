# Infinite Gist PRD

## Overview

Infinite Gist is a security product that continuously discovers, scores, and remediates sensitive leaks and risky fragments in GitHub Gists. It is designed as a practical detection-and-remediation workflow for developers, engineering teams, and security teams that need visibility into exposed credentials, internal code, and risky snippets shared through Gists.

The product exists because GitHub Gists often behave like lightweight repositories but are usually treated with less operational discipline. That creates a real risk that secrets, proprietary code, connection details, or unsafe fragments are exposed in ways that are hard to track and even harder to remediate at scale. The initial product wedge is intentionally narrow: scan Gists, validate risk, recommend or execute remediation, and produce proof-of-fix artifacts.

## Product summary

### Product name

Infinite Gist

### Product type

Security monitoring and remediation platform for GitHub Gists.

### Core problem

Developers and organizations accidentally expose credentials, configuration, proprietary code, and risky fragments in GitHub Gists. These leaks can persist unnoticed, can remain recoverable in revision history even after edits, and can create downstream engineering and supply-chain risk.

### Product thesis

If Infinite Gist can continuously detect exposed secrets and risky code in Gists, rank the risk accurately, and drive remediation with minimal friction, it can become the default control point for Gist hygiene and a natural expansion point into broader code-fragment security.

## Goals

### Business goals

- Establish a credible security wedge around Gist leak detection and remediation.
- Win early trust with solo developers, small engineering teams, and security-conscious organizations.
- Build a foundation that can later expand into adjacent repository-fragment and snippet-security workflows.
- Demonstrate measurable value through reduced exposure time, safer code-sharing behavior, and auditable remediation.

### Product goals

- Detect exposed secrets and risky content in public and authorized private Gists.
- Inspect revision history so removed secrets are still flagged if they remain recoverable.
- Offer safe remediation options, from guided recommendations to approved automated actions.
- Produce auditable evidence showing what was found, what action was taken, and what risk remains.
- Maintain a low false-positive rate so users trust the system and act on alerts.

### Non-goals for v1

- Full repository scanning beyond Gists.
- Broad application security testing across arbitrary codebases.
- Real-time IDE copilots or editor plugins.
- Complete enterprise incident response across every downstream service.
- A generalized cloud-security or posture-management platform.

## Users and buyers

The primary user is a developer or engineering team that uses GitHub and wants visibility into accidental Gist exposure. The primary early buyer is likely a small technical team, engineering manager, or security-minded founder who wants lightweight monitoring and straightforward remediation without adopting a heavyweight platform.

A secondary strategic segment is Python-heavy or infrastructure-sensitive teams that are already aware of supply-chain blast radius and want tighter controls around public code fragments and leaked credentials.

## User stories

A solo developer wants to connect a GitHub account, scan all accessible Gists, and receive a prioritized list of leaks with exact remediation guidance.

An engineering lead wants team-level visibility so new or changed Gists are scanned continuously and critical leaks trigger immediate alerts.

A security analyst wants revision-history awareness so a secret removed from the current Gist body is still flagged if it remains accessible in past revisions.

An administrator wants an audit log that proves which leaks were found, which were remediated, which were dismissed as false positives, and which remain open.

## Core use cases

### Use case 1: initial account scan

A user authenticates with GitHub, grants access permissions, and launches an initial scan. Infinite Gist enumerates relevant Gists, inspects content and revision history, classifies findings by severity, and returns a dashboard plus a remediation queue.

### Use case 2: continuous monitoring

After onboarding, the service periodically rescans or reacts to relevant change signals where feasible, then updates findings and notifies users when new critical or high-severity issues appear.

### Use case 3: guided remediation

For each finding, the product offers a recommended path such as rotate secret, make Gist private, delete Gist, scrub content, or confirm benign usage. Where allowed, the system can automate the GitHub-side step and log the result.

### Use case 4: proof of remediation

After action is taken, Infinite Gist stores a machine-readable trail showing detection time, evidence, recommended action, executed action, post-fix verification result, and remaining risk.

## Functional requirements

### 1. Authentication and access

- Support GitHub OAuth or GitHub App-based authentication.
- Allow per-user onboarding and later organization onboarding.
- Request the minimum permissions needed for enumerating Gists and executing approved remediations.
- Store tokens securely and support revocation or reauthorization flows.

### 2. Gist discovery

- Enumerate accessible Gists for the authenticated user.
- Support public Gist discovery within configured product limits.
- Support organization and team-linked discovery where the chosen GitHub auth model permits it.
- Track scan coverage and last-seen state for each Gist.

### 3. Content and history scanning

- Scan current Gist files for secrets, credentials, keys, tokens, hardcoded passwords, connection strings, certificates, and risky fragments.
- Traverse accessible revision history because exposed material may remain in prior revisions even if current content appears clean.
- Classify findings using deterministic rules first, then optional model-based triage for borderline cases.
- Tag findings with source file, line context, revision identifier, and confidence.

### 4. Risk scoring

- Assign severity across critical, high, medium, and low.
- Consider secret type, apparent validity, exposure surface, age, owner context, and whether a secret appears live or revoked.
- Distinguish between direct credential exposure and weaker informational leaks such as internal endpoints or architectural clues.

### 5. Remediation engine

- Support recommendation-only mode for cautious users.
- Support assisted actions including make private, prepare delete action, generate credential rotation instructions, generate owner notification, and create structured issue or report output.
- Support controlled automated actions for explicitly approved workflows.
- Prevent destructive actions without clear policy or explicit user confirmation.

### 6. Alerting and reporting

- Send immediate alerts for critical findings.
- Generate daily and weekly summaries for lower-severity findings.
- Provide a dashboard with open findings, resolved findings, mean time to remediation, false-positive dispositions, and scan coverage.
- Export structured reports suitable for engineering or security review.

### 7. Auditability

- Log every detection, classification, notification, and remediation event.
- Preserve enough evidence for post-hoc review without storing unnecessary sensitive payloads in plaintext.
- Record whether a change was system-executed, system-suggested, or user-approved.

## Requirements for the coding agent

The coding agent should build v1 as a narrow web application plus backend workers. The system should prefer deterministic pipelines over model-heavy orchestration for core detection because false positives, reproducibility, and explainability matter more than novelty at this stage.

The coding agent should design the architecture around these components.

| Component | Responsibility |
|---|---|
| Web app | onboarding, auth, findings dashboard, remediation actions |
| API layer | auth callbacks, findings retrieval, action endpoints, reporting |
| Scan worker | enumerate Gists, fetch content and history, run detectors |
| Detection engine | rules, regex, entropy checks, secret detectors, optional triage model |
| Remediation worker | execute approved actions, generate instructions, verify results |
| Scheduler | periodic rescans and digest generation |
| Data store | users, Gists, findings, actions, audit log, scan state |
| Notification layer | email, Slack, webhook delivery |

## Suggested technical architecture

### Front end

A simple authenticated web application with four main screens: onboarding, findings queue, finding detail, and audit/reporting. The interface should prioritize triage speed and trust over visual complexity.

### Back end

A service that handles auth, APIs, state management, and orchestration. Background workers should perform scans and remediations asynchronously so long-running jobs do not block the UI.

### Storage

Use a relational database for core entities and state transitions. Store minimal encrypted sensitive metadata where necessary, but avoid persisting raw exposed secrets longer than needed for verification and audit-safe display.

### Detection pipeline

The pipeline should combine multiple detector types: regex patterns, entropy heuristics, known token formats, allowlists, and optional secret-scanning libraries. The design should allow plugging in TruffleHog-class scanning or equivalent detectors because the product concept depends on real leak detection quality.

## Data model

The coding agent should at minimum define these entities.

| Entity | Purpose |
|---|---|
| User | authenticated account owner |
| Organization | optional team or org container |
| GitHubAccount | OAuth or app installation linkage |
| Gist | discovered Gist metadata |
| GistRevision | revision snapshot metadata |
| Finding | specific leak or risk item |
| RemediationAction | suggested or executed fix |
| ScanRun | one completed or in-progress scan |
| NotificationEvent | alert and digest delivery record |
| AuditEvent | immutable operational trail |
| Policy | remediation and safety settings |

## Finding schema expectations

Each finding should include a stable identifier, owner reference, Gist reference, file path, line range or excerpt reference, revision reference where applicable, finding type, severity, confidence, status, first seen time, last seen time, remediation recommendation, and verification result.

## UX requirements

The user experience should feel like a triage console rather than a generic SaaS dashboard. The main queue should let a user answer three questions immediately: what is dangerous, what should be fixed first, and what can be safely ignored.

The findings list should support severity filtering, status filtering, owner filtering, and age sorting. Each finding detail page should show why it was flagged, where it appeared, whether it exists in history, and which remediation actions are available.

For sensitive content, the UI should mask secrets by default and reveal them only when necessary for verification. The product should also clearly separate machine confidence from confirmed validity so users do not mistake a heuristic match for a verified live credential.

## Safety and trust requirements

This product only works if users trust it. That means the coding agent should optimize for explainability, conservative automation, and visible safeguards.

Auto-remediation should be opt-in. Delete operations should require elevated confirmation unless a very explicit policy says otherwise. Make-private actions are safer than delete actions and should usually appear earlier in the workflow. Notifications should avoid echoing full secrets into email or chat payloads.

## KPI definitions

The system should measure:

- Gists scanned per day
- Findings per 1,000 Gists scanned
- Critical and high findings count
- Verified true-positive rate
- False-positive rate
- Mean time to first alert
- Mean time to remediation
- Automated remediation success rate
- Percentage of findings that exist only in history versus current content
- User or team retention on continuous monitoring

## Success criteria for v1

Version 1 succeeds if a user can connect GitHub, scan accessible Gists, detect real high-signal leaks including history-based leaks, take a safe remediation action, and receive a verifiable audit trail without heavy manual work. The product does not need broad market polish at this stage; it needs credible detection, safe workflow, and repeatable operational value.

## Scope for v1

### In scope

- GitHub auth
- User-level Gist enumeration
- Current-content scanning
- Revision-history scanning where accessible
- Severity scoring
- Findings dashboard
- Recommendation-only remediation
- Limited approved automated actions
- Alerts and audit log

### Out of scope

- Full repo scanning
- Multi-platform paste site coverage
- IDE plugins
- Large enterprise policy engine
- End-to-end secret rotation across every provider
- Complex billing system beyond basic plan gating

## Milestones

### Milestone 1: foundation

Ship auth, database schema, Gist ingestion, manual scan trigger, and a basic findings table.

### Milestone 2: credible detection

Add stronger secret detection, history scanning, severity model, and masked evidence display.

### Milestone 3: remediation

Add remediation action flows, proof-of-fix verification, notifications, and audit events.

### Milestone 4: continuous operation

Add scheduler, recurring scans, digests, and account-level policy settings.

## Open questions for implementation

The coding agent should resolve or surface these before full implementation:

- Should auth use GitHub OAuth, GitHub App installation flow, or both?
- What exact GitHub permissions are required for read-only mode versus assisted remediation mode?
- What is the canonical false-positive review workflow?
- How much revision history can be scanned within GitHub rate limits and cost targets?
- Which detector stack should be first-class in v1: native rules, TruffleHog integration, or a hybrid?
- What actions are considered safe enough for unattended execution?
- How should exposed secrets be redacted in storage and UI while preserving evidence quality?

## Build guidance

The coding agent should treat this product as a security workflow engine, not a content site and not an AI-demo shell. The first priority is a reliable detection-and-remediation loop. The second priority is operational clarity. The third priority is user trust through reviewable actions, complete audit logs, and conservative automation.

A strong first build would favor boring, testable infrastructure: explicit queues, typed finding states, deterministic detectors, reviewable remediation actions, and complete audit logs. Fancy orchestration can sit on top of that foundation later.
