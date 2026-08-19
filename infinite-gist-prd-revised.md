# Infinite Gist

## Evidence-Safe, History-Aware Gist Audit

**Product requirements document — revised 2026-07-21**  
**Status:** Proposed product contract  
**Primary source reviewed:** [`docs/infinite-gist-prd.md`](https://github.com/AgenticJennifer/infinite-gist/blob/main/docs/infinite-gist-prd.md)  
**Repository reviewed:** [`AgenticJennifer/infinite-gist`](https://github.com/AgenticJennifer/infinite-gist)  

---

## 1. Executive decision

Infinite Gist should narrow from “security monitoring and remediation platform” to an **evidence-safe, history-aware audit and remediation queue for a GitHub user’s Gists**.

The product’s first job is not to out-scan GitHub or promise autonomous remediation. Its first job is to answer, with defensible evidence:

1. What exposure was observed?
2. Where and when was it observable, including prior revisions?
3. What is known, inferred, or still unverified?
4. What response is safest?
5. Did the response remove current exposure and revoke the credential?
6. What residual risk remains?

This framing matches GitHub’s platform constraints and creates a sharper distinction from native secret scanning. GitHub already scans secret gists for partner patterns. A public gist cannot be converted to a secret gist after creation, and a secret gist is not private. Infinite Gist therefore wins through broader audit coverage, explicit uncertainty, revision-aware evidence, decision support, and proof of response.

The first release should remain read-only by default. It should never execute a GitHub mutation or contact a credential provider without explicit, recorded approval. Unattended remediation is outside the validated product scope.

---

## 2. Evidence status used in this PRD

Every material statement belongs to one of four classes:

| Label | Meaning |
|---|---|
| **Verified platform fact** | Supported by current GitHub documentation or a direct API contract. |
| **Observed repository fact** | Present in source code or repository documentation; runtime behavior was not independently exercised during this review. |
| **Product hypothesis** | Plausible, but not supported by user, market, or usage evidence yet. |
| **Requirement** | A proposed product or engineering contract. |

This distinction is mandatory in future product reviews, security claims, dashboards, and exported evidence.

---

## 3. Problem definition

### 3.1 Problem

Developers use Gists as lightweight Git repositories. Public and secret Gists retain revision history. Secret gists are unlisted, not private. A credential removed from the latest revision might remain visible in an earlier revision. A detection result alone does not establish validity, ownership, exploitability, or successful remediation.

The operational gap is therefore larger than “find strings that resemble secrets.” Users need a trustworthy case record that connects:

**observation → adjudication → approved response → independent verification → residual risk**

### 3.2 Current alternatives and remaining gap

GitHub automatically scans secret gists for partner-supported secrets and notifies participating providers. GitHub also exposes Gist commits and revisions through its API. Those capabilities reduce the value of a generic “we scan Gists” claim.

Infinite Gist’s proposed differentiation is:

- one review queue across current content and accessible revisions;
- transparent detector evidence and explicit confidence limits;
- findings beyond partner-supported token patterns, subject to measured precision;
- cross-Gist correlation through non-reversible keyed fingerprints;
- separate exposure, credential-validity, and remediation states;
- approval-bound response plans;
- evidence bundles that prove what the system observed and checked without storing raw secrets.

This differentiation remains a **product hypothesis** until controlled evaluations and user pilots demonstrate value beyond GitHub’s native experience.

### 3.3 Target user for the first release

The first target is a security-minded developer, consultant, maintainer, or small-team technical lead who:

- owns or controls one or more GitHub accounts;
- has accumulated Gists over time;
- needs a one-time or recurring exposure audit;
- values a reviewable record more than unattended action;
- accepts account-by-account authorization.

Organization-wide security teams are a later segment. Gists are user-scoped rather than organization-owned resources, so organization coverage requires member authorization, an enterprise-supported identity model, or another proven aggregation route. The PRD must not imply organization-wide coverage before that route exists.

### 3.4 Buyer hypothesis

The current repository contains no evidence that a defined buyer has budget, urgency, or procurement intent for this product. “Security-minded founder,” “engineering manager,” and “security team” are hypotheses, not established buyers.

Before paid packaging, interview at least 10 target users and run at least five consented account audits. Record current workflow, native GitHub usage, Gist count, historical findings, response time, willingness to grant access, and willingness to pay.

---

## 4. Product promise

### 4.1 One-sentence promise

Infinite Gist gives a GitHub account owner a defensible record of sensitive material found in current or historical Gist content, the evidence behind each judgment, the approved response, and the residual risk after verification.

### 4.2 Product principles

1. **Raw secrets are transient.** Raw values stay inside the shortest feasible scan boundary and never enter application storage, normal logs, analytics, browser payloads, notifications, or exported reports.
2. **Observation is not validation.** A pattern match, credential-validity check, and security impact are separate facts.
3. **Severity is explainable.** Every priority has visible inputs and no hidden model-only authority.
4. **Read-only is the default.** Mutations require a separate permission tier and recorded approval.
5. **Rotation precedes cosmetic cleanup.** Removing text does not revoke a credential.
6. **History is residual risk.** Editing current content does not erase prior Gist revisions.
7. **Audit records are append-only.** Corrections create new events; they do not overwrite history.
8. **Proof has limits.** “Source no longer observed” is different from “credential revoked” and “copies do not exist elsewhere.”
9. **Coverage is measured.** Truncated, inaccessible, skipped, rate-limited, and failed content appears in the result.
10. **No silent action.** The system never changes a Gist, deletes content, or contacts a secret provider without an approval record that names the action and target.

---

## 5. Scope

### 5.1 Version 1 in scope

- GitHub user authorization with separate read and write permission tiers.
- Enumeration of Gists accessible to the authenticated user.
- Scan of current Gist content.
- Scan of accessible commit history and revisions.
- Explicit acquisition coverage, including truncation and fetch failures.
- Deterministic detectors and optional TruffleHog-class detectors.
- Masked evidence and versioned keyed fingerprints.
- Human review and disposition.
- Separate confidence, validity, impact, exposure, and remediation states.
- Response playbooks for credential rotation, content cleanup, Gist deletion, and migration to a private repository.
- Explicitly approved deletion or current-content edit where supported.
- Post-response rescan and credential-revocation recording.
- Append-only audit events and exportable proof bundles.
- Scheduled read-only rescans and concise digests.

### 5.2 Version 1 out of scope

- Converting a public Gist to secret; GitHub does not support this transition.
- Claiming that a secret Gist is private.
- Automatic credential rotation across arbitrary providers.
- Unattended deletion, content edits, or provider validity checks.
- Organization-wide coverage without an explicit account authorization model.
- Full GitHub repository scanning.
- General application security testing.
- Global public-Gist surveillance.
- Incident-response claims about downstream access or misuse without external evidence.
- Compliance certification or legal-evidence claims.
- Model-based dismissal of findings without human review.

---

## 6. Core workflow

### Stage 1: Define audit scope

The user selects an authorized GitHub account and a time window or full-history audit. The system records:

- account identifier;
- authorization type and granted permissions;
- audit start time;
- requested scope;
- product, detector, rule-set, and policy versions;
- whether external validity checks are allowed;
- whether write actions are allowed at all.

**Exit condition:** A signed scope record exists. Missing access appears as excluded scope, not as zero findings.

### Stage 2: Acquire source inventory

The system enumerates accessible Gists, files, commits, and revisions. For every source object it records:

- GitHub object identifier;
- owner identifier;
- observed visibility;
- revision SHA and committed time;
- fetch time;
- response status and source metadata needed for replay;
- truncation state;
- acquisition outcome;
- content digest computed in memory.

Raw Gist bodies are not retained after scanning. If GitHub returns truncated content, the system follows the documented raw-content or clone route within configured size and safety limits. Unresolved truncation lowers coverage.

**Exit condition:** The audit has a coverage manifest with complete, partial, failed, and excluded objects.

### Stage 3: Detect candidate evidence

Detectors inspect content in an isolated scan boundary. Each signal records:

- detector name, version, and configuration digest;
- pattern or rule identifier;
- file and revision location;
- line span;
- secret type candidate;
- masked excerpt;
- non-reversible keyed fingerprint and key version;
- detector confidence and basis;
- detection time.

No raw value crosses the scan boundary.

**Exit condition:** Every candidate is reproducible from the same controlled fixture and detector version.

### Stage 4: Normalize and correlate

The system groups repeat observations without collapsing distinct exposures. Identity uses:

- tenant/account boundary;
- versioned HMAC fingerprint;
- Gist identifier;
- revision identifier;
- file location;
- detector rule.

One credential appearing in five Gists produces one correlated secret case with five exposure observations. It does not produce one database row that erases the other four locations.

**Exit condition:** A reviewer sees every exposure location and the correlation basis.

### Stage 5: Adjudicate

The reviewer classifies each case along independent axes:

| Axis | Allowed states |
|---|---|
| Detection confidence | high, medium, low |
| Human disposition | unreviewed, suspected, confirmed, benign, duplicate, insufficient evidence |
| Credential validity | not checked, active, inactive, indeterminate, unsupported, check failed |
| Exposure state | present in current, historical only, deleted source, inaccessible, unknown |
| Business impact | critical, high, medium, low, unassessed |

Severity is derived from documented inputs. A high-confidence match is not automatically critical. An inactive credential might still prove unsafe handling, and historical exposure might still demand rotation evidence.

Optional provider validity checks require separate consent, a supported provider adapter, a logged request, redacted response metadata, and a no-side-effect test contract.

**Exit condition:** The case has an evidence-backed disposition or a visible “insufficient evidence” state.

### Stage 6: Plan response

For a confirmed or suspected credential exposure, the default response order is:

1. Revoke or rotate the credential through the issuing provider.
2. Verify that the old credential is inactive where a safe check exists.
3. Remove the credential from current Gist content or delete the Gist.
4. Re-scan current and historical content.
5. Record unavoidable historical exposure and possible copies or forks.

The system must not present “make private” for a public Gist. It should explain that public-to-secret conversion is unsupported and that secret Gists remain URL-accessible. Safer alternatives are deletion, replacement with a new secret Gist after rotation, or migration to a private repository.

Every proposed mutation displays:

- exact target;
- exact action;
- expected effect;
- limits and irreversibility;
- approval requirement;
- rollback availability;
- verification plan.

**Exit condition:** The user approves or rejects a concrete action plan. No approval means no mutation.

### Stage 7: Execute approved action

Mutation requests use idempotency keys and a short approval lifetime. The service rechecks ownership, current source state, and permission immediately before execution. Delete requires a fresh confirmation because it is irreversible.

Credential rotation remains an instruction and evidence-collection workflow until a provider-specific integration has passed a separate safety review.

**Exit condition:** The system records the requested action, executor, source response, timestamps, and outcome without raw secrets.

### Stage 8: Verify outcome

Verification runs independently from the action request. It checks each relevant claim:

- **Credential revoked:** provider evidence says the prior credential is inactive, or the user supplies an attestation when no safe check exists.
- **Current exposure cleared:** a fresh source read no longer contains the fingerprint.
- **Source deleted:** GitHub returns the expected deletion result and a later read confirms absence, subject to API semantics.
- **Historical exposure remains:** prior revisions still contain the fingerprint, or the source is deleted and no longer auditable.
- **Copies unresolved:** forks, clones, caches, logs, and third-party copies remain outside proof unless separately checked.

“Resolved” requires a defined resolution policy. The recommended default is: credential revoked plus current exposure cleared. Historical exposure remains part of the record.

**Exit condition:** Every response claim is verified, failed, indeterminate, or unsupported. The product never turns an unverified attempt into “fixed.”

### Stage 9: Export proof bundle

The user receives a machine-readable and human-readable case bundle containing:

- audit scope and coverage;
- case and exposure identifiers;
- masked evidence;
- detector and policy versions;
- human decisions;
- approvals;
- action attempts and results;
- verification results;
- residual risk;
- append-only event hashes;
- export time and format version.

The bundle excludes raw secret values and raw Gist bodies.

---

## 7. State model

### 7.1 Case lifecycle

`observed → review_pending → suspected | confirmed | benign | insufficient_evidence`

Confirmed or suspected cases proceed through:

`response_planned → approval_pending → approved | rejected | expired → executing → verification_pending → resolved | residual_risk | failed | indeterminate`

Any later observation produces `reopened` and a new event. Prior states remain in history.

### 7.2 Required invariants

- A case never becomes `resolved` solely because a Gist was edited or deleted.
- A failed or missing validity check never becomes `inactive`.
- A low-confidence signal never disappears without a disposition event.
- A duplicate retains its exposure location and points to the canonical case.
- An action without a matching approval record is rejected.
- Expired approval requires a new confirmation.
- A source access failure lowers coverage and never implies a clean result.

---

## 8. Evidence and audit data contract

### 8.1 Exposure observation

Each observation requires:

- `observation_id`
- `tenant_id`
- `github_account_id`
- `gist_id`
- `gist_owner_id`
- `visibility_observed`
- `revision_sha`
- `file_path`
- `line_start` and `line_end`
- `source_committed_at`
- `source_fetched_at`
- `source_content_digest`
- `source_truncated`
- `acquisition_status`
- `detector_id`
- `detector_version`
- `rule_id`
- `rule_config_digest`
- `secret_type_candidate`
- `masked_value`
- `masked_excerpt`
- `fingerprint_hmac`
- `fingerprint_key_version`
- `confidence_score`
- `confidence_basis`
- `created_at`

### 8.2 Case record

Each case requires:

- `case_id`
- correlated observation identifiers;
- human disposition and rationale;
- credential-validity state, method, time, and evidence reference;
- impact level and scoring inputs;
- recommended response;
- owner and assignee;
- due time where policy requires one;
- current lifecycle state;
- residual-risk statement;
- reopen history.

### 8.3 Approval record

Each mutation requires:

- `approval_id`
- approver identity;
- target account, Gist, and case;
- exact action and parameters;
- expected effect;
- irreversible-effect warning;
- policy version;
- requested, approved, and expiry times;
- approval channel;
- idempotency key;
- pre-action source digest.

### 8.4 Audit event

Each event requires:

- `event_id`
- `previous_event_hash`
- `event_hash`
- UTC event time;
- actor type and actor identifier;
- tenant and account boundary;
- object type and identifier;
- event type;
- request and idempotency identifiers;
- approval reference when applicable;
- policy and product versions;
- before and after digests where relevant;
- outcome and stable error code;
- redacted structured detail;
- retention class.

Audit events are append-only. Corrections point to earlier events. Access to audit events is itself audited. A hash chain offers tamper evidence, not proof against a fully compromised application and database; exports should state that limit.

---

## 9. Security and privacy requirements

### 9.1 Raw-secret boundary

- Raw values exist only in process memory or an isolated, process-owned temporary scan directory.
- Temporary files use restrictive permissions and guaranteed cleanup on success, failure, cancellation, and process recovery where feasible.
- Application tables do not store raw Gist bodies.
- Logs use structured allowlists, never arbitrary exception payloads from secret-handling code.
- Browser and notification payloads contain masked evidence only.
- Crash reporting and telemetry exclude content and fingerprints.

### 9.2 Fingerprinting

- Use HMAC-SHA-256 with a dedicated fingerprint key, not a plain SHA-256 digest.
- Version keys and support controlled rotation.
- Bind deduplication to the tenant boundary.
- Preserve one-to-many exposure observations.
- Never expose fingerprints in ordinary APIs or exports unless an explicit interoperability need passes review.

### 9.3 Authorization

- Read authorization is separate from write authorization.
- The default onboarding path requests read access only.
- The UI explains granted and missing scopes.
- Every request enforces tenant and object ownership server-side.
- Provider validity checks use distinct consent and credentials.

### 9.4 Retention

- Retain source metadata, masked evidence, case decisions, actions, and audit events according to explicit policy.
- Do not retain raw source content.
- Support account disconnect, token revocation, evidence export, and policy-bound deletion.
- Deletion of operational records produces a tombstone event where policy permits.

---

## 10. Detection and risk requirements

### 10.1 Detector contract

Each detector must publish:

- supported secret types;
- rule identifiers;
- expected precision class;
- known blind spots;
- paired-pattern requirements;
- encoding support;
- maximum input size;
- timeout behavior;
- version and configuration digest.

Model-assisted triage is advisory. It does not receive raw secret values unless a separate privacy and threat review approves that route. It never dismisses a case without a logged human or deterministic policy decision.

### 10.2 Severity model

Priority should combine independent inputs:

- credential type;
- confidence;
- confirmed validity;
- current versus historical exposure;
- public versus secret visibility;
- exposure age;
- number of observed locations;
- known privilege or production context;
- owner-supplied business impact.

The UI must show which inputs are known, inferred, or missing. “Critical” requires either confirmed active high-impact credentials or a documented conservative policy rule. A string type alone is insufficient.

### 10.3 Benchmark gate

Before external pilot claims, run a versioned benchmark with:

- confirmed positive fixtures;
- realistic benign fixtures;
- current and historical Gist structures;
- paired and split credentials;
- encoded variants;
- large and truncated files;
- duplicate credentials across several Gists;
- secret and public visibility states.

Report precision, recall, false-positive rate, false-negative examples, latency, and coverage by detector and secret class. Never publish “low false-positive rate” without this evidence.

---

## 11. User experience requirements

### 11.1 Audit summary

The first screen answers:

- What scope was checked?
- How complete was coverage?
- What needs human attention now?
- Which credentials appear active?
- Which cases have unresolved current or historical exposure?
- Which actions await approval?

### 11.2 Case detail

Each case shows:

- masked evidence and every observed location;
- current versus historical status;
- detector and confidence basis;
- credential-validity state;
- impact inputs;
- recommended response order;
- action limits;
- event timeline;
- residual risk.

### 11.3 Language rules

Use precise terms:

- “detected pattern,” not “confirmed leak,” before review;
- “secret gist,” not “private gist”;
- “current source cleared,” not “risk removed,” after an edit;
- “credential reported inactive,” not “safe,” after a validity check;
- “deletion confirmed by GitHub response and follow-up read,” not “erased everywhere.”

---

## 12. Success measures

### 12.1 Safety guardrails

- Raw secret persistence incidents: **0**
- Raw secret appearances in API, logs, notifications, browser payloads, or exports: **0**
- Mutations without a valid approval: **0**
- Cases marked resolved without required verification: **0**
- Cross-tenant case or fingerprint exposure: **0**

### 12.2 Audit quality

- Acquisition coverage by Gist, file, and revision.
- Percentage of observations with complete detector provenance.
- Percentage of response actions with complete approval and verification evidence.
- Percentage of exported bundles passing schema and hash-chain validation.
- Replay agreement for fixed detector versions and fixtures.

### 12.3 Detection quality

- Precision and recall by secret class.
- Human-confirmed false-positive rate by detector and rule.
- Indeterminate rate.
- Percentage of confirmed cases found only in history.
- Percentage of correlated credentials found in multiple exposure locations.

### 12.4 Response quality

- Median time from observation to human disposition.
- Median time from confirmation to credential revocation.
- Median time from confirmation to current-source clearance.
- Percentage of confirmed cases with explicit residual-risk records.
- Reopen rate after reported resolution.

### 12.5 Product validation

- Percentage of pilot users who complete an audit.
- Percentage who adjudicate at least one case.
- Percentage who export or retain a proof bundle.
- Number of confirmed findings not surfaced through the user’s prior workflow.
- Pilot-user statement of the decision improved by the product.
- Willingness to repeat the audit and willingness to pay, recorded separately.

“Gists scanned” and “findings generated” are operational counts, not success outcomes.

---

## 13. Release gates

### Gate A: Platform truth

- Remove public-to-secret conversion from product copy and code paths.
- Document secret-Gist visibility accurately.
- Exercise current GitHub Gist API behavior against a disposable test account.
- Test pagination, revision fetch, truncation, deletion, missing permissions, rate limits, and deleted sources.

### Gate B: Evidence safety

- Prove that raw Gist content and raw secrets do not persist in database rows.
- Replace plain hashes with a single versioned HMAC implementation.
- Add tests that scan database, API, logs, notifications, exports, and browser payloads for fixture secrets.
- Review temporary-file lifecycle for optional scanners.

### Gate C: Case integrity

- Replace global one-row secret deduplication with tenant-scoped cases and multiple observations.
- Add explicit validity, exposure, disposition, response, and residual-risk states.
- Preserve detector provenance and acquisition coverage.

### Gate D: Approval and verification

- Disable unattended remediation for the first release.
- Add exact-target approvals, expiry, idempotency, and pre-action state checks.
- Verify actions through fresh reads and separate credential evidence.
- Prevent “completed” from displaying as “resolved.”

### Gate E: Audit integrity

- Make events append-only.
- Add stable event types and error codes.
- Add per-tenant sequencing and tamper-evident hashes.
- Validate proof-bundle schema and redaction.

### Gate F: Detection evidence

- Publish internal benchmark results by rule and secret class.
- Set pilot thresholds from measured results.
- Keep unsupported secret types and model judgments visibly experimental.

---

## 14. Rollout plan

### Phase 0: Correctness hardening

Complete Gates A–E. Use disposable fixtures only. No external security claim should exceed the test evidence.

### Phase 1: Consent-based single-user audits

Run five pilot audits in read-only mode. Observe review behavior, missing context, false positives, coverage gaps, and proof-bundle usefulness. No automated mutation.

### Phase 2: Approved response actions

Add deletion or supported current-content edits only after the approval and verification model passes adversarial tests. Rotation remains guided unless a provider-specific integration exists.

### Phase 3: Recurring monitoring

Enable scheduled read-only scans and digests after change detection, idempotency, rate-limit behavior, and alert fatigue meet defined thresholds.

### Phase 4: Team and organization hypothesis test

Test whether account aggregation is feasible and valuable. Do not build enterprise policy layers before confirming authorization, coverage, buyer, and workflow fit.

---

## 15. Immediate implementation corrections revealed by review

These are repository observations, not runtime test results:

### P0 — block misleading or unsafe behavior

1. **Remove `make_gist_private`.** The service sends `PATCH /gists/{id}` with `{"public": false}`, but GitHub’s update contract does not accept a `public` field and GitHub states that a public Gist cannot be converted to secret.
2. **Disable auto-remediation.** The current auto-remediation path calls the unsupported make-private action. The first product release should use read-only monitoring plus approved response plans.
3. **Stop raw content persistence.** `GistFile.content` exists, and the update path assigns fetched Gist content to it. That contradicts the stated database-compromise safety goal.
4. **Unify fingerprinting.** Repository code contains both plain SHA-256 and keyed HMAC descriptions or implementations. Use one dedicated, versioned HMAC path and remove plain-secret digests.

### P1 — repair evidence semantics

1. **Replace global fingerprint uniqueness.** `Finding.value_hash` is globally unique while the scanner also expects per-Gist deduplication. This loses or rejects distinct exposure locations and creates tenant-boundary risk.
2. **Split cases from observations.** Store every source location, then correlate them under one case.
3. **Expand audit events.** The current audit record is a mutable row with free-form text and JSON. Add stable event types, approval references, before/after digests, sequencing, and tamper evidence.
4. **Separate action completion from security resolution.** GitHub action success, current-source clearance, and credential revocation are different verification results.
5. **Treat rotation as a guided step.** The current rotation method is a stub and should not appear as implemented rotation.

### P2 — prove product claims

1. Benchmark detection quality.
2. Exercise the full API path against disposable Gists.
3. Validate all redaction surfaces with seeded fixture secrets.
4. Test proof-bundle replay and schema validation.
5. Run user pilots before selecting a buyer, pricing model, or organization roadmap.

---

## 16. Major changes and rationale

| Major change | Rationale |
|---|---|
| Reframed the product as an evidence-safe audit and response queue | “Security monitoring platform” is broad and weakly differentiated. GitHub already scans secret gists for partner patterns. The tighter frame emphasizes defensible decisions and proof. |
| Narrowed the first user to an authorized account owner | Gists are user-scoped. The earlier organization language lacked an authorization and coverage model. |
| Replaced “private Gist” language with exact visibility terms | GitHub says secret gists are not private and public gists cannot be converted to secret. The earlier remediation promise was false. |
| Made read-only operation the default | The system processes high-risk material. Trust depends on least privilege and review before mutation. |
| Removed unattended remediation from v1 | The present automated path targets an unsupported action, and no evidence supports user demand or safety for autonomous deletion or edits. |
| Put credential rotation before content cleanup | Deleting or editing a Gist does not revoke a leaked credential. Response order must reflect the security objective. |
| Split detection confidence, credential validity, impact, exposure, and remediation | The earlier severity model collapsed distinct claims and risked overstating certainty. |
| Added acquisition coverage and truncation states | A clean scan is meaningless when content, revisions, or large files were skipped. GitHub documents truncation and alternate fetch routes. |
| Replaced one-row findings with cases plus observations | One credential might appear across several Gists and revisions. Every exposure location belongs in the evidence record. |
| Specified a versioned HMAC fingerprint | Plain hashes expose low-entropy values to offline guessing. Repository documents and code are inconsistent today. |
| Prohibited raw Gist-body persistence | The current model and update path permit raw content storage, conflicting with the repository’s own threat model. |
| Added append-only, tamper-evident event requirements | Free-form mutable audit rows are operational logs, not a defensible evidence trail. |
| Tightened “proof of fix” into separate verification claims | Current-source clearance, source deletion, credential revocation, and absence of copies are different facts. |
| Replaced vanity metrics with safety, quality, response, and validation measures | Scan and finding volume do not establish value. Precision, coverage, verified response, and user decisions do. |
| Added release gates and pilot evidence | The prior roadmap marked phases complete without tying product claims to platform exercises, detection benchmarks, or user validation. |

---

## 17. Open decisions and testable questions

1. **Native-gap test:** On a controlled corpus, what confirmed exposures does Infinite Gist surface that the account owner did not already receive through GitHub or provider notifications?
2. **Audit-value test:** Do users retain or share the proof bundle, and which decision does it support?
3. **Trust test:** What permission level causes users to abandon onboarding? Compare read-only first with upfront write access.
4. **History-value test:** What share of confirmed, actionable cases appears only in revisions?
5. **Validity-check test:** Which provider checks are safe, side-effect-free, and useful enough to justify added exposure and consent?
6. **Buyer test:** Who owns the problem, who performs the review, and who pays? Record these as separate roles.
7. **Team-coverage test:** What account-authorization model yields acceptable coverage for a small team?
8. **Retention test:** How long should masked evidence and audit events remain, and which customer or legal requirement drives that period?

---

## 18. Sources and review limits

### Repository sources

- [Current PRD](https://github.com/AgenticJennifer/infinite-gist/blob/main/docs/infinite-gist-prd.md)
- [README](https://github.com/AgenticJennifer/infinite-gist/blob/main/README.md)
- [Product notes](https://github.com/AgenticJennifer/infinite-gist/blob/main/PRODUCT.md)
- [Security model](https://github.com/AgenticJennifer/infinite-gist/blob/main/SECURITY.md)
- [Roadmap](https://github.com/AgenticJennifer/infinite-gist/blob/main/.planning/ROADMAP.md)
- [Database models](https://github.com/AgenticJennifer/infinite-gist/blob/main/src/backend/db/models.py)
- [Gist scanner](https://github.com/AgenticJennifer/infinite-gist/blob/main/src/backend/services/gist_scanner.py)
- [GitHub service](https://github.com/AgenticJennifer/infinite-gist/blob/main/src/backend/services/github_service.py)
- [Audit service](https://github.com/AgenticJennifer/infinite-gist/blob/main/src/backend/services/audit_service.py)
- [Remediation service](https://github.com/AgenticJennifer/infinite-gist/blob/main/src/backend/services/remediation_service.py)

### Platform sources

- [GitHub REST API endpoints for Gists](https://docs.github.com/en/rest/gists/gists)
- [GitHub: Creating Gists](https://docs.github.com/en/get-started/writing-on-github/editing-and-sharing-content-with-gists/creating-gists)
- [GitHub: OAuth app scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)
- [GitHub: Secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning)
- [GitHub: Supported secret-scanning patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)

This review inspected repository source and documentation but did not execute the application, rerun its test suite, inspect production data, interview users, or benchmark detection. Repository status claims remain observed claims until independently reproduced.

---

## 19. Definition of version 1 success

Version 1 succeeds when an authorized GitHub user completes a read-only audit with measured coverage, reviews at least one evidence-backed case, follows a safe response plan, verifies credential and source outcomes separately, and exports a redacted proof bundle whose events and provenance pass validation.

It fails if it stores raw secrets, implies complete coverage after skipped content, treats a heuristic match as confirmed, claims a secret Gist is private, marks a case fixed after cosmetic cleanup alone, or performs a mutation without exact approval.
