# KAVACH: Three-Phase Execution Plan

This plan turns the six-week schedule in the solution proposal into three
delivery phases. Each phase has a tangible outcome and an exit check. The
project remains a controlled Linux proof of concept; advanced features are
optional and must not delay the core MVP.

## Plan at a Glance

| Phase | Weeks | Goal | Exit outcome |
| --- | --- | --- | --- |
| 1. Foundation and telemetry | 1–2 | Establish the test environment and reliably collect normalized endpoint events. | Process, selected file, and available network metadata reach local storage in a documented schema. |
| 2. Detection and incident analysis | 3–4 | Turn collected events into explainable, correlated incidents. | Deterministic rules produce evidence-linked alerts and timelines; optional AI explanations remain evidence-grounded. |
| 3. Dashboard, validation, and release | 5–6 | Deliver an integrated, demonstrable MVP and report measured results. | Dashboard, automated tests, controlled scenarios, documentation, and evaluation results meet the acceptance checks. |

## Current Execution Status

**Phase 1: In progress.** The initial event schema, SQLite event store,
process/file/network collectors, CLI, setup guide, and unit tests have been
implemented. Nine unit tests pass on the development workstation. Live
collector validation on the selected Linux VM is still required; Phase 1 is
not complete until that environment, permissions, monitored paths, and
process/network attribution have been verified.

**Phase 2: In progress.** Deterministic process/file rules, bounded
process-lineage and time-window correlation, SQLite incident records, and
read-only health/events/incidents API routes have been implemented. Fifteen
unit tests pass, covering the rules, correlation boundaries, persistence, and
API. A live Docker smoke test confirmed a monitored file change produces a
low-severity incident with retrievable event evidence and a SHA-256 digest.
AI explanations are not part of this increment.

**Phase 3: Complete for the current prototype scope.** A responsive dashboard is served by the API and
displays recent telemetry, severity-filtered incidents, evidence timelines,
and process relationships when recorded metadata supports them. Four
deterministic scenario fixtures and an evaluation record have been added.
Sixteen unit tests pass, including the scenario, storage, API, and static
dashboard tests. The dashboard was rebuilt and verified in a browser: health,
severity filtering, incident selection, and evidence timeline rendering
responded. The container reports healthy. WSL live validation has now observed
process start/stop, shell detection, file create/modify/delete, and a
`KAV-CORR-001` incident for a harmless loopback test; the dashboard loaded
after the missing `web/` assets were copied. The incident's referenced event
IDs confirmed an established loopback connection attributed to the shell.
An initial 60-second WSL idle sample measured 1.07% mean CPU (one core) and
27.38 MiB mean/peak RSS for the service process; a 60-second benign file
workload measured 1.67% mean CPU and the same RSS, observing 29 modifications
for 30 intended updates. The file-change-to-event estimate was median 418 ms,
p95 971 ms, and max 996 ms; its 31-record query differed from the workload's
30-event count, so it is indicative rather than a formal benchmark. WSL
Ubuntu satisfies the evaluator's Linux-environment requirement. Broader
endpoint workload evaluation and end-to-end API latency measurement remain
future validation; the results are prototype evidence, not production
detection-quality claims.

**Containerization: Initial Compose setup added.** The default service uses a
read-only filesystem, unprivileged UID, no added capabilities, localhost-only
API publishing, read-only test-data mount, and persistent SQLite volume. By
default it sees the container namespace; an explicit Linux-only overlay opts
into read-only host procfs access. Compose configuration and image build
validated; the default container is running and healthy, and health/event/
incident/dashboard requests responded successfully. The host-procfs overlay
has configuration validation only and requires an authorized Linux host for
runtime validation.

## Phase 1 — Foundation and Telemetry (Weeks 1–2)

**Objective:** Prove that KAVACH can safely collect and persist the MVP event
types on the selected Ubuntu/Linux test environment.

### Work

- Confirm the Linux VM, authorized test scope, required permissions, and
  explicitly configured monitoring directories.
- Define and document the common event schema, including event ID, timestamp,
  event type, process identifiers, available process metadata, and source.
- Implement process lifecycle collection and enrichment using the available
  Linux interfaces.
- Implement file create/modify/delete monitoring for selected test paths;
  record metadata and calculate SHA-256 hashes where applicable.
- Capture available network connection metadata and record missing or
  uncertain process attribution rather than implying certainty.
- Persist normalized events locally using SQLite and log collector or
  ingestion failures.
- Add basic tests for schema validation, persistence, and each collector.

### Deliverables

- Reproducible Linux development/test environment and setup notes.
- Versioned common event schema and sample event records.
- Process, file, and network metadata collectors.
- Local event storage and initial automated tests.
- Documented permissions, monitored paths, and known telemetry limitations.

### Exit checks

- Collector runs on the selected test environment and stores process events.
- A change to a designated test file is recorded with relevant metadata and a
  hash where supported.
- Network metadata is recorded where available, with attribution gaps explicit.
- Collector can be stopped cleanly; monitoring is restricted to authorized
  test scope and does not capture file contents or unrelated personal data.

## Phase 2 — Detection and Incident Analysis (Weeks 3–4)

**Objective:** Use stored telemetry to generate transparent alerts and group
related evidence into incidents.

### Work

- Implement a modular deterministic rule engine with rule IDs, conditions,
  severity, risk contributions, and human-readable triggering reasons.
- Add process ancestry and event correlation using process identity and a
  documented time window; retain references to the original event IDs.
- Create incident records and APIs for alerts, supporting events, and
  timelines.
- Test rules against benign activity and controlled, synthetic scenarios,
  including a test process chain, a monitored test-file change, and correlated
  local test activity.
- If time and an approved provider are available, implement the optional AI
  explanation path using only a structured incident evidence bundle. Label
  interpretations as hypotheses, cite supporting event IDs, and keep detection
  functional when the AI service is unavailable.
- Add unit and integration tests for rule outcomes, correlation, missing
  metadata, and optional AI failure handling.

### Deliverables

- Explainable rule engine and configured MVP rules.
- Process relationship and event-correlation logic.
- Persisted incident records with supporting event IDs and triggering reasons.
- API endpoints or service interfaces for incident data.
- Optional evidence-grounded explanation module, if time permits.
- Automated tests and documented scenario inputs/expected results.

### Exit checks

- Each configured alert records its triggering rule and supporting event IDs.
- Related events can be retrieved as one incident timeline.
- Missing attribution or evidence is represented honestly and does not become
  an unsupported factual claim.
- Core deterministic detection works without the optional AI service.
- At least three documented controlled scenarios produce the expected event
  records and rule outcomes.

## Phase 3 — Dashboard, Validation, and Release (Weeks 5–6)

**Objective:** Integrate the workflow into a usable dashboard, validate it
end-to-end, and prepare a reproducible final demonstration.

### Work

- Build dashboard views for collector/system status, alerts, incident details,
  event timelines, and process relationships.
- Integrate the dashboard with the incident APIs and verify that evidence links
  lead back to original event records.
- Run end-to-end tests across collection, storage, detection, correlation, and
  dashboard display.
- Execute the documented scenarios in an isolated Linux VM, including benign
  baseline activity; record test-case counts and actual outcomes.
- Measure precision, recall, eligible-event process attribution, event
  processing latency, and idle/workload CPU and memory overhead.
- Compare results with the proposal's provisional goals: 85% precision, 85%
  recall, 90% process attribution where supported, under 2-second processing
  latency, and 100% evidence support for AI claims presented as facts. Report
  measured results without presenting goals as guarantees.
- Fix release-blocking defects, document limitations and setup, and prepare an
  architecture overview, user guide, evaluation report, and repeatable demo.
- Keep response actions disabled by default. Do not include destructive or
  unattended response in the MVP.

### Deliverables

- Integrated web dashboard and incident investigation flow.
- End-to-end and automated test results.
- Controlled scenario set and reproducible demonstration instructions.
- Evaluation report with methodology, test counts, measured metrics, and
  limitations.
- Architecture overview, setup guide, and user guide.

### Exit checks

- Dashboard displays alert reason, severity, supporting evidence, timeline, and
  available process relationships for tested scenarios.
- Acceptance scenarios replay reproducibly; event and alert results match
  documented expectations.
- Evaluation reports actual metrics and limitations, including unavailable
  telemetry and resource overhead.
- AI explanations, if enabled, cite supplied evidence and do not replace the
  underlying event record.
- Project can be set up and demonstrated from the written instructions.

## Delivery Controls

- **MVP first:** Do not make eBPF, machine-learning anomaly detection, or
  production hardening prerequisites for delivery.
- **Safe test boundary:** Use an isolated, authorized Linux VM, synthetic
  workloads, and deliberately created test files; do not use real malware or
  monitor third-party systems.
- **Least privilege and privacy:** Restrict monitored paths, collect only
  necessary metadata, avoid secrets and file contents, and document permission
  requirements.
- **Evidence before explanation:** Deterministic rules and recorded events are
  the source of alerts; AI is optional and advisory.
- **Scope trade-off:** If schedule slips, defer the AI explanation and visual
  graph enhancements before reducing collector reliability, evidence-linked
  detection, scenario testing, or reproducibility.
