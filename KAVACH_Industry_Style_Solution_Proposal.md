KAVACH

AI-Powered Runtime System Security and Intrusion Detection Platform

SOLUTION PROPOSAL

| Document Control \| Details \|

| --- \| --- \|

| Document type \| Solution Proposal \|

| Version \| 1.0 \|

| Date \| 31 October 2026 \|

| Proposed platform \| Linux endpoint / runtime monitoring prototype \|

| Project duration \| 6 weeks (proposed) \|

| Status \| Proposed -- for academic review and implementation planning
  \|

Prepared as a project-level technical proposal

## 1. Executive Summary

KAVACH is a proposed Linux-focused runtime security and intrusion
detection platform that monitors system activity, identifies suspicious
behaviour, and helps an operator investigate potential security
incidents. Instead of relying only on file signatures or isolated log
entries, KAVACH correlates activity across processes, file changes, and
network connections to build a clearer picture of what a program is
doing.

The proposed solution combines lightweight endpoint telemetry,
configurable detection rules, behaviour-based risk scoring, process and
event correlation, and AI-assisted incident explanations. A web
dashboard will present alerts, timelines, and process relationships so
that a user can review the evidence behind each detection.

The initial release is an academic proof of concept for a controlled
Linux environment. It is not positioned as a replacement for a
commercial Endpoint Detection and Response (EDR) product, antivirus
suite, or enterprise Security Information and Event Management (SIEM)
platform.

### 1.1 Proposal at a Glance

| Area \| Proposal \|

| --- \| --- \|

| Problem \| Suspicious runtime activity can be difficult to identify
  when process, file, and network events are viewed separately. \|

| Proposed response \| Collect and correlate endpoint events, apply
  behaviour-based detection, and present evidence-backed alerts. \|

| Primary users \| Students, system administrators, security learners,
  and reviewers operating a controlled Linux test environment. \|

| Initial platform \| Ubuntu/Linux workstation or virtual machine. \|

| Core outcome \| A working prototype that detects selected suspicious
  behaviours and explains why they were flagged. \|

| Delivery model \| Six-week staged implementation with a defined MVP
  and optional stretch features. \|

## 2. Problem Statement and Business Need

Modern operating systems generate many events while applications
execute: processes start and stop, files are created or modified, and
programs establish network connections. A suspicious activity may be
visible only when these events are considered together. For example, an
unfamiliar process may launch a command interpreter, modify a monitored
configuration file, and then communicate with an external destination.

When monitoring tools expose these events in separate views, an
investigator may need to manually reconstruct the sequence. This
increases investigation effort and can make it harder for a learner or
small system administrator to understand the context of an alert.

### 2.1 Problem to Be Addressed

How can a Linux system continuously monitor selected runtime activities,
correlate process, file, and network events, and identify potentially
suspicious behaviour with clear supporting evidence?

### 2.2 Current Challenges

-   Fragmented visibility: process, file, and network activities may be
    recorded by different tools.

-   Limited context: a single event may appear harmless without its
    parent process or surrounding activity.

-   Alert interpretation: raw event records do not always explain why an
    activity may be risky.

-   Investigation effort: reconstructing the sequence of events manually
    can be time-consuming.

-   Prototype constraints: a student-scale solution must balance useful
    visibility with implementation time and system overhead.

## 3. Proposed Solution

KAVACH will operate as a lightweight endpoint monitoring and analysis
platform on a Linux machine. It will collect selected system events,
normalize them into a common event format, associate events with
processes, and evaluate activity using transparent detection rules and
risk scoring. Related events will be grouped into an incident timeline.
An AI-assisted explanation component may then summarize the recorded
evidence in plain language.

### 3.1 Proposed Operating Flow

1.  Collect: capture process lifecycle information, selected file
    changes, and process-associated network connection metadata.

2.  Normalize: convert collected records into a consistent event schema
    with timestamps and process identifiers.

3.  Enrich: attach available process details such as PID, parent PID,
    executable path, user ID, and command line.

4.  Detect: evaluate events and event sequences against configurable
    behaviour rules; optionally use anomaly scoring as an experimental
    layer.

5.  Correlate: group related events by process identity, parent-child
    relationships, time window, and other available attributes.

6.  Explain: generate a concise, evidence-grounded incident explanation
    that references the underlying event identifiers.

7.  Present: display alerts, severity, process relationships, and event
    timelines in a dashboard.

### 3.2 Key Differentiator

KAVACH focuses on runtime behaviour and event relationships rather than
treating every event as an isolated alert. Its central value is the
ability to connect what a process launched, which monitored files it
affected, and what network activity was associated with it---where the
operating system exposes sufficient attribution data.

## 4. Objectives and Expected Outcomes

-   Monitor selected process activity on a Linux endpoint.

-   Detect and record changes to configured files or directories using
    hashes and file-event metadata.

-   Collect available network connection metadata and associate it with
    processes where possible.

-   Apply explainable rules and risk scoring to identify selected
    suspicious patterns.

-   Correlate related events into an incident timeline and process
    relationship view.

-   Provide AI-assisted summaries that are grounded in collected
    evidence and clearly distinguish facts from hypotheses.

-   Evaluate detection quality, event-processing latency, attribution
    quality, and resource overhead.

## 5. Scope and Boundaries

### 5.1 Minimum Viable Product (MVP)

| In scope \| MVP implementation \|

| --- \| --- \|

| Process monitoring \| Process start/stop, PID, parent PID, user,
  executable path, and available command-line metadata. \|

| File integrity monitoring \| Watch selected test directories; record
  create/modify/delete events and calculate SHA-256 hashes where
  applicable. \|

| Network metadata \| Record available connection metadata such as
  process association, protocol, local/remote endpoint, and timestamp.
  \|

| Detection \| A small set of transparent rules for selected suspicious
  process, file, and network behaviours. \|

| Correlation \| Group events into a timeline and display process
  parent-child relationships. \|

| AI explanation \| Optional LLM-generated explanation using only
  selected incident evidence; retain source event references. \|

| Dashboard \| View system status, alerts, incident details, event
  timelines, and process relationships. \|

### 5.2 Out of Scope for the Initial Release

-   Production-grade enterprise EDR replacement or guaranteed prevention
    of all malware.

-   Kernel-level agent development or mandatory eBPF implementation.

-   Automatic deletion or quarantine of files, network blocking, or
    unattended destructive response.

-   Monitoring devices or networks without authorization.

-   Training a new foundation model or claiming AI-based detection
    without measured evaluation.

-   Guaranteed attribution for every network event; visibility depends
    on platform permissions and available telemetry.

### 5.3 Optional Enhancements

-   eBPF-based telemetry as a stretch goal if the environment and time
    permit.

-   Isolation Forest or another unsupervised model evaluated against a
    defined dataset.

-   A richer process graph and incident comparison view.

-   Manual response actions in an isolated lab, such as terminating a
    selected test process after explicit confirmation.

## 6. Solution Architecture

The proposed architecture separates endpoint collection, event
processing, detection, incident analysis, and user presentation. This
separation allows each module to be tested independently and keeps the
initial implementation manageable.

| Layer \| Responsibilities \|

| --- \| --- \|

| LINUX ENDPOINT \| Process telemetry (/proc, psutil) • File events
  (watchdog / auditd) • Network metadata (available OS connection data)
  \|

| EVENT COLLECTION & NORMALIZATION \| Collectors → common event schema →
  timestamping and process enrichment \|

| ANALYSIS & CORRELATION \| Rule engine + risk scoring → process tree →
  event correlation → incident timeline \|

| AI-ASSISTED EXPLANATION \| Evidence-only incident context →
  explanation with event references and uncertainty labels \|

| APPLICATION & STORAGE \| FastAPI service → SQLite (MVP) → React
  dashboard / process graph \|

Conceptual data flow: Linux endpoint sources → collectors → normalized
event store → detection and correlation → incident record → AI-assisted
explanation → dashboard.

### 6.1 Major Components

| Component \| Responsibility \| Candidate technology \|

| --- \| --- \| --- \|

| Endpoint collector \| Collect process and system activity. \| Python,
  psutil, /proc \|

| File monitor \| Watch selected directories and record file changes. \|
  watchdog; auditd where suitable \|

| Network monitor \| Capture available connection metadata and process
  association. \| psutil and Linux networking interfaces \|

| Event pipeline \| Normalize, validate, timestamp, and persist events.
  \| Python, FastAPI, SQLite \|

| Detection engine \| Apply rules, assign risk scores, and record
  reasons. \| Python rule modules; optional scikit-learn \|

| Correlation engine \| Link process ancestry and related events. \|
  NetworkX or relational queries \|

| Explanation service \| Summarize evidence without inventing missing
  facts. \| LLM API with structured input/output \|

| Dashboard \| Display alerts, timelines, and process relationships. \|
  React, TypeScript, Cytoscape.js \|

## 7. Functional Requirements

| ID \| Functional requirement \|

| --- \| --- \|

| FR-01 \| The system shall collect selected process lifecycle events
  from the monitored Linux endpoint. \|

| FR-02 \| The system shall record process identifiers and available
  parent-process and executable metadata. \|

| FR-03 \| The system shall monitor user-configured directories for file
  changes. \|

| FR-04 \| The system shall calculate SHA-256 hashes for monitored files
  when appropriate. \|

| FR-05 \| The system shall collect available network connection
  metadata and associate it with a process when supported. \|

| FR-06 \| The system shall normalize collected events into a common
  schema. \|

| FR-07 \| The system shall evaluate configured rules and record the
  reason for each alert. \|

| FR-08 \| The system shall correlate related events into an incident
  timeline. \|

| FR-09 \| The system shall display incident evidence and process
  relationships in a dashboard. \|

| FR-10 \| The system may generate an AI-assisted explanation that
  references the evidence supplied to it. \|

| FR-11 \| Any response action shall require explicit user confirmation
  and be limited to the test environment. \|

## 8. Non-Functional Requirements

| Quality attribute \| Requirement \|

| --- \| --- \|

| Performance \| Collectors should be lightweight; processing delay and
  CPU/memory overhead will be measured during tests. \|

| Reliability \| Collector and analysis failures should be logged;
  malformed events should not crash the full pipeline. \|

| Security \| Apply least privilege, restrict monitored paths, protect
  stored event data, and avoid exposing secrets in logs. \|

| Explainability \| Each alert should include its triggering rule or
  score contribution and supporting event references. \|

| Usability \| The dashboard should make alert severity, time, process,
  and evidence easy to inspect. \|

| Maintainability \| Keep collectors, rules, correlation, storage, and
  API layers modular and testable. \|

| Privacy \| Collect only the metadata needed for the project; avoid
  capturing file contents or unrelated personal data. \|

## 9. Detection and Risk-Scoring Approach

The first version will prioritize deterministic, explainable rules. Each
rule will define the observed condition, its severity, and the evidence
fields required to trigger it. A risk score may combine rule severity
and contextual signals, but the score will be treated as a
prioritization aid---not a probability that an attack has occurred.

### 9.1 Example Behaviour Scenarios

| Scenario \| Possible signals \| KAVACH response \|

| --- \| --- \| --- \|

| Unexpected command interpreter child process \| A monitored
  application launches a shell or unusual child process. \| Record
  process ancestry; raise a rule-based alert if the configured context
  matches. \|

| Sensitive test-file modification \| A process modifies a file in a
  configured test directory. \| Record path, operation, timestamp,
  process details, and before/after hash where available. \|

| Correlated multi-stage activity \| The same process chain is
  associated with a suspicious child process, monitored file change, and
  unusual outbound connection. \| Group the events into one incident
  timeline and show the supporting evidence. \|

The examples are controlled test scenarios, not claims that these
signals alone prove malicious intent. Rules must be tuned and evaluated
to reduce false positives.

## 10. AI-Assisted Investigation Design

AI is proposed as an explanation and investigation-assistance layer, not
as the sole authority for detection. The detection engine will first
produce a structured incident record containing event IDs, timestamps,
process metadata, triggered rules, and observed indicators. Only this
evidence bundle will be passed to the language model.

-   The model should summarize what was observed and identify which
    events support each statement.

-   It should label uncertain interpretations as hypotheses rather than
    facts.

-   It must not invent missing process details, file contents, network
    reputation, or attacker identity.

-   The UI should retain links to the original events so a reviewer can
    verify the explanation.

-   If the AI service is unavailable, deterministic detection and
    dashboard functionality should continue.

## 11. Technology Stack

| Layer \| Proposed technology \| Reason for selection \|

| --- \| --- \| --- \|

| Operating environment \| Ubuntu Linux VM / workstation \| Provides a
  controlled environment for process and file monitoring. \|

| Collector and backend \| Python, psutil, FastAPI \| Rapid
  implementation, OS metadata access, and API development. \|

| File monitoring \| watchdog; auditd where appropriate \| Supports
  monitoring of configured file-system activity. \|

| Storage \| SQLite for MVP; PostgreSQL optional \| Simple local
  persistence with a path to a more robust database. \|

| Detection and analysis \| Python rules; optional scikit-learn \|
  Explainable baseline with an optional experimental anomaly layer. \|

| Correlation and graph \| NetworkX, Cytoscape.js \| Process/event
  relationship analysis and visualization. \|

| Frontend \| React, TypeScript \| Structured dashboard development. \|

| Testing and packaging \| pytest, Docker Compose (where suitable) \|
  Repeatable testing and service setup. \|

| AI explanation \| LLM API, optional \| Plain-language incident
  summaries grounded in evidence. \|

## 12. Implementation Plan and Timeline

| Week \| Planned activities \| Milestone / output \|

| --- \| --- \| --- \|

| 1 \| Set up Ubuntu test environment; inspect /proc and psutil; define
  event schema; implement process collector. \| Process telemetry
  prototype and schema. \|

| 2 \| Implement selected file monitoring, hashing, network metadata
  collection, and local persistence. \| End-to-end event ingestion. \|

| 3 \| Build rule engine, risk scoring, process ancestry, and basic
  event correlation. \| First detection and incident records. \|

| 4 \| Add AI-assisted explanation with evidence references; test
  failure handling and explanation quality. \| Evidence-grounded
  incident explanation. \|

| 5 \| Build dashboard views for alerts, event timelines, and process
  relationships; add controlled response only if stable. \| Usable
  dashboard and integrated MVP. \|

| 6 \| Run test scenarios; measure detection and overhead; fix issues;
  package, document, and prepare demo. \| Test report, documentation,
  and final demonstration. \|

The schedule assumes a focused prototype and access to a Linux test
environment. eBPF, extensive model training, and production hardening
are not dependencies for MVP delivery.

## 13. Validation and Success Metrics

KAVACH will be evaluated using repeatable benign and controlled
suspicious-behaviour scenarios in an isolated Linux VM. Metrics will be
reported from actual test runs; target values are provisional
engineering goals, not guaranteed outcomes.

| Metric \| How it will be measured \| Proposed evaluation goal \|

| --- \| --- \| --- \|

| Detection precision \| True positive alerts / all positive alerts in
  the labelled test set. \| Target ≥ 85% on the defined test scenarios.
  \|

| Detection recall \| Detected labelled scenarios / all labelled
  scenarios executed. \| Target ≥ 85% on the defined test scenarios. \|

| Process attribution \| Share of eligible events linked to the correct
  process in the test set. \| Target ≥ 90% where OS telemetry supports
  attribution. \|

| Event processing latency \| Time from event timestamp/receipt to
  persisted analysis result. \| Aim for under 2 seconds for the
  prototype workload. \|

| AI evidence validity \| Share of factual claims in generated
  explanations supported by referenced event records. \| Target 100% for
  claims presented as observed facts. \|

| Resource overhead \| CPU and memory use while idle and during a
  defined workload. \| Establish baseline and report measured overhead.
  \|

The test set should include normal application activity as well as
controlled scenarios. Results must state the number and type of test
cases; small prototype results should not be generalized to all Linux
systems.

## 14. Risks, Assumptions, and Mitigations

| Risk / assumption \| Potential impact \| Mitigation \|

| --- \| --- \| --- \|

| Monitoring permissions vary by Linux configuration. \| Some process or
  network details may be unavailable. \| Document required permissions;
  degrade gracefully; test on the target Ubuntu setup. \|

| File and process events may be noisy. \| False positives and excessive
  event volume. \| Limit monitored paths; add configurable rules and
  filters; measure false positives. \|

| Process-to-network attribution may be incomplete. \| An event may not
  map reliably to a process. \| Record attribution confidence and
  missing fields; avoid unsupported conclusions. \|

| LLM output may hallucinate or overstate risk. \| Misleading incident
  explanations. \| Use structured evidence, event references,
  uncertainty labels, and deterministic detection as the source of
  alerts. \|

| Time constraints may affect advanced features. \| MVP delivery could
  be delayed. \| Prioritize collectors, deterministic rules,
  correlation, and a basic dashboard; defer eBPF and ML. \|

| Elevated privileges increase risk. \| The monitoring agent could
  affect the host system. \| Use a disposable VM, least privilege,
  test-only paths, and no automatic destructive response. \|

### 14.1 Key Assumptions

-   A Linux/Ubuntu virtual machine or dedicated test machine will be
    available.

-   The project will monitor only systems and files for which the team
    has authorization.

-   An external LLM API is optional; the MVP remains useful without it.

-   The initial database and dashboard are intended for a single test
    deployment, not a multi-tenant enterprise rollout.

## 15. Security, Privacy, and Safe Testing

Because KAVACH monitors system activity, the prototype must be developed
and demonstrated responsibly. Testing will use synthetic workloads and
deliberately created test files inside an isolated virtual machine. No
real malware, unauthorized access, or third-party monitoring is
required.

-   Restrict monitoring to explicitly configured directories and the
    project test machine.

-   Avoid collecting file contents, credentials, browser data, or
    unrelated personal information.

-   Protect API keys and other secrets using environment variables;
    never place them in source control or event records.

-   Run collectors with the minimum permissions needed and document any
    elevated permission requirement.

-   Keep response actions disabled by default; any process termination
    demonstration must require manual confirmation and target a known
    test process.

-   Provide a clear way to stop the collector and remove test
    configuration.

## 16. Deliverables

-   Working Linux endpoint collector for the agreed MVP event types.

-   Common event schema and local event storage.

-   Configurable detection rules with risk/severity and evidence
    references.

-   Incident correlation and process relationship representation.

-   Basic web dashboard for alerts and incident investigation.

-   Optional AI-assisted incident explanation module.

-   Automated tests and a documented set of controlled demonstration
    scenarios.

-   Architecture diagram, setup guide, user guide, limitations, and
    evaluation report.

## 17. Acceptance Criteria

-   The collector runs on the selected Linux test environment and
    records the agreed MVP event types.

-   A monitored test-file modification is detected and recorded with
    relevant metadata and hash information where supported.

-   At least three documented behaviour scenarios can be replayed and
    produce expected event records.

-   The detection engine creates alerts with a clear triggering reason
    and supporting event IDs.

-   Related events can be viewed together in an incident timeline.

-   The dashboard displays alert details and process relationships for
    the tested scenarios.

-   AI-generated explanations, if enabled, reference supplied evidence
    and do not replace the underlying event record.

-   The project includes test results, known limitations, setup
    instructions, and a reproducible demonstration.

## 18. Conclusion and Recommendation

KAVACH proposes a practical approach to Linux runtime monitoring by
connecting process, file, and network activity into evidence-backed
incident views. Its main contribution is the correlation of system
behaviour and the explanation of why a sequence of events deserves
attention. A staged six-week implementation, beginning with
deterministic monitoring and detection, keeps the project achievable
while leaving room for optional anomaly detection and AI-assisted
investigation.

Recommendation: proceed with the MVP as a controlled Linux proof of
concept. Validate event collection and attribution first, then add
correlation, dashboard functionality, and the optional AI explanation
layer. This sequence reduces technical risk and ensures that the core
security workflow remains useful even if advanced components are
deferred.

## Appendix A -- Example Incident Record (Illustrative)

| Field \| Illustrative value \|

| --- \| --- \|

| Incident ID \| KAV-INC-0001 \|

| Severity \| Medium (prototype rule output) \|

| Observed sequence \| Test application starts child shell → monitored
  test configuration file changes → outbound connection metadata is
  observed. \|

| Evidence \| Event IDs, timestamps, process IDs, parent PID, file
  path/hash metadata, and available connection metadata. \|

| Detection reason \| Multiple configured behaviour signals occurred
  within the correlation window. \|

| AI explanation \| A plain-language summary of the recorded sequence,
  with links to the supporting event IDs. \|

| Analyst status \| Needs human review; the sequence is suspicious for
  the configured test policy but is not proof of compromise. \|

## Appendix B -- Glossary

| Term \| Meaning \|

| --- \| --- \|

| Runtime monitoring \| Observing activity while programs and services
  are executing. \|

| Endpoint \| A computer or virtual machine being monitored. \|

| Process \| A running instance of a program, identified by an
  operating-system process ID. \|

| Parent process \| The process that created or launched another
  process. \|

| File integrity monitoring \| Recording changes to selected files,
  often using cryptographic hashes. \|

| Event correlation \| Connecting related events using time, process
  identity, and other available context. \|

| EDR \| Endpoint Detection and Response; a category of tools for
  endpoint visibility, detection, and response. \|

| False positive \| A benign activity incorrectly flagged as suspicious.
  \|
