# Phase 3 Evaluation Record

## Scope and method

The controlled scenario unit test drives `DetectionEngine` with four
deterministic event fixtures: one benign-labeled scenario and three
rule-signal-labeled scenarios. Each fixture is one prediction; an incident
means detected. These labels check that the configured rules behave as
specified. They are not ground-truth labels for real benign or malicious
endpoint activity.

The live Docker smoke check separately exercised a benign file create and
retrieved its detection and supporting event through the API. It is an
integration check, not an additional labelled precision/recall sample.

The user also ran the collector directly in WSL Ubuntu. Their terminal output
showed successful `/health`, `/events`, and `/incidents` responses; process and
network records; and a monitored test-file creation with a SHA-256 digest and
referenced `KAV-FILE-001` incident. Additional live WSL checks observed process
start/stop, a shell-named process with `KAV-PROC-001`, and file create/modify/
delete events with linked `KAV-FILE-001` incidents. A harmless loopback test
then produced a `KAV-CORR-001` incident through the live collector and API,
confirming the correlated rule emitted for the shell/file/network sequence.
Inspection of the incident's referenced event IDs confirmed the evidence:
the shell process (`bash`, PID 1392), a monitored file creation, and an
established loopback TCP connection attributed to PID 1392 with observed
ownership. A separate 60-second benign file workload (one small file updated
every two seconds) used 61 service-process samples: mean CPU was 1.67% of one
core and mean/peak RSS was 27.38 MiB. It produced one `file.created`, 29
`file.modified`, and 30 linked file incidents. The intended 30 updates yielded
29 modifications, consistent with polling coalescing or a missed change; this
is a limitation of the observed run, not proof of the specific cause. These
checks validate telemetry and detection in WSL, not a
dedicated isolated Linux VM benchmark. The dashboard initially failed
because the WSL copy lacked `web/`; after copying the directory, the user
confirmed the dashboard assets were present and the dashboard loaded.
The evaluator accepts WSL Ubuntu as the required Linux environment, so a
dedicated VM run is not an acceptance prerequisite for this project.

## Observed results

| Measure | Observed result | Interpretation |
| --- | --- | --- |
| Controlled scenario fixtures | 4 total: 3 expected detections, 1 expected no-detection | Synthetic, deterministic rule fixtures |
| Scenario-level confusion counts | TP 3, FP 0, TN 1, FN 0 | Relative only to fixture expectations |
| Scenario-level precision | 100% (3 / 3) | Not a real-world false-positive estimate |
| Scenario-level recall | 100% (3 / 3) | Not representative beyond these fixtures |
| Dashboard / API integration | Health, events, incidents, details, and static assets verified by tests; browser check confirmed healthy status, severity filtering, incident selection, and evidence timeline rendering with no page errors | One integrated browser check; no cross-browser compatibility claim |
| Docker smoke test | File event, SHA-256, low-severity incident, and supporting evidence retrieved | Windows Docker Desktop container namespace only |
| WSL live telemetry and API | Health and event APIs; process start/stop, shell alert, file create/modify/delete alerts, and a live `KAV-CORR-001` incident with referenced shell, file, and established loopback TCP evidence | WSL runtime; connection ownership was observed for PID 1392, the correlated shell |
| WSL dashboard | Loaded after the missing `web/` directory was copied into the WSL project | WSL is accepted by the evaluator as the Linux environment |
| Dedicated Linux VM / host attribution | Not run | Not required by the evaluator; Docker host-procfs overlay remains Linux-host-only |
| End-to-end processing/API latency | Not measured | File-change-to-event timing below does not include API delivery or dashboard refresh |
| WSL idle service resources | 60-second sample, 61 observations: mean CPU 1.07% of one core, mean/peak RSS 27.38 MiB | KAVACH service process only; no concurrent test workload, and not total WSL VM usage |
| WSL benign file-workload resources | 60-second sample, 61 observations: mean CPU 1.67% of one core, mean/peak RSS 27.38 MiB; 1 create and 29 modifications observed | One small file updated every two seconds; 30 linked file incidents; one fewer modification than intended |
| WSL file-change-to-event latency estimate | 31 matching event records: median 418.10 ms, p95 970.56 ms, max 995.78 ms | Computed as collector event timestamp minus file `modified_ns`; p95 was below the provisional 2-second goal in this run. Not end-to-end processing/API latency. The query found 31 records, while the workload summary counted 30 events, so treat these as estimates. |

The 100% fixture metrics should not be read as meeting the proposal's 85%
targets on a meaningful operational dataset. Live WSL runs verified the
documented process, file, and correlated scenarios, and the resource sample
covered idle and a controlled file-change workload. These results complete
the current prototype validation scope, but do not establish production
detection quality or generalize to a broad endpoint workload.

## Limitations and next validation

- The Windows Docker Desktop service observes its container namespace, not
  Windows host processes or network connections.
- Polling collectors can miss short-lived process or network states between
  samples.
- The benign file workload observed 29 modifications for 30 intended updates;
  polling may coalesce rapid successive changes. The latency query returned 31
  records versus 30 in the workload summary, so its percentiles are estimates
  and warrant a bounded repeat before using them as a formal benchmark.
- The live correlated scenario returned a `KAV-CORR-001` incident with
  shell, file, and established loopback TCP evidence. A prior client-side
  summary missed the connection because its filter expected a descendant PID;
  inspecting the incident's event IDs confirmed that the shell itself owned
  the connection.
- File events are scoped to mounted configured directories and are not linked
  to a modifying process by this collector.
- Process/network ownership depends on procfs access and permissions.
- Detection rules are simple, explainable prototype signals and need evaluation
  against a larger benign workload.
- AI explanation is not implemented; dashboard evidence is based on stored
  event references only.
