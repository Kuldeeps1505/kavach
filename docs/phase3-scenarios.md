# Phase 3 Controlled Scenarios

Run the deterministic, synthetic scenario checks with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_scenarios.py" -v
```

These are in-process detection-engine fixtures. They validate expected rule
behavior, not OS-level event collection, attacker behavior, or general malware
detection.

| Scenario | Label for this fixture | Synthetic inputs | Expected result |
| --- | --- | --- | --- |
| Benign application start | No configured signal | `process.started` for `editor` | No incident |
| Observed shell-named child | Configured signal | `process.started` for `sh` | `KAV-PROC-001` |
| Monitored test-file change | Configured signal | `file.modified` under the fixture test path | `KAV-FILE-001` |
| Correlated synthetic activity | Configured signal | `bash` process, test-file change, child process, attributed established TCP event, in that order within 30 seconds | `KAV-CORR-001` plus the individual process/file observations |

The fixture-level score treats each scenario as one prediction: any incident
means detected. These labels mean "the defined rule should emit" and do not
assert that the activity is malicious. Do not compare this tiny synthetic
score to production detection quality.

## Live Docker smoke test

With the default Compose service running, create a harmless file in
`test-data`, wait for one polling interval, and verify:

1. `GET /events?limit=1000` includes `file.created` with the container path
   under `/data/watch` and a SHA-256 digest.
2. `GET /incidents?limit=1000` includes a `KAV-FILE-001` incident referencing
   the event ID.
3. `GET /incidents/{incident_id}` returns that incident and its supporting
   event.
4. Remove the test file and confirm a `file.deleted` event is recorded.

The run used for initial Phase 3 bring-up validated create, incident evidence,
and SHA-256 retrieval. Live delete observation and Linux host-procfs runtime
validation remain to be separately exercised.
