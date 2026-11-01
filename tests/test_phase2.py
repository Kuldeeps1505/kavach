from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

from kavach.api import create_api_server
from kavach.detection import DetectionEngine, Incident
from kavach.schema import Event
from kavach.storage import SQLiteEventStore

_BASE_TIME = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def _event(
    event_type: str,
    seconds: int,
    *,
    pid: int | None = None,
    parent_pid: int | None = None,
    process_name: str | None = None,
    payload: dict[str, object] | None = None,
) -> Event:
    body = dict(payload or {})
    if process_name is not None:
        body["process_name"] = process_name
    return Event(
        event_type=event_type,
        source="test",
        timestamp=(_BASE_TIME + timedelta(seconds=seconds)).isoformat(),
        pid=pid,
        parent_pid=parent_pid,
        payload=body,
    )


class DetectionEngineTests(unittest.TestCase):
    def test_shell_and_file_rules_are_explainable_and_deduplicated(self) -> None:
        shell = _event("process.started", 1, pid=40, parent_pid=1, process_name="bash")
        file_change = _event(
            "file.modified",
            2,
            payload={"path": "/test-data/sample.conf", "sha256": "abc"},
        )
        engine = DetectionEngine()

        incidents = engine.evaluate([shell, file_change])
        self.assertEqual(
            {incident.rule_id for incident in incidents},
            {"KAV-PROC-001", "KAV-FILE-001"},
        )
        self.assertTrue(all(incident.event_ids == (shell.event_id,) for incident in incidents
                            if incident.rule_id == "KAV-PROC-001"))
        self.assertTrue(
            any("does not establish suspicious intent" in incident.reason for incident in incidents)
        )
        self.assertEqual(engine.evaluate([shell, file_change]), [])

    def test_correlates_shell_child_file_and_attributed_connection_with_evidence(self) -> None:
        shell = _event("process.started", 1, pid=40, parent_pid=10, process_name="sh")
        file_change = _event(
            "file.modified",
            2,
            payload={"path": "/test-data/marker.txt", "sha256": "def"},
        )
        child = _event("process.started", 3, pid=41, parent_pid=40, process_name="test-client")
        connection = _event(
            "network.connection",
            4,
            pid=41,
            payload={"protocol": "tcp", "state": "ESTABLISHED"},
        )
        engine = DetectionEngine()

        incidents = engine.evaluate([shell, file_change, child, connection])
        correlated = [incident for incident in incidents if incident.rule_id == "KAV-CORR-001"]

        self.assertEqual(len(correlated), 1)
        incident = correlated[0]
        self.assertEqual(incident.severity, "medium")
        self.assertEqual(incident.confidence, "low")
        self.assertEqual(
            incident.event_ids,
            (shell.event_id, file_change.event_id, child.event_id, connection.event_id),
        )
        self.assertIn("no process attribution", incident.reason)
        self.assertEqual(engine.evaluate([connection]), [])

    def test_does_not_correlate_unattributed_network_or_out_of_window_activity(self) -> None:
        events = [
            _event("process.started", 1, pid=40, parent_pid=10, process_name="bash"),
            _event("file.modified", 2),
            _event(
                "network.connection",
                3,
                payload={"protocol": "tcp", "state": "ESTABLISHED"},
            ),
        ]
        engine = DetectionEngine(correlation_window_seconds=5)

        incidents = engine.evaluate(events)
        self.assertNotIn("KAV-CORR-001", {incident.rule_id for incident in incidents})

        other_engine = DetectionEngine(correlation_window_seconds=5)
        other = other_engine.evaluate(
            [
                _event("process.started", 1, pid=40, parent_pid=10, process_name="bash"),
                _event("file.modified", 2),
                _event(
                    "network.connection",
                    10,
                    pid=40,
                    payload={"protocol": "tcp", "state": "ESTABLISHED"},
                ),
            ]
        )
        self.assertNotIn("KAV-CORR-001", {incident.rule_id for incident in other})

    def test_rejects_non_positive_correlation_window(self) -> None:
        with self.assertRaisesRegex(ValueError, "greater than zero"):
            DetectionEngine(correlation_window_seconds=0)


class IncidentStorageTests(unittest.TestCase):
    def test_incident_and_supporting_events_persist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            event = _event("file.modified", 1, payload={"path": "/test-data/a"})
            incident = Incident(
                rule_id="KAV-FILE-001",
                title="Monitored file changed",
                severity="low",
                reason="Test reason",
                event_ids=(event.event_id,),
                created_at=event.timestamp,
                correlation_basis="configured_path_event",
                confidence="observed",
            )
            with SQLiteEventStore(Path(temporary_directory) / "events.sqlite3") as store:
                store.append(event)
                store.append_incidents([incident])
                self.assertEqual(store.list_incidents(), [incident])
                self.assertEqual(store.get_incident(incident.incident_id), incident)
                self.assertEqual(store.get_events(incident.event_ids), [event])


class IncidentApiTests(unittest.TestCase):
    def test_read_only_api_returns_incident_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = SQLiteEventStore(Path(temporary_directory) / "events.sqlite3")
            event = _event("file.modified", 1, payload={"path": "/test-data/a"})
            incident = Incident(
                rule_id="KAV-FILE-001",
                title="Monitored file changed",
                severity="low",
                reason="Test reason",
                event_ids=(event.event_id,),
                created_at=event.timestamp,
                correlation_basis="configured_path_event",
                confidence="observed",
            )
            store.append(event)
            store.append_incidents([incident])
            server = create_api_server(store, "127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_port}"
            try:
                with urlopen(f"{base_url}/", timeout=2) as response:
                    self.assertIn(b"Security overview", response.read())
                    self.assertEqual(
                        response.headers["Content-Security-Policy"],
                        "default-src 'self'; style-src 'self'; script-src 'self'; "
                        "connect-src 'self'; img-src 'self'; object-src 'none'; "
                        "base-uri 'none'; frame-ancestors 'none'",
                    )
                with urlopen(f"{base_url}/dashboard.js", timeout=2) as response:
                    self.assertIn(b"refreshDashboard", response.read())
                with urlopen(f"{base_url}/dashboard.css", timeout=2) as response:
                    self.assertIn(b".metric-grid", response.read())
                with urlopen(f"{base_url}/health", timeout=2) as response:
                    self.assertEqual(json.load(response), {"status": "ok"})
                with urlopen(f"{base_url}/incidents/{incident.incident_id}", timeout=2) as response:
                    result = json.load(response)
                self.assertEqual(result["incident"]["rule_id"], "KAV-FILE-001")
                self.assertEqual(result["events"][0]["event_id"], event.event_id)
                with self.assertRaises(HTTPError) as error:
                    urlopen(f"{base_url}/incidents?limit=0", timeout=2)
                self.assertEqual(error.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                store.close()


if __name__ == "__main__":
    unittest.main()
