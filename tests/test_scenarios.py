from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from kavach.detection import DetectionEngine
from kavach.schema import Event

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
    event_payload = dict(payload or {})
    if process_name is not None:
        event_payload["process_name"] = process_name
    return Event(
        event_type=event_type,
        source="scenario-fixture",
        timestamp=(_BASE_TIME + timedelta(seconds=seconds)).isoformat(),
        pid=pid,
        parent_pid=parent_pid,
        payload=event_payload,
    )


@dataclass(frozen=True)
class Scenario:
    name: str
    expected_detection: bool
    events: tuple[Event, ...]


class ControlledScenarioTests(unittest.TestCase):
    def test_expected_scenario_detection_metrics(self) -> None:
        scenarios = (
            Scenario(
                name="benign application start",
                expected_detection=False,
                events=(
                    _event("process.started", 1, pid=10, parent_pid=1, process_name="editor"),
                ),
            ),
            Scenario(
                name="observed shell-named child",
                expected_detection=True,
                events=(
                    _event("process.started", 1, pid=20, parent_pid=10, process_name="sh"),
                ),
            ),
            Scenario(
                name="monitored test-file change",
                expected_detection=True,
                events=(
                    _event("file.modified", 1, payload={"path": "/test-data/marker"}),
                ),
            ),
            Scenario(
                name="correlated synthetic activity",
                expected_detection=True,
                events=(
                    _event("process.started", 1, pid=30, parent_pid=10, process_name="bash"),
                    _event("file.modified", 2, payload={"path": "/test-data/marker"}),
                    _event(
                        "process.started",
                        3,
                        pid=31,
                        parent_pid=30,
                        process_name="test-client",
                    ),
                    _event(
                        "network.connection",
                        4,
                        pid=31,
                        payload={"protocol": "tcp", "state": "ESTABLISHED"},
                    ),
                ),
            ),
        )

        true_positive = false_positive = true_negative = false_negative = 0
        for scenario in scenarios:
            with self.subTest(scenario=scenario.name):
                detections = DetectionEngine().evaluate(list(scenario.events))
                observed = bool(detections)
                if scenario.expected_detection and observed:
                    true_positive += 1
                elif scenario.expected_detection:
                    false_negative += 1
                elif observed:
                    false_positive += 1
                else:
                    true_negative += 1
                self.assertEqual(observed, scenario.expected_detection)

        precision = true_positive / (true_positive + false_positive)
        recall = true_positive / (true_positive + false_negative)
        self.assertEqual((true_positive, false_positive, true_negative, false_negative), (3, 0, 1, 0))
        self.assertGreaterEqual(precision, 0.85)
        self.assertGreaterEqual(recall, 0.85)


if __name__ == "__main__":
    unittest.main()
