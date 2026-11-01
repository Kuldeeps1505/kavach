from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .schema import Event

_SHELL_NAMES = {"ash", "bash", "dash", "fish", "ksh", "sh", "zsh"}
_FILE_CHANGE_TYPES = {"file.created", "file.modified", "file.deleted"}


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("event timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class Incident:
    rule_id: str
    title: str
    severity: str
    reason: str
    event_ids: tuple[str, ...]
    created_at: str
    correlation_basis: str
    confidence: str
    incident_id: str = field(default_factory=lambda: str(uuid4()))

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["event_ids"] = list(self.event_ids)
        return record


class DetectionEngine:
    def __init__(self, correlation_window_seconds: float = 30.0) -> None:
        if correlation_window_seconds <= 0:
            raise ValueError("correlation window must be greater than zero")
        self.correlation_window = timedelta(seconds=correlation_window_seconds)
        self._history: dict[str, Event] = {}
        self._emitted: dict[tuple[str, tuple[str, ...]], datetime] = {}

    def evaluate(self, events: list[Event]) -> list[Incident]:
        if not events:
            return []

        for event in events:
            self._history[event.event_id] = event
        latest_time = max(_parse_timestamp(event.timestamp) for event in events)
        cutoff = latest_time - self.correlation_window
        self._history = {
            event_id: event
            for event_id, event in self._history.items()
            if _parse_timestamp(event.timestamp) >= cutoff
        }
        self._emitted = {
            signature: emitted_at
            for signature, emitted_at in self._emitted.items()
            if emitted_at >= cutoff
        }

        incidents: list[Incident] = []
        for event in events:
            if (
                event.event_type == "process.started"
                and self._process_name(event) in _SHELL_NAMES
            ):
                incidents.extend(
                    self._emit(
                        "KAV-PROC-001",
                        "Shell-named process started",
                        "low",
                        "A process with a shell name started. The parent's executable "
                        "and command line are not collected, so this observation alone "
                        "does not establish suspicious intent.",
                        (event,),
                        "process_event",
                        "low",
                    )
                )
            elif event.event_type in _FILE_CHANGE_TYPES:
                incidents.extend(
                    self._emit(
                        "KAV-FILE-001",
                        "Monitored file changed",
                        "low",
                        "A create, modify, or delete event was observed in a configured "
                        "monitoring directory. File contents are not collected.",
                        (event,),
                        "configured_path_event",
                        "observed",
                    )
                )

        incidents.extend(self._correlate(latest_time))
        return sorted(
            incidents,
            key=lambda incident: (incident.created_at, incident.rule_id, incident.event_ids),
        )

    def _correlate(self, latest_time: datetime) -> list[Incident]:
        recent = list(self._history.values())
        processes = [
            event
            for event in recent
            if event.event_type == "process.started"
            and self._process_name(event) in _SHELL_NAMES
        ]
        files = [event for event in recent if event.event_type in _FILE_CHANGE_TYPES]
        networks = [
            event
            for event in recent
            if event.event_type == "network.connection"
            and event.pid is not None
            and event.payload.get("protocol") == "tcp"
            and event.payload.get("state") == "ESTABLISHED"
        ]
        parents = {
            event.pid: event.parent_pid
            for event in recent
            if event.event_type == "process.started"
            and event.pid is not None
            and event.parent_pid is not None
        }
        process_events = {
            event.pid: event
            for event in recent
            if event.event_type == "process.started" and event.pid is not None
        }
        incidents: list[Incident] = []

        for process in processes:
            process_time = _parse_timestamp(process.timestamp)
            for network in networks:
                if network.pid is None:
                    continue
                network_time = _parse_timestamp(network.timestamp)
                if not (process_time <= network_time <= process_time + self.correlation_window):
                    continue
                lineage_events = self._lineage_events(
                    network.pid, process.pid, parents, process_events
                )
                if lineage_events is None:
                    continue
                if any(
                    not process_time <= _parse_timestamp(lineage.timestamp) <= network_time
                    for lineage in lineage_events
                ):
                    continue
                for file_event in files:
                    file_time = _parse_timestamp(file_event.timestamp)
                    if not (process_time <= file_time <= network_time):
                        continue
                    if network_time - process_time > self.correlation_window:
                        continue
                    incidents.extend(
                        self._emit(
                            "KAV-CORR-001",
                            "Multiple runtime signals co-occurred",
                            "medium",
                            "A shell-named process, a monitored file change, and an "
                            "established TCP connection attributed to that process or "
                            "a recorded descendant occurred in sequence within the "
                            "correlation window. The file event has no process "
                            "attribution; temporal co-occurrence is not proof of a "
                            "causal relationship or compromise.",
                            (process, *lineage_events, file_event, network),
                            "process_lineage_for_network_and_temporal_co_occurrence_for_file",
                            "low",
                        )
                    )
        return incidents

    def _emit(
        self,
        rule_id: str,
        title: str,
        severity: str,
        reason: str,
        events: tuple[Event, ...],
        correlation_basis: str,
        confidence: str,
    ) -> list[Incident]:
        ordered_events = tuple(
            sorted(events, key=lambda event: (_parse_timestamp(event.timestamp), event.event_id))
        )
        signature = (rule_id, tuple(event.event_id for event in ordered_events))
        if signature in self._emitted:
            return []
        self._emitted[signature] = max(_parse_timestamp(event.timestamp) for event in ordered_events)
        return [
            Incident(
                rule_id=rule_id,
                title=title,
                severity=severity,
                reason=reason,
                event_ids=signature[1],
                created_at=ordered_events[-1].timestamp,
                correlation_basis=correlation_basis,
                confidence=confidence,
            )
        ]

    @staticmethod
    def _process_name(event: Event) -> str:
        process_name = event.payload.get("process_name")
        if isinstance(process_name, str) and process_name:
            return process_name.rsplit("/", 1)[-1].lower()
        if event.executable:
            return event.executable.rsplit("/", 1)[-1].lower()
        return ""

    @staticmethod
    def _lineage_events(
        candidate_pid: int,
        ancestor_pid: int | None,
        parents: dict[int, int],
        process_events: dict[int, Event],
    ) -> tuple[Event, ...] | None:
        if ancestor_pid is None:
            return None
        current_pid = candidate_pid
        visited: set[int] = set()
        lineage: list[Event] = []
        while current_pid not in visited:
            if current_pid == ancestor_pid:
                return tuple(lineage)
            visited.add(current_pid)
            parent_pid = parents.get(current_pid)
            if parent_pid is None:
                return None
            process_event = process_events.get(current_pid)
            if process_event is not None:
                lineage.append(process_event)
            current_pid = parent_pid
        return None
