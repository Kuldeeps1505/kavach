from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Iterable

from .detection import Incident
from .schema import Event


class SQLiteEventStore:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                pid INTEGER,
                parent_pid INTEGER,
                user_id INTEGER,
                executable TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)"
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                event_ids_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                correlation_basis TEXT NOT NULL,
                confidence TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at)"
        )
        self._connection.commit()

    def append(self, event: Event) -> None:
        self.append_many((event,))

    def append_many(self, events: Iterable[Event]) -> None:
        rows = [
            (
                event.event_id,
                event.timestamp,
                event.event_type,
                event.source,
                event.pid,
                event.parent_pid,
                event.user_id,
                event.executable,
                json.dumps(event.payload, sort_keys=True),
            )
            for event in events
        ]
        if not rows:
            return
        with self._lock:
            with self._connection:
                self._connection.executemany(
                    """
                    INSERT INTO events (
                        event_id, timestamp, event_type, source, pid, parent_pid,
                        user_id, executable, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

    def list_events(self, limit: int = 100) -> list[Event]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT event_id, timestamp, event_type, source, pid, parent_pid,
                       user_id, executable, payload_json
                FROM events
                ORDER BY timestamp DESC, event_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def get_events(self, event_ids: Iterable[str]) -> list[Event]:
        ids = tuple(dict.fromkeys(event_ids))
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT event_id, timestamp, event_type, source, pid, parent_pid,
                       user_id, executable, payload_json
                FROM events
                WHERE event_id IN ({placeholders})
                ORDER BY timestamp, event_id
                """,
                ids,
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def append_incidents(self, incidents: Iterable[Incident]) -> None:
        rows = [
            (
                incident.incident_id,
                incident.rule_id,
                incident.title,
                incident.severity,
                incident.reason,
                json.dumps(incident.event_ids),
                incident.created_at,
                incident.correlation_basis,
                incident.confidence,
            )
            for incident in incidents
        ]
        if not rows:
            return
        with self._lock:
            with self._connection:
                self._connection.executemany(
                    """
                    INSERT INTO incidents (
                        incident_id, rule_id, title, severity, reason, event_ids_json,
                        created_at, correlation_basis, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

    def list_incidents(self, limit: int = 100) -> list[Incident]:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT incident_id, rule_id, title, severity, reason, event_ids_json,
                       created_at, correlation_basis, confidence
                FROM incidents
                ORDER BY created_at DESC, incident_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._incident_from_row(row) for row in rows]

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT incident_id, rule_id, title, severity, reason, event_ids_json,
                       created_at, correlation_basis, confidence
                FROM incidents
                WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
        return self._incident_from_row(row) if row is not None else None

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> Event:
        return Event(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            source=row["source"],
            pid=row["pid"],
            parent_pid=row["parent_pid"],
            user_id=row["user_id"],
            executable=row["executable"],
            payload=json.loads(row["payload_json"]),
        )

    @staticmethod
    def _incident_from_row(row: sqlite3.Row) -> Incident:
        return Incident(
            incident_id=row["incident_id"],
            rule_id=row["rule_id"],
            title=row["title"],
            severity=row["severity"],
            reason=row["reason"],
            event_ids=tuple(json.loads(row["event_ids_json"])),
            created_at=row["created_at"],
            correlation_basis=row["correlation_basis"],
            confidence=row["confidence"],
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> SQLiteEventStore:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
