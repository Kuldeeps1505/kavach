from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class Event:
    event_type: str
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: str = field(default_factory=lambda: str(uuid4()))
    pid: int | None = None
    parent_pid: int | None = None
    user_id: int | None = None
    executable: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_type.strip():
            raise ValueError("event_type must not be empty")
        if not self.source.strip():
            raise ValueError("source must not be empty")
        if not self.event_id.strip():
            raise ValueError("event_id must not be empty")
        try:
            parsed_timestamp = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO-8601 datetime") from exc
        if parsed_timestamp.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        if self.pid is not None and self.pid < 0:
            raise ValueError("pid must be non-negative")
        if self.parent_pid is not None and self.parent_pid < 0:
            raise ValueError("parent_pid must be non-negative")

    def to_record(self) -> dict[str, Any]:
        return asdict(self)
