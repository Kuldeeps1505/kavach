from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import socket
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path

from .schema import Event

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    parent_pid: int
    user_id: int | None
    executable: str | None
    name: str
    start_time_ticks: str


class ProcessCollector:
    def __init__(self, proc_root: str | Path = "/proc") -> None:
        self.proc_root = Path(proc_root)
        self._previous: dict[int, ProcessInfo] | None = None

    def poll(self) -> list[Event]:
        current = self._read_processes()
        if self._previous is None:
            self._previous = current
            return []

        events: list[Event] = []
        for pid, process in current.items():
            previous = self._previous.get(pid)
            if previous is None or previous.start_time_ticks != process.start_time_ticks:
                if previous is not None:
                    events.append(self._event("process.stopped", previous))
                events.append(self._event("process.started", process))

        for pid, process in self._previous.items():
            if pid not in current:
                events.append(self._event("process.stopped", process))

        self._previous = current
        return events

    def _read_processes(self) -> dict[int, ProcessInfo]:
        processes: dict[int, ProcessInfo] = {}
        try:
            entries = list(self.proc_root.iterdir())
        except OSError as exc:
            raise OSError(f"cannot read process source {self.proc_root}: {exc}") from exc

        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                info = self._read_process(entry)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError as exc:
                _LOGGER.warning("Cannot inspect process metadata under %s: %s", entry, exc)
                continue
            processes[info.pid] = info
        return processes

    @staticmethod
    def _read_process(process_dir: Path) -> ProcessInfo:
        stat = (process_dir / "stat").read_text(encoding="utf-8")
        closing_parenthesis = stat.rfind(")")
        if closing_parenthesis < 0:
            raise ValueError(f"invalid process stat record for PID {process_dir.name}")
        name = stat[stat.find("(") + 1 : closing_parenthesis]
        fields = stat[closing_parenthesis + 1 :].split()
        if len(fields) <= 19:
            raise ValueError(f"incomplete process stat record for PID {process_dir.name}")
        parent_pid = int(fields[1])
        start_time_ticks = fields[19]

        user_id: int | None = None
        try:
            for line in (process_dir / "status").read_text(encoding="utf-8").splitlines():
                if line.startswith("Uid:"):
                    user_id = int(line.split()[1])
                    break
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass

        executable: str | None = None
        try:
            executable = str((process_dir / "exe").readlink())
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            pass

        return ProcessInfo(
            pid=int(process_dir.name),
            parent_pid=parent_pid,
            user_id=user_id,
            executable=executable,
            name=name,
            start_time_ticks=start_time_ticks,
        )

    @staticmethod
    def _event(event_type: str, process: ProcessInfo) -> Event:
        return Event(
            event_type=event_type,
            source="procfs",
            pid=process.pid,
            parent_pid=process.parent_pid,
            user_id=process.user_id,
            executable=process.executable,
            payload={"process_name": process.name},
        )


@dataclass(frozen=True, slots=True)
class FileInfo:
    modified_ns: int
    size: int
    inode: int


class FileCollector:
    def __init__(self, directories: list[str | Path]) -> None:
        if not directories:
            raise ValueError("at least one monitored directory is required")
        roots: list[Path] = []
        for directory in directories:
            root = Path(directory).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise ValueError(f"monitored path is not a directory: {root}")
            if root == Path(root.anchor):
                raise ValueError(f"refusing to monitor filesystem root: {root}")
            if root not in roots:
                roots.append(root)
        self.roots = tuple(roots)
        self._previous: dict[Path, FileInfo] | None = None
        self._hashes: dict[Path, str] = {}

    def poll(self) -> list[Event]:
        current = self._scan()
        if self._previous is None:
            self._previous = current
            return []

        events: list[Event] = []
        for path, info in current.items():
            previous = self._previous.get(path)
            if previous is None:
                events.append(self._change_event("file.created", path, info))
            elif info != previous:
                events.append(self._change_event("file.modified", path, info))

        for path in self._previous.keys() - current.keys():
            events.append(
                Event(
                    event_type="file.deleted",
                    source="filesystem-poll",
                    payload={
                        "path": str(path),
                        "size": self._previous[path].size,
                        "sha256": self._hashes.pop(path, None),
                    },
                )
            )

        self._previous = current
        return events

    def _scan(self) -> dict[Path, FileInfo]:
        files: dict[Path, FileInfo] = {}
        for root in self.roots:
            for directory, child_directories, filenames in os.walk(
                root, followlinks=False, onerror=self._log_scan_error
            ):
                child_directories[:] = [
                    name
                    for name in child_directories
                    if not (Path(directory) / name).is_symlink()
                ]
                for filename in filenames:
                    path = Path(directory) / filename
                    try:
                        if path.is_symlink():
                            continue
                        stat = path.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    except PermissionError as exc:
                        _LOGGER.warning("Cannot inspect monitored file metadata %s: %s", path, exc)
                        continue
                    if not stat_module.S_ISREG(stat.st_mode):
                        continue
                    files[path] = FileInfo(
                        modified_ns=stat.st_mtime_ns,
                        size=stat.st_size,
                        inode=stat.st_ino,
                    )
        return files

    @staticmethod
    def _log_scan_error(error: OSError) -> None:
        _LOGGER.warning("Cannot scan monitored path %s: %s", error.filename, error)

    def _change_event(self, event_type: str, path: Path, info: FileInfo) -> Event:
        digest = self._sha256(path)
        if digest is not None:
            self._hashes[path] = digest
        else:
            self._hashes.pop(path, None)
        return Event(
            event_type=event_type,
            source="filesystem-poll",
            payload={
                "path": str(path),
                "size": info.size,
                "modified_ns": info.modified_ns,
                "sha256": digest,
            },
        )

    @staticmethod
    def _sha256(path: Path) -> str | None:
        digest = hashlib.sha256()
        try:
            with path.open("rb") as file:
                for block in iter(lambda: file.read(1024 * 1024), b""):
                    digest.update(block)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            _LOGGER.warning("Cannot calculate SHA-256 for monitored file %s: %s", path, exc)
            return None
        return digest.hexdigest()


class NetworkCollector:
    _TCP_STATES = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }

    def __init__(self, proc_root: str | Path = "/proc") -> None:
        self.proc_root = Path(proc_root)
        self._seen: set[tuple[str, str, str, int, str]] = set()

    def poll(self) -> list[Event]:
        if not (self.proc_root / "net").is_dir():
            raise OSError(f"Linux procfs network tables unavailable at {self.proc_root / 'net'}")
        owners = self._socket_owners()
        events: list[Event] = []
        current_connections: set[tuple[str, str, str, int, str]] = set()
        for protocol, filename, family in (
            ("tcp", "tcp", socket.AF_INET),
            ("tcp", "tcp6", socket.AF_INET6),
            ("udp", "udp", socket.AF_INET),
            ("udp", "udp6", socket.AF_INET6),
        ):
            table = self.proc_root / "net" / filename
            if not table.exists():
                continue
            for row in self._read_table(table, family, protocol):
                inode = row.pop("inode")
                state = str(row["state"])
                key = (protocol, str(row["local_address"]), str(row["remote_address"]), inode, state)
                current_connections.add(key)
                if key in self._seen:
                    continue
                owner_pids = owners.get(inode, [])
                unique_owners = sorted(set(owner_pids))
                pid = unique_owners[0] if len(unique_owners) == 1 else None
                row["owner_pids"] = unique_owners
                row["attribution_confidence"] = (
                    "observed" if len(unique_owners) == 1 else
                    "ambiguous" if unique_owners else
                    "unavailable"
                )
                events.append(
                    Event(
                        event_type="network.connection",
                        source="procfs",
                        pid=pid,
                        payload={"protocol": protocol, **row},
                    )
                )
        self._seen = current_connections
        return events

    def _socket_owners(self) -> dict[int, list[int]]:
        owners: dict[int, list[int]] = {}
        try:
            process_directories = list(self.proc_root.iterdir())
        except OSError as exc:
            raise OSError(f"cannot inspect process descriptors under {self.proc_root}: {exc}") from exc

        for process_dir in process_directories:
            if not process_dir.name.isdecimal():
                continue
            fd_directory = process_dir / "fd"
            try:
                descriptors = list(fd_directory.iterdir())
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            for descriptor in descriptors:
                try:
                    target = descriptor.readlink().name
                except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    try:
                        inode = int(target[8:-1])
                    except ValueError:
                        continue
                    owners.setdefault(inode, []).append(int(process_dir.name))
        return owners

    @classmethod
    def _read_table(
        cls, table: Path, family: socket.AddressFamily, protocol: str
    ) -> list[dict[str, object]]:
        try:
            lines = table.read_text(encoding="ascii").splitlines()[1:]
        except OSError as exc:
            raise OSError(f"cannot read network table {table}: {exc}") from exc
        rows: list[dict[str, object]] = []
        for line in lines:
            fields = line.split()
            if len(fields) <= 9:
                continue
            local_address, local_port = cls._decode_endpoint(fields[1], family)
            remote_address, remote_port = cls._decode_endpoint(fields[2], family)
            state = fields[3].upper()
            rows.append(
                {
                    "local_address": local_address,
                    "local_port": local_port,
                    "remote_address": remote_address,
                    "remote_port": remote_port,
                    "state": cls._TCP_STATES.get(state, state) if protocol == "tcp" else state,
                    "inode": int(fields[9]),
                }
            )
        return rows

    @staticmethod
    def _decode_endpoint(value: str, family: socket.AddressFamily) -> tuple[str, int]:
        address_hex, port_hex = value.split(":")
        packed = bytes.fromhex(address_hex)
        if family == socket.AF_INET:
            packed = packed[::-1]
        else:
            packed = b"".join(packed[index : index + 4][::-1] for index in range(0, 16, 4))
        return str(ipaddress.ip_address(packed)), int(port_hex, 16)
