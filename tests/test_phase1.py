from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path

from kavach.collectors import FileCollector, NetworkCollector, ProcessCollector
from kavach.schema import Event
from kavach.storage import SQLiteEventStore


class EventSchemaTests(unittest.TestCase):
    def test_event_requires_timezone_aware_timestamp(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone"):
            Event(event_type="test", source="test", timestamp="2026-10-31T12:00:00")

    def test_event_round_trip_record_contains_no_command_line_field(self) -> None:
        event = Event(
            event_type="process.started",
            source="procfs",
            pid=42,
            payload={"process_name": "demo"},
        )
        record = event.to_record()
        self.assertEqual(record["pid"], 42)
        self.assertNotIn("command_line", record)


class SQLiteEventStoreTests(unittest.TestCase):
    def test_events_persist_and_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "nested" / "events.sqlite3"
            expected = Event(
                event_type="file.created",
                source="filesystem-poll",
                payload={"path": "/tmp/test.txt", "sha256": "abc"},
            )
            with SQLiteEventStore(database) as store:
                store.append(expected)
                actual = store.list_events()[0]
            self.assertEqual(actual, expected)

    def test_limit_must_be_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            with SQLiteEventStore(Path(temporary_directory) / "events.sqlite3") as store:
                with self.assertRaisesRegex(ValueError, "at least 1"):
                    store.list_events(0)


class FileCollectorTests(unittest.TestCase):
    def test_reports_create_modify_and_delete_with_hash_without_file_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "watched"
            root.mkdir()
            collector = FileCollector([root])
            self.assertEqual(collector.poll(), [])

            monitored_file = root / "sample.conf"
            monitored_file.write_text("safe test data", encoding="utf-8")
            created = collector.poll()
            self.assertEqual([event.event_type for event in created], ["file.created"])
            self.assertEqual(created[0].payload["path"], str(monitored_file.resolve()))
            self.assertEqual(len(created[0].payload["sha256"]), 64)
            self.assertNotIn("contents", created[0].payload)

            monitored_file.write_text("updated safe test data", encoding="utf-8")
            modified = collector.poll()
            self.assertEqual([event.event_type for event in modified], ["file.modified"])

            monitored_file.unlink()
            deleted = collector.poll()
            self.assertEqual([event.event_type for event in deleted], ["file.deleted"])
            self.assertEqual(len(deleted[0].payload["sha256"]), 64)

    def test_rejects_filesystem_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "filesystem root"):
            FileCollector([Path.cwd().anchor])


class ProcessCollectorTests(unittest.TestCase):
    def test_detects_new_and_stopped_processes_from_procfs_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            proc_root = Path(temporary_directory)
            self._write_process(proc_root, 101, 1, "first", "1000")
            collector = ProcessCollector(proc_root)

            self.assertEqual(collector.poll(), [])
            self._write_process(proc_root, 202, 101, "second", "2000")
            started = collector.poll()
            self.assertEqual([event.event_type for event in started], ["process.started"])
            self.assertEqual(started[0].pid, 202)
            self.assertEqual(started[0].parent_pid, 101)
            self.assertEqual(started[0].user_id, 2000)
            self.assertEqual(started[0].payload["process_name"], "second")

            (proc_root / "202").rename(proc_root / "gone")
            stopped = collector.poll()
            self.assertEqual([event.event_type for event in stopped], ["process.stopped"])
            self.assertEqual(stopped[0].pid, 202)

    @staticmethod
    def _write_process(root: Path, pid: int, parent_pid: int, name: str, start_ticks: str) -> None:
        process_dir = root / str(pid)
        process_dir.mkdir(exist_ok=True)
        fields = ["S", str(parent_pid)] + ["0"] * 17 + [start_ticks]
        (process_dir / "stat").write_text(
            f"{pid} ({name}) {' '.join(fields)}",
            encoding="utf-8",
        )
        (process_dir / "status").write_text(f"Name:\t{name}\nUid:\t{int(start_ticks)}\t0\t0\t0\n", encoding="utf-8")


class NetworkCollectorTests(unittest.TestCase):
    def test_poll_records_connection_and_marks_unavailable_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            proc_root = Path(temporary_directory)
            network_root = proc_root / "net"
            network_root.mkdir()
            network_table = network_root / "tcp"
            network_table.write_text(
                "sl local_address rem_address st tx_queue rx_queue tr tm retrnsmt uid timeout inode\n"
                "0: 0100007F:1F90 0200007F:0050 01 00000000:00000000 00:00000000 "
                "00000000 1000 0 12345\n",
                encoding="ascii",
            )
            collector = NetworkCollector(proc_root)
            events = collector.poll()

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].event_type, "network.connection")
            self.assertIsNone(events[0].pid)
            self.assertEqual(events[0].payload["local_address"], "127.0.0.1")
            self.assertEqual(events[0].payload["local_port"], 8080)
            self.assertEqual(events[0].payload["remote_address"], "127.0.0.2")
            self.assertEqual(events[0].payload["remote_port"], 80)
            self.assertEqual(events[0].payload["attribution_confidence"], "unavailable")
            self.assertEqual(collector.poll(), [])
            network_table.write_text(
                network_table.read_text(encoding="ascii").replace(
                    " 01 00000000:00000000", " 02 00000000:00000000"
                ),
                encoding="ascii",
            )
            self.assertEqual(
                [event.event_type for event in collector.poll()],
                ["network.connection"],
            )

    def test_decodes_ipv4_and_ipv6_endpoints(self) -> None:
        self.assertEqual(
            NetworkCollector._decode_endpoint("0100007F:1F90", socket.AF_INET),
            ("127.0.0.1", 8080),
        )
        self.assertEqual(
            NetworkCollector._decode_endpoint(
                "00000000000000000000000001000000:0050",
                socket.AF_INET6,
            ),
            ("::1", 80),
        )


if __name__ == "__main__":
    unittest.main()
