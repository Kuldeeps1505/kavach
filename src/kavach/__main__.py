from __future__ import annotations

import argparse
import logging
import os
import signal
import sqlite3
import threading
import time
from collections.abc import Callable

from .api import create_api_server
from .collectors import FileCollector, NetworkCollector, ProcessCollector
from .detection import DetectionEngine
from .schema import Event
from .storage import SQLiteEventStore


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect KAVACH Linux endpoint telemetry.")
    parser.add_argument(
        "--watch-dir",
        action="append",
        required=True,
        help="Authorized directory to monitor; may be provided more than once.",
    )
    parser.add_argument("--database", default="data/kavach.sqlite3")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--proc-root", default="/proc")
    parser.add_argument("--api-host", default="127.0.0.1")
    parser.add_argument("--api-port", type=int, default=8000)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("kavach")
    if not os.path.isdir(args.proc_root) or not os.path.isdir(
        os.path.join(args.proc_root, "net")
    ):
        logger.error("Linux procfs is unavailable at %s.", args.proc_root)
        return 2
    if args.interval <= 0:
        logger.error("--interval must be greater than zero.")
        return 2
    if not 0 <= args.api_port <= 65535:
        logger.error("--api-port must be between 0 and 65535.")
        return 2

    try:
        collectors: list[tuple[str, Callable[[], list[Event]]]] = [
            ("process", ProcessCollector(args.proc_root).poll),
            ("file", FileCollector(args.watch_dir).poll),
            ("network", NetworkCollector(args.proc_root).poll),
        ]
    except (OSError, ValueError) as exc:
        logger.error("Unable to initialize collectors: %s", exc)
        return 2

    api_server = None
    try:
        with SQLiteEventStore(args.database) as store:
            try:
                api_server = create_api_server(store, args.api_host, args.api_port)
            except OSError as exc:
                logger.error("Unable to start read-only API: %s", exc)
                return 1
            stop_event = threading.Event()

            def request_stop(signal_number: int, frame: object) -> None:
                logger.info("Received signal %d; stopping collection.", signal_number)
                stop_event.set()

            signal.signal(signal.SIGINT, request_stop)
            signal.signal(signal.SIGTERM, request_stop)
            try:
                api_thread = threading.Thread(
                    target=api_server.serve_forever,
                    name="kavach-api",
                    daemon=True,
                )
                api_thread.start()
                logger.info("Read-only API listening on %s:%d", *api_server.server_address)
                detection = DetectionEngine()
                logger.info("Collecting telemetry; stop with Ctrl+C or SIGTERM.")
                while not stop_event.is_set():
                    new_events: list[Event] = []
                    for name, poll in collectors:
                        try:
                            events = poll()
                            new_events.extend(events)
                            if events:
                                logger.info("%s collector observed %d event(s)", name, len(events))
                        except OSError as exc:
                            logger.error("%s collector failed: %s", name, exc)
                    store.append_many(new_events)
                    incidents = detection.evaluate(new_events)
                    store.append_incidents(incidents)
                    for incident in incidents:
                        logger.warning(
                            "%s %s [%s]: %s",
                            incident.severity.upper(),
                            incident.rule_id,
                            incident.incident_id,
                            incident.reason,
                        )
                    stop_event.wait(args.interval)
            finally:
                if api_server is not None:
                    api_server.shutdown()
                    api_server.server_close()
                    api_server = None
            logger.info("Collection stopped.")
    except (OSError, sqlite3.Error) as exc:
        logger.error("Collector service failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
