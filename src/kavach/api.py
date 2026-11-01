from __future__ import annotations

import json
import logging
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Type
from urllib.parse import parse_qs, unquote, urlsplit

from .storage import SQLiteEventStore

_LOGGER = logging.getLogger(__name__)
_MAX_LIMIT = 1000
_WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
_STATIC_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
    "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
}


def create_api_server(
    store: SQLiteEventStore, host: str, port: int
) -> ThreadingHTTPServer:
    class RequestHandler(BaseHTTPRequestHandler):
        server_version = "KAVACH"

        def do_GET(self) -> None:
            request = urlsplit(self.path)
            route = request.path.rstrip("/") or "/"
            try:
                if route in _STATIC_ASSETS:
                    self._respond_asset(route)
                elif route == "/health":
                    self._respond(200, {"status": "ok"})
                elif route == "/events":
                    limit = self._limit(parse_qs(request.query))
                    self._respond(
                        200,
                        {"events": [event.to_record() for event in store.list_events(limit)]},
                    )
                elif route == "/incidents":
                    limit = self._limit(parse_qs(request.query))
                    self._respond(
                        200,
                        {
                            "incidents": [
                                incident.to_record()
                                for incident in store.list_incidents(limit)
                            ]
                        },
                    )
                elif route.startswith("/incidents/"):
                    incident_id = unquote(route.removeprefix("/incidents/"))
                    if not incident_id or "/" in incident_id:
                        self._respond(400, {"error": "invalid incident ID"})
                        return
                    incident = store.get_incident(incident_id)
                    if incident is None:
                        self._respond(404, {"error": "incident not found"})
                        return
                    self._respond(
                        200,
                        {
                            "incident": incident.to_record(),
                            "events": [
                                event.to_record()
                                for event in store.get_events(incident.event_ids)
                            ],
                        },
                    )
                else:
                    self._respond(404, {"error": "not found"})
            except ValueError as exc:
                self._respond(400, {"error": str(exc)})
            except sqlite3.Error:
                _LOGGER.exception("API query failed")
                self._respond(500, {"error": "storage query failed"})
            except OSError:
                _LOGGER.exception("Static dashboard asset could not be served")
                self._respond(500, {"error": "dashboard asset unavailable"})

        @staticmethod
        def _limit(query: dict[str, list[str]]) -> int:
            values = query.get("limit", ["100"])
            if len(values) != 1:
                raise ValueError("limit must be specified once")
            try:
                limit = int(values[0])
            except ValueError as exc:
                raise ValueError("limit must be an integer") from exc
            if not 1 <= limit <= _MAX_LIMIT:
                raise ValueError(f"limit must be between 1 and {_MAX_LIMIT}")
            return limit

        def _respond(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        def _respond_asset(self, route: str) -> None:
            asset_name, content_type = _STATIC_ASSETS[route]
            body = (_WEB_ROOT / asset_name).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("Cache-Control", "no-store")

        def log_message(self, format_string: str, *args: object) -> None:
            _LOGGER.info("%s - %s", self.address_string(), format_string % args)

    handler: Type[RequestHandler] = RequestHandler
    return ThreadingHTTPServer((host, port), handler)
