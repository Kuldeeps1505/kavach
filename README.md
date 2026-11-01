# KAVACH: Linux Runtime Telemetry Prototype

KAVACH is a controlled proof of concept for Linux runtime telemetry,
deterministic behavior rules, evidence-linked incidents, a dashboard, and
read-only incident APIs. It is not a production EDR replacement.

## Requirements

- Docker Engine with the Compose plugin, or Linux with Python 3.11 or newer
- One or more dedicated directories authorized for monitoring
- For direct Linux host telemetry, a Linux Docker host and the optional host
  procfs Compose overlay described below

The collector does not record command-line arguments or file contents. Network
attribution is marked unavailable or ambiguous unless procfs identifies one
owning process. Only configured directories are monitored. No response
actions are implemented.

## Start with Docker Compose

Create `test-data` if needed and place only test files there. Build and start
the collector, SQLite store, read-only API, and dashboard:

```sh
docker compose up --build -d
docker compose ps
```

The service stores its database in the `kavach-data` named volume and monitors
`test-data` read-only. The dashboard and API are published only on localhost at
`http://127.0.0.1:8000`. Open that URL for the dashboard; its incident table
links to severity, rule, evidence timeline, and available process relationships.
Check the JSON endpoints directly:

```sh
curl http://127.0.0.1:8000/health
curl "http://127.0.0.1:8000/events?limit=20"
curl "http://127.0.0.1:8000/incidents?limit=20"
```

On Docker Desktop for Windows or macOS, the default configuration sees the
container's process/network namespace, not the desktop host's. This is a
platform boundary, not host endpoint monitoring.

On an authorized Linux Docker host, opt into host procfs visibility with:

```sh
docker compose -f compose.yaml -f compose.linux-host.yaml up --build -d
```

This mounts host `/proc` read-only and lets the collector inspect the host PID
namespace. Host permissions and procfs restrictions can still limit process
details and network attribution. Use it only on a system you are authorized to
monitor. The container runs unprivileged, drops all Linux capabilities, and is
not granted privileged mode.

Stop the service with:

```sh
docker compose down
```

The named database volume is retained by default. Remove it only when you
intend to discard stored events and incidents:

```sh
docker compose down --volumes
```

## Read-only API

- `GET /health` — service health
- `GET /events?limit=100` — recent normalized events
- `GET /incidents?limit=100` — recent detections
- `GET /incidents/{incident_id}` — incident details and referenced evidence
- `GET /` — dashboard
- `GET /dashboard.css` and `GET /dashboard.js` — dashboard assets

Limits must be between 1 and 1000. The API has no write or response-action
routes and is bound to localhost by the default Compose port mapping.

## Direct Linux run

```sh
PYTHONPATH=src python3 -m kavach \
  --watch-dir ./test-data \
  --database ./data/kavach.sqlite3 \
  --api-host 127.0.0.1 \
  --api-port 8000
```

The process and network collectors use Linux procfs. They establish a baseline
on startup and report changes observed afterwards. File changes are polled at
one-second intervals by default.

### WSL Ubuntu setup from a Windows checkout

The dashboard assets must be copied alongside `src` into the project root.
If only `src` and `test-data` were copied, the JSON API can run while `GET /`
returns an error because `web/index.html` is missing. From WSL, copy the
dashboard directory from the Windows checkout:

```sh
cp -a "/mnt/c/Users/KULDEEP SHINDE/OneDrive/Documents/Desktop/KAVACH/web" \
  ~/kavach/
test -f ~/kavach/web/index.html
```

Restart the collector if needed and open `http://localhost:8001` in the
Windows browser when using port 8001. The dashboard reads its static assets
from `web/` at the project root; keep that directory next to `src/`.

## Detection behavior

- `KAV-PROC-001`: a process with a shell name started. Low severity; the parent
  executable and command line are not collected, so this alone is not evidence
  of suspicious intent.
- `KAV-FILE-001`: a create/modify/delete event occurred under a configured
  directory. Low severity; file contents are not collected.
- `KAV-CORR-001`: a shell-named process, a monitored file change, and an
  established TCP connection attributed to that process or a recorded
  descendant occurred in sequence within 30 seconds. Medium severity and low
  confidence. The file event has no process attribution; temporal co-occurrence
  does not prove a causal relationship or compromise.

Every incident retains IDs for its supporting events and states its
correlation basis and confidence.

## Tests and evaluation

Run the standard-library unit suite from the project directory:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The tests cover Phase 1 event collection and storage, Phase 2 rules,
correlation and incident APIs, and dashboard assets. Controlled scenario
fixtures and their limits are documented in
[`docs/phase3-scenarios.md`](docs/phase3-scenarios.md); the observed evaluation
results are in [`docs/phase3-evaluation.md`](docs/phase3-evaluation.md).
Fixture metrics do not generalize to operational detection quality. Live
telemetry and performance still require validation on the selected Linux
environment.
