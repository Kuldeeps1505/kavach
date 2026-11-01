"use strict";

const state = {
  incidents: [],
  selectedIncidentId: null,
  severity: "all",
  refreshing: false,
};

const byId = (id) => document.getElementById(id);

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function severityClass(value) {
  return `severity severity-${["low", "medium"].includes(value) ? value : "low"}`;
}

async function getJson(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`Request failed (${response.status}): ${path}`);
  return response.json();
}

function renderIncidents() {
  const tbody = byId("incident-rows");
  tbody.replaceChildren();
  const visible = state.incidents.filter(
    (incident) => state.severity === "all" || incident.severity === state.severity,
  );
  if (visible.length === 0) {
    const row = makeElement("tr");
    const cell = makeElement(
      "td",
      "empty-state",
      state.incidents.length ? "No incidents match this filter." : "No incidents recorded yet.",
    );
    cell.colSpan = 5;
    row.append(cell);
    tbody.append(row);
    return;
  }

  for (const incident of visible) {
    const row = makeElement("tr", incident.incident_id === state.selectedIncidentId ? "selected" : "");
    row.tabIndex = 0;
    row.setAttribute("aria-label", `${incident.severity} ${incident.title}`);
    const severity = makeElement("td");
    severity.append(makeElement("span", severityClass(incident.severity), incident.severity));
    const title = makeElement("td");
    title.append(makeElement("span", "incident-name", incident.title));
    title.append(makeElement("span", "subtle", incident.incident_id));
    const rule = makeElement("td");
    rule.append(makeElement("span", "rule-code", incident.rule_id));
    const evidence = makeElement("td", "", `${incident.event_ids.length} event(s)`);
    const observed = makeElement("td", "", formatTime(incident.created_at));
    row.append(severity, title, rule, evidence, observed);
    row.addEventListener("click", () => selectIncident(incident.incident_id));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectIncident(incident.incident_id);
      }
    });
    tbody.append(row);
  }
}

function renderEvents(events) {
  const list = byId("event-list");
  list.replaceChildren();
  if (!events.length) {
    list.append(makeElement("div", "empty-state", "No events recorded yet."));
    return;
  }
  for (const event of events) {
    const row = makeElement("div", "event-row");
    row.append(makeElement("span", "event-marker"));
    const content = makeElement("div");
    content.append(makeElement("div", "event-name", event.event_type));
    const description = event.payload.path
      || event.executable
      || (event.pid !== null ? `PID ${event.pid}` : event.payload.local_address
        ? `${event.payload.protocol} ${event.payload.local_address}:${event.payload.local_port}`
        : "Metadata attribution unavailable");
    content.append(makeElement("div", "event-description", String(description)));
    row.append(content, makeElement("div", "event-time", formatTime(event.timestamp)));
    list.append(row);
  }
}

function createMeta(label, value) {
  const cell = makeElement("div");
  cell.append(makeElement("span", "", label), makeElement("strong", "", value || "Unavailable"));
  return cell;
}

function renderProcessLineage(events) {
  const processes = events.filter(
    (event) => event.event_type === "process.started" && event.pid !== null,
  );
  if (!processes.length) return null;

  const byPid = new Map(processes.map((event) => [event.pid, event]));
  const roots = processes.filter((event) => !byPid.has(event.parent_pid));
  const ordered = [];
  const visited = new Set();
  const visit = (event, depth) => {
    if (visited.has(event.pid)) return;
    visited.add(event.pid);
    ordered.push({ event, depth });
    for (const child of processes.filter((candidate) => candidate.parent_pid === event.pid)) {
      visit(child, depth + 1);
    }
  };
  for (const root of roots) visit(root, 0);
  for (const process of processes) visit(process, 0);
  if (!ordered.some(({ event }) => event.parent_pid !== null)) return null;

  const lineage = makeElement("div", "lineage");
  for (const { event, depth } of ordered) {
    if (depth > 0) lineage.append(makeElement("span", "lineage-arrow", "→"));
    const processName = event.payload.process_name || event.executable || "process";
    lineage.append(makeElement("span", "lineage-node", `${processName} · PID ${event.pid}`));
  }
  return lineage;
}

function renderIncidentDetails(incident, events) {
  byId("detail-title").textContent = incident.title;
  byId("detail-rule").textContent = incident.rule_id;
  const body = byId("detail-body");
  body.replaceChildren();
  body.append(makeElement("p", "reason", incident.reason));
  const metadata = makeElement("div", "detail-meta");
  metadata.append(
    createMeta("Severity", incident.severity),
    createMeta("Confidence", incident.confidence),
    createMeta("Correlation basis", incident.correlation_basis),
    createMeta("Incident ID", incident.incident_id),
  );
  body.append(metadata);

  const timeline = makeElement("div", "timeline");
  for (const event of events) {
    const item = makeElement("div", "timeline-item");
    item.append(
      makeElement("div", "timeline-time", formatTime(event.timestamp)),
      makeElement("div", "timeline-title", event.event_type),
      makeElement(
        "div",
        "timeline-note",
        `${event.payload.path || event.payload.process_name || event.executable || "Observed event"} · event ${event.event_id}`,
      ),
    );
    timeline.append(item);
  }
  body.append(makeElement("div", "section-label", "Evidence timeline"));
  body.append(timeline);

  const lineage = renderProcessLineage(events);
  if (lineage) {
    body.append(makeElement("div", "section-label", "Available process relationships"));
    body.append(lineage);
  }
}

async function selectIncident(incidentId) {
  state.selectedIncidentId = incidentId;
  renderIncidents();
  byId("detail-body").replaceChildren(makeElement("div", "empty-state", "Loading evidence…"));
  try {
    const result = await getJson(`/incidents/${encodeURIComponent(incidentId)}`);
    renderIncidentDetails(result.incident, result.events);
  } catch (error) {
    byId("detail-body").replaceChildren(makeElement("div", "empty-state", error.message));
  }
}

async function refreshDashboard() {
  if (state.refreshing) return;
  state.refreshing = true;
  byId("refresh-button").disabled = true;
  try {
    const [health, eventsResult, incidentsResult] = await Promise.all([
      getJson("/health"),
      getJson("/events?limit=100"),
      getJson("/incidents?limit=100"),
    ]);
    const events = eventsResult.events;
    state.incidents = incidentsResult.incidents;
    byId("service-status").className = "status-pill";
    byId("service-status").replaceChildren(
      makeElement("span", "status-dot"),
      document.createTextNode(health.status === "ok" ? "Sensor operational" : "Sensor unavailable"),
    );
    byId("sensor-context").textContent = "Local collector · API online";
    byId("event-count").textContent = String(events.length);
    byId("incident-count").textContent = String(state.incidents.length);
    byId("process-count").textContent = String(
      events.filter((event) => event.event_type.startsWith("process.")).length,
    );
    byId("network-count").textContent = String(
      events.filter((event) => event.event_type === "network.connection").length,
    );
    byId("last-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    renderIncidents();
    renderEvents(events.slice(0, 12));
    if (state.selectedIncidentId && state.incidents.some((item) => item.incident_id === state.selectedIncidentId)) {
      await selectIncident(state.selectedIncidentId);
    } else if (state.selectedIncidentId) {
      state.selectedIncidentId = null;
      byId("detail-title").textContent = "Select an incident";
      byId("detail-rule").textContent = "NO SELECTION";
      byId("detail-body").replaceChildren(
        makeElement("div", "empty-detail"),
      );
      const empty = byId("detail-body").firstElementChild;
      empty.append(makeElement("span", "", "◎"));
      empty.append(makeElement("p", "", "Select an incident above to inspect its evidence, event sequence, and available process relationships."));
    }
  } catch (error) {
    byId("service-status").className = "status-pill status-error";
    byId("service-status").replaceChildren(
      makeElement("span", "status-dot"),
      document.createTextNode("API unavailable"),
    );
    byId("sensor-context").textContent = error.message;
    byId("incident-rows").replaceChildren();
    const row = makeElement("tr");
    const cell = makeElement("td", "empty-state", `Unable to load data: ${error.message}`);
    cell.colSpan = 5;
    row.append(cell);
    byId("incident-rows").append(row);
  } finally {
    state.refreshing = false;
    byId("refresh-button").disabled = false;
  }
}

byId("refresh-button").addEventListener("click", refreshDashboard);
byId("severity-filter").addEventListener("change", (event) => {
  state.severity = event.target.value;
  renderIncidents();
});
refreshDashboard();
window.setInterval(refreshDashboard, 10000);
