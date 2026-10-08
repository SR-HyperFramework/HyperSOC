# HyperSOC console

`console.html`, `soc.css` and `soc.js` form a dependency-free, API-connected SOC
console served at `/` and `/investigator`. Provision a viewer/analyst/admin account
using the [deployment guide](../docs/soc-deployment.md). Sessions use HttpOnly
cookies and CSRF headers. The served console contains no live-data fixtures.

The incident queue exposes cited findings, source evidence, alert timelines,
internal context, learned behavior and access-path hypotheses. Citation buttons
open and focus their evidence. Analyst conclusions preserve the machine report.
Response requests, approvals, execution and endpoint verification are separate
controls; offline results explicitly identify simulation.

## Workspace views

The four navigation views use persisted backend data:

- Overview (default): threat posture, KPI strip, 24h activity, open-severity mix,
  priority queue, top MITRE techniques and automation pipeline status.
- Incidents: filterable queue, case evidence, review and response.
- Intelligence hub: asset/identity/process/IP/technique entities and observed relationships.
- Automation: alert stages, checkpoint evidence, attempts and failed-job retry.

Use Refresh data for current counts, queue, entities or workflow state. Inventory
import and model training use the admin API/connector CLI. The original `index.html`
dashboard mockup and `investigator.html` remain as historical files; they are not
the console currently served by FastAPI.

## Backend endpoints used

```text
GET  /api/v1/dashboard/summary
GET  /api/v1/dashboard/timeline
GET  /api/v1/dashboard/mitre
GET  /api/v1/auth/me
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/incidents
GET  /api/v1/incidents/{id}
GET  /api/v1/alerts/{id}
GET  /api/v1/incidents/{id}/investigations
POST /api/v1/incidents/{id}/investigations
POST /api/v1/investigations/{id}/review
GET  /api/v1/hub/incidents/{id}/context
GET  /api/v1/hub/entities
GET  /api/v1/hub/entities/{id}/graph
GET  /api/v1/workflows
POST /api/v1/workflows/{id}/retry
GET  /api/v1/incidents/{id}/actions
POST /api/v1/incidents/{id}/actions
POST /api/v1/actions/{id}/approve
POST /api/v1/actions/{id}/reject
POST /api/v1/actions/{id}/execute
POST /api/v1/actions/{id}/verify
```

## Rendering and accessibility

Untrusted text uses `textContent`, including provider reports and source commands.
The graph shows up to 25 nodes with a reference list; backend truncation is
disclosed independently. Semantic forms, labels, keyboard focus, status notices,
responsive grids and reduced-motion support are provided. See
[`console-design.md`](../docs/console-design.md) for the visual contract.
