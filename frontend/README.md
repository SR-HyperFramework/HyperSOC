# AI SOC Frontend Dashboard (Phase 13)

This directory contains a lightweight static dashboard shell for the MVP. It is
intentionally dependency-free so the lab can inspect the analyst workflow without
requiring a Nuxt/Next toolchain yet.

## Pages represented

The MVP dashboard layout maps directly to the roadmap pages:

- `/dashboard` — summary cards, alert/incident timeline, MITRE overview.
- `/incidents` — queue of open incidents.
- `/incidents/:id` — incident summary, attack chain, evidence, AI analysis, and
  response-action approval area.
- `/alerts` — alert list backed by `GET /api/v1/alerts`.
- `/mitre` — highlighted technique chain.
- `/actions` — pending/approved/rejected response actions.
- `/settings` — local lab configuration checklist.

## Backend endpoints used

```text
GET  /api/v1/dashboard/summary
GET  /api/v1/dashboard/mitre
GET  /api/v1/dashboard/timeline
GET  /api/v1/incidents
GET  /api/v1/incidents/{id}
GET  /api/v1/incidents/{id}/analysis
POST /api/v1/incidents/{id}/actions
POST /api/v1/actions/{id}/approve
POST /api/v1/actions/{id}/execute
```

## Next frontend step

When a JS framework is added, keep this static shell as the visual contract and
replace fixture data with calls to the endpoints above.
