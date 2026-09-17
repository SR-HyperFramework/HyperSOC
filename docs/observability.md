# Phase 17 — Observability

The backend already emits JSON-formatted application logs through
`app.core.logging.configure_logging()`. Phase 17 defines the fields and metrics
that future middleware/exporters should preserve.

## Required log fields

```text
time
level
logger
message
request_id
incident_id
alert_id
service
latency_ms
error
```

Current implementation guarantees the base JSON fields. Service-specific code
should add IDs and latency as structured message fields or logger extras without
logging secrets.

## Metrics contract

Future Prometheus/Grafana integration should expose:

```text
alerts_received_total
incidents_created_total
llm_requests_total
llm_failures_total
llm_latency_seconds
threat_intel_requests_total
response_actions_total
response_action_failures_total
```

## Alerting notes

- Alert on repeated ingest signature failures.
- Alert on AI triage validation failures.
- Alert on response-action execution failures.
- Track p95 latency for ingest, triage, correlation, and active response.
