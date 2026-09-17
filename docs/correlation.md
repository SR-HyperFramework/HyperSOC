# Correlation engine

Phase 6 turns multiple related alerts into one incident. It is deliberately
rule-based: AI triage starts in a later phase after alerts have already been
normalized, enriched, and correlated.

## Scope

Correlation consumes trusted backend contracts, not raw Wazuh JSON:

- persisted `Alert` rows are converted through `normalize_persisted_alert()` into
  Phase 4 `NormalizedAlert` objects.
- threat-intel influence comes from sanitized Phase 5 `alert_threat_intel` and
  `threat_intel_indicators` rows.
- incident responses reference related alert IDs; they do not embed
  `alerts.raw_event`.

The signed Wazuh ingest endpoint is unchanged and does not run correlation during
`POST /api/v1/alerts`.

## Incident model

Incidents store the Phase 6 roadmap fields:

- `title`, `status`, `severity`, and `confidence`
- `first_seen` / `last_seen`
- `primary_host`, `primary_user`, and `primary_src_ip`
- `mitre_ids`
- `alert_count`
- reserved `ai_summary` and `ai_analysis` fields for later Phase 7 output

Supported statuses are:

```text
NEW
TRIAGED
INVESTIGATING
CONTAINED
RESOLVED
FALSE_POSITIVE
```

`incident_alerts` links each incident to its related alert IDs. Re-running
correlation is idempotent: existing open incidents are updated and duplicate join
rows are not created.

## Rules

The initial window is 10 minutes by default. The baseline grouping rule is:

```text
same host
+
same source IP
+
within the configured time window
→ same incident
```

Additional rule families influence the incident title, severity, and confidence:

- **Brute force chain:** repeated failed authentication followed by successful
  authentication for the same host/source/user context.
- **PowerShell chain:** PowerShell evidence plus network evidence in the same
  host/source/time window.
- **Persistence chain:** PowerShell plus registry or scheduled-task-like evidence.
- **Malware chain:** file/hash or process evidence with suspicious or malicious
  sanitized threat-intel association.

Severity and confidence are deterministic. They are based on Wazuh rule level,
matched pattern, alert count, MITRE IDs, and sanitized threat-intel risk/verdict.

## API

Run correlation over a bounded lookback:

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/correlation/run' \
  -H 'Content-Type: application/json' \
  -d '{"lookback_minutes":60,"window_minutes":10,"min_alerts":2}'
```

List incidents:

```bash
curl -fsS 'http://localhost:8000/api/v1/incidents?status=NEW&limit=50'
```

Read incident detail:

```bash
curl -fsS 'http://localhost:8000/api/v1/incidents/<incident-id>'
```

Example correlation response:

```json
{
  "created_count": 1,
  "updated_count": 0,
  "incidents": [
    {
      "id": "00000000-0000-0000-0000-000000000200",
      "title": "Possible brute-force authentication chain for root on linux-server",
      "status": "NEW",
      "severity": "high",
      "confidence": 77,
      "first_seen": "2026-09-16T12:00:00Z",
      "last_seen": "2026-09-16T12:09:00Z",
      "primary_host": "linux-server",
      "primary_user": "root",
      "primary_src_ip": "10.10.10.50",
      "mitre_ids": ["T1110"],
      "alert_count": 10,
      "ai_summary": null,
      "ai_analysis": null,
      "alert_ids": []
    }
  ]
}
```

## Operational notes

- Default correlation reads existing enrichment only. It does not refresh provider
  lookups unless `refresh_threat_intel=true` is requested.
- The current APIs are lab/local endpoints until later authentication, RBAC, and
  rate limiting phases are implemented.
- Phase 7 AI triage consumes correlated incidents produced by this service; it
  does not change correlation behavior or run from the signed ingest endpoint.
- Phase 8 prompt-injection protection sanitizes AI-bound incident evidence after
  normalization/correlation and before provider analysis.
- Incident AI fields are intentionally empty in Phase 6 and populated only by the
  later triage path.
- Raw log content remains untrusted evidence and must not be passed directly to an
  LLM in later phases.
