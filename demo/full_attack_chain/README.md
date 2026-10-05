# Phase 16 — Automated Demo Scenario

This scenario describes the final MVP story without requiring destructive actions.
It is designed for a controlled SOC lab with Wazuh agents already enrolled.

## Expected sequence

1. Generate lab-only SSH authentication telemetry.
2. Confirm Wazuh receives failed and successful authentication alerts.
3. Forward Wazuh alerts to `POST /api/v1/alerts` with HMAC signing.
4. Normalize alerts through Phase 4 contracts.
5. Enrich IOCs through Phase 5 offline threat intel.
6. Correlate related alerts through `POST /api/v1/correlation/run`.
7. Run AI triage through `POST /api/v1/incidents/{id}/triage`.
8. Retrieve RAG context for MITRE/playbook explanation.
9. Review dashboard and MITRE chain.
10. Create a pending `BLOCK_IP` response action.
11. Analyst approves the action.
12. Execute approved Wazuh Active Response in offline mode or configured Wazuh mode.
13. Store audited simulation/delivery results. In real Wazuh mode, verify endpoint
    block evidence for every requested agent before marking the incident `CONTAINED`.

## Operator checklist

Start the stack with `docker compose up -d --build`; the migration service must
complete before the backend becomes ready.
Provision an analyst account and obtain a bearer session as described in
[`soc-deployment.md`](../../docs/soc-deployment.md). Normal ingest runs the worker
automatically; the API commands below are optional manual operations.

```bash
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/ready
curl -fsS -X POST http://localhost:8000/api/v1/correlation/run \
  -H "Authorization: Bearer $SOC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"lookback_minutes":60,"window_minutes":10,"min_alerts":2}'
curl -fsS -H "Authorization: Bearer $SOC_TOKEN" http://localhost:8000/api/v1/dashboard/summary
```

Only execute active response after analyst approval and only against lab targets.
