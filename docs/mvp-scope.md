# Phase 22 — Final MVP Scope

## Supported in this repository

```text
Wazuh alert ingestion
Alert normalization
Threat-intel enrichment with offline provider
Incident correlation
Offline AI incident summary and MITRE explanation
Prompt-injection protection
RAG knowledge base
Analyst incident/dashboard APIs
Static frontend dashboard shell
Human-approved BLOCK_IP response action
Offline Wazuh Active Response simulation
Audit fields on response actions
Safe lab attack/demo scaffolding
Testing, hardening, observability, and eval documentation
```

## Not built initially

```text
full SOAR
multi-tenancy
complex ML detection
custom anomaly model
automatic malware sandbox
hundreds of integrations
production JWT/RBAC enforcement
real external LLM calls
real Wazuh API active-response client
```

## Final demo story

The final demo should show the documented path:

```text
lab telemetry → Wazuh alert → signed backend ingest → normalization → enrichment
→ correlation → AI triage + RAG → dashboard → analyst approval → active response
→ action logged → incident contained
```

The default active-response provider is offline and records the action result. A
real Wazuh provider can replace `SIEMProvider.execute_response()` without changing
response-action policy or approval flows.
