# Phase 22 — Final MVP Scope

## Supported in this repository

```text
Wazuh alert ingestion
Alert normalization
Threat-intel enrichment with offline and external providers
Incident correlation
Offline AI incident summary and MITRE explanation
Prompt-injection protection
RAG knowledge base
Analyst incident/dashboard APIs
Connected authenticated SOC console, Hub explorer and workflow checkpoints
Cyber Intelligence Hub with asset/identity inventory, posture and behavior evidence
Canonical, ECS and osquery connectors
Durable automatic alert pipeline with leases/retries/checkpoints
Learned categorical behavior baseline, technique transitions and access-path hypotheses
Human-approved BLOCK_IP response action
Offline Wazuh Active Response simulation
Opt-in Wazuh Active Response client against a real manager API
Role enforcement and audit events for analyst decisions and response actions
Safe lab attack/demo scaffolding
Testing, hardening, observability, and eval documentation
```

## Not built initially

```text
full SOAR
multi-tenancy
advanced supervised or deep-learning detection
automatic malware sandbox
hundreds of integrations
enterprise SSO and multi-tenant policy isolation
response actions beyond BLOCK_IP
```

## Final demo story

The final demo should show the documented path:

```text
lab telemetry → Wazuh alert → signed backend ingest → normalization → enrichment
→ correlation → AI triage + RAG → dashboard → analyst approval → active response
→ action delivery/simulation logged → real endpoint effect verified → incident contained
```

The default active-response provider is offline and records the action result.
Simulation and Manager acceptance do not establish containment. The SOC model
implementation and operating contract are tracked in
[`soc-model-implementation.md`](soc-model-implementation.md) and
[`soc-deployment.md`](soc-deployment.md).
Setting `WAZUH_ACTIVE_RESPONSE_PROVIDER_MODE=wazuh` swaps in the real manager
API client without changing response-action policy or approval flows; see
[`wazuh-integration.md`](wazuh-integration.md).
