# AI SOC Lab

AI SOC Lab is an offline-first security operations center (SOC) MVP. It ingests
signed Wazuh alerts, stores them in PostgreSQL, normalizes and enriches evidence,
correlates incidents, performs schema-validated AI triage, and supports
human-approved containment simulations.

The implementation roadmap is available in
[`../AI SOC Lab Implementation Plan.md`](../AI%20SOC%20Lab%20Implementation%20Plan.md).

## MVP capabilities

```text
Wazuh signed alert ingestion
→ canonical alert normalization
→ offline threat-intelligence enrichment
→ rule-based incident correlation
→ offline AI triage with prompt-injection controls and local RAG context
→ analyst/dashboard APIs and static dashboard shell
→ human-approved BLOCK_IP action
→ offline Wazuh Active Response simulation
```

The default providers are deterministic and offline. Local testing and demos do
not require API keys, internet access, Qdrant, a real LLM endpoint, or a real
Wazuh API client.

## Quick start

### Prerequisites

- Docker Engine with Docker Compose v2
- A random `APP_SECRET_KEY`; do not use the placeholder value or commit a real
  secret

### Start the local stack

Create local configuration from the template, replace `APP_SECRET_KEY` with a
random value, then build and start the services:

```bash
cp .env.example .env
# Edit .env and replace APP_SECRET_KEY with a long random secret.
docker compose up -d --build
docker compose exec backend alembic upgrade head
```

Verify health and database readiness:

```bash
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/ready
```

Compose starts the backend, PostgreSQL, and a reserved Redis service. It does
**not** replace, start, or reconfigure an existing Wazuh Manager, Indexer, or
Dashboard. PostgreSQL and Redis remain on the private Compose network; the
backend is the only service that publishes port `8000`.

## Run tests

Run the backend test suite in Docker:

```bash
ENV_FILE=.env.example docker compose run --rm --no-deps backend sh -lc \
  'pip install --quiet pytest httpx && python -m pytest tests/ -v'
```

The suite covers normalization, IOC extraction and enrichment, correlation, AI
triage schema validation, prompt sanitization, RAG retrieval, analyst and
dashboard APIs, response policy validation, offline active response, signed
ingestion, and replay-safe deduplication.

See [`docs/testing.md`](docs/testing.md) for the security test checklist and
additional verification guidance.

## Connect an existing Wazuh Manager

Read the full topology, setup, and troubleshooting guide in
[`docs/wazuh-integration.md`](docs/wazuh-integration.md). In summary:

1. Install `integrations/wazuh/custom-ai-soc.py` on the Wazuh Manager as
   `/var/ossec/integrations/custom-ai-soc.py`, owned by `root:wazuh` with mode
   `750`.
2. Configure the same random secret as the backend's `APP_SECRET_KEY` and the
   Wazuh integration's `<api_key>`. Never commit the real secret.
3. Use an endpoint that is routable **from the Manager**. Do not use `backend`
   or `localhost` unless the backend runs on the same host as the Manager:

   ```xml
   <integration>
     <name>custom-ai-soc</name>
     <hook_url>https://SOC_BACKEND_HOST/api/v1/alerts</hook_url>
     <api_key>SHARED_HMAC_SECRET</api_key>
     <alert_format>json</alert_format>
   </integration>
   ```

4. Restart `wazuh-manager`, monitor `/var/ossec/logs/integrations.log`, create
   safe lab telemetry, and check `GET /api/v1/alerts`. A new alert returns
   `201`; a replay with the same fingerprint returns `200`.

`POST /api/v1/alerts` requires `X-SOC-Timestamp` and `X-SOC-Signature` HMAC
headers. The full event remains stored as `raw` for provenance, while downstream
services use bounded normalized evidence rather than parsing raw Wazuh JSON.

## Core workflow

### Alert normalization

The Wazuh adapter sends a signed transport envelope containing:

```text
source, timestamp, agent, rule, event, raw
```

`app.services.normalization.normalize_wazuh_alert()` converts native Wazuh JSON
or the envelope into the provider-neutral `NormalizedAlert` contract:

```text
id, timestamp, host, identity, network, process, file, detection, raw_ref
```

The normalizer supports Windows authentication, Sysmon, PowerShell, Linux SSH,
auditd, file-integrity monitoring, and nginx evidence families. Missing or
malformed optional fields are omitted rather than inferred. Native event content
remains untrusted; `raw_ref` is provenance metadata only.

### Threat-intelligence enrichment

Phase 5 enriches bounded IOC values extracted from normalized evidence. Supported
indicator types are `ip`, `domain`, `hash`, and `url`. Results include sanitized
provider metadata, a risk score, verdict, cache state, and expiration metadata.

The default deterministic provider works offline. Cache durations are six hours
for IPs and URLs, 12 hours for domains, and 24 hours for hashes.

```bash
curl -fsS 'http://localhost:8000/api/v1/threat-intel/lookup?type=ip&indicator=198.51.100.42'
curl -fsS -X POST 'http://localhost:8000/api/v1/alerts/<alert-id>/threat-intel'
curl -fsS 'http://localhost:8000/api/v1/alerts/<alert-id>/threat-intel'
```

See [`docs/threat-intelligence.md`](docs/threat-intelligence.md) for the full
contract and provider behavior.

### Incident correlation

The rule-based correlation engine creates or updates incidents from related
persisted alerts. It uses normalized evidence and sanitized enrichment summaries;
it does not parse raw Wazuh JSON directly and is not invoked by the signed ingest
endpoint.

The initial deterministic rules correlate alerts that share a host and source IP
within the default 10-minute window. Additional logic scores brute-force,
PowerShell, persistence, and malware/hash chains.

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/correlation/run' \
  -H 'Content-Type: application/json' \
  -d '{"lookback_minutes":60,"window_minutes":10,"min_alerts":2}'
curl -fsS 'http://localhost:8000/api/v1/incidents?status=NEW'
curl -fsS 'http://localhost:8000/api/v1/incidents/<incident-id>'
```

See [`docs/correlation.md`](docs/correlation.md) for rule details and
idempotency behavior.

### Offline AI triage and prompt-injection protection

AI triage builds a bounded context from the incident, normalized alert evidence,
and sanitized enrichment summaries. It does **not** send raw event JSON, signed
ingest bodies, or raw provider payloads to the AI provider.

The default provider is deterministic and offline. Successful runs store a short
validated summary in `incidents.ai_summary` and schema-validated JSON in
`incidents.ai_analysis`.

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/incidents/<incident-id>/triage' \
  -H 'Content-Type: application/json' \
  -d '{"force":true}'
curl -fsS 'http://localhost:8000/api/v1/incidents/<incident-id>/analysis'
```

All untrusted event text passes through the sanitizer and is serialized inside
`<UNTRUSTED_EVENT_DATA>` boundaries for AI providers. The sanitizer removes
control and binary-like data, redacts secret-like values, truncates long fields,
and limits context size, JSON depth, and list lengths.

AI output is advisory only. It must pass strict Pydantic schema validation and
cannot automatically execute actions or change an incident lifecycle state.

See:

- [`docs/ai-triage.md`](docs/ai-triage.md)
- [`docs/prompt-injection-protection.md`](docs/prompt-injection-protection.md)
- [`docs/llm-cost-token-control.md`](docs/llm-cost-token-control.md)

### Offline RAG knowledge base

The local knowledge base provides MITRE ATT&CK, Wazuh, Sigma, SOC playbook, and
Windows/Linux reference material. Markdown documents are chunked
deterministically and searched through a replaceable `VectorStore` interface.
Retrieved chunks add bounded MITRE and playbook context to AI triage and remain
subject to sanitization and output validation.

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/knowledge/index'
curl -fsS 'http://localhost:8000/api/v1/knowledge/search?mitre_ids=T1110&alert_types=ssh&top_k=5'
```

The default mode requires no embeddings service, Qdrant, network connection, or
API key. See [`docs/knowledge-base.md`](docs/knowledge-base.md) for source,
metadata, chunking, and retrieval details.

## Analyst and response APIs

### Dashboard and incident analysis

```text
GET  /api/v1/dashboard/summary
GET  /api/v1/dashboard/mitre
GET  /api/v1/dashboard/timeline
GET  /api/v1/incidents
GET  /api/v1/incidents/{incident_id}
POST /api/v1/incidents/{incident_id}/triage
POST /api/v1/incidents/{incident_id}/reanalyze
GET  /api/v1/incidents/{incident_id}/analysis
```

A static dashboard shell and endpoint mapping are available in `frontend/`.
The MITRE visualization contract is documented in
[`docs/mitre-visualization.md`](docs/mitre-visualization.md).

### Human-in-the-loop response actions

```text
POST /api/v1/incidents/{incident_id}/actions
GET  /api/v1/incidents/{incident_id}/actions
POST /api/v1/actions/{action_id}/approve
POST /api/v1/actions/{action_id}/reject
POST /api/v1/actions/{action_id}/execute
```

The MVP supports only `BLOCK_IP` actions. An action is created as `PENDING` and
requires explicit analyst approval before it can be executed. Policy validation
runs at request and approval time, and execution accepts only `APPROVED` actions.

The default provider is an **offline Wazuh Active Response simulation**. It
records a structured result, changes the action to `SUCCESS`, and marks the
incident `CONTAINED`; it does not contact a real Wazuh Manager or alter a
firewall. Replace the `SIEMProvider` adapter only when a reviewed, real Wazuh API
integration is ready.

The policy rejects unsupported action types, malformed IP addresses, localhost,
unspecified, link-local, multicast, allowlisted/denylisted targets, and private
management subnets by default.

## Security boundaries

- Never store or log real API keys, Wazuh credentials, or application secrets.
- Treat external alerts, knowledge documents, and threat-intelligence responses
  as untrusted input.
- Keep raw Wazuh events outside AI triage context.
- Require strict schema validation for all AI output.
- Never permit LLM-generated shell, Bash, PowerShell, or arbitrary executable
  response actions.
- Require human approval and policy validation for every containment action.
- Keep the scripts under `attacks/` in isolated laboratory environments only.

See [`docs/security-hardening.md`](docs/security-hardening.md) for production
hardening requirements, including JWT authentication, RBAC, rate limiting,
secret management, audit logging, restrictive CORS, and request-size limits.

## Lab automation and demo

`attacks/` contains **LAB ONLY** benign telemetry generators and documentation;
it does not contain credential attacks, destructive payloads, malware, or
evasion functionality. The end-to-end demo checklist is in
[`demo/full_attack_chain/README.md`](demo/full_attack_chain/README.md).

Additional operational documentation:

- [`docs/observability.md`](docs/observability.md)
- [`docs/ai-evaluation.md`](docs/ai-evaluation.md)
- [`docs/testing.md`](docs/testing.md)
- [`docs/mvp-scope.md`](docs/mvp-scope.md)

## MVP scope

Implemented:

```text
Signed Wazuh ingest, normalization, offline enrichment, correlation,
offline AI triage, prompt-injection protection, local RAG, analyst APIs,
dashboard shell, human-approved BLOCK_IP actions, offline active-response
simulation, safe lab/demo scaffolding, and supporting documentation.
```

Deliberately deferred:

```text
Full SOAR, multi-tenancy, complex ML detection, production JWT/RBAC
enforcement, real external LLM calls, a real Wazuh active-response client,
and a large integration catalog.
```

See [`docs/mvp-scope.md`](docs/mvp-scope.md) for the detailed boundary and demo
story.

## References

- [Wazuh external API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [`docs/wazuh-integration.md`](docs/wazuh-integration.md)
