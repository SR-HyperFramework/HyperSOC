# 🛡️ AI SOC Lab

> Turn Wazuh alerts into incident investigations—with bounded AI triage and human-approved response simulations.

## 🌟 Highlights

- **Incident-centric investigations:** correlate related alerts by host, source IP,
  and time window, with scoring for authentication, PowerShell, persistence, and
  malware/hash activity.
- **Structured security evidence:** normalize Wazuh events into a provider-neutral
  model and enrich IP, domain, URL, and hash indicators with an offline provider.
- **Offline-first triage:** run deterministic analysis locally, or opt into
  TypeSafe Jev for typed classification, severity, and false-positive decisions.
- **Local SOC knowledge:** retrieve MITRE ATT&CK notes, Wazuh references, Sigma
  explanations, and internal playbooks from a Markdown knowledge base.
- **AI input safeguards:** sanitize untrusted evidence, bound context size, and
  validate analysis output against strict schemas. Recommendations stay advisory.
- **Approval-gated response:** request, approve, reject, and simulate `BLOCK_IP`
  actions through a persisted workflow—without modifying a real firewall.

## ℹ️ Overview

AI SOC Lab is the offline-first SOC workflow MVP in the **HyperSOC** repository.
It is designed for SOC analysts, security engineers, and lab builders exploring
how to turn individual detections into incident investigations. Wazuh remains the
telemetry and detection platform; this project adds signed alert ingestion,
normalization, enrichment, correlation, triage, and response approval on top.

```text
Wazuh alerts → HMAC-signed ingest → PostgreSQL
             → normalization + enrichment → incident correlation
             → triage + local knowledge → analyst review
             → approved offline containment simulation
```

The backend uses Python, FastAPI, SQLAlchemy, Alembic, and PostgreSQL. Analyst and
dashboard APIs expose incident data; `frontend/` contains a **static dashboard
shell**, not a fully integrated analyst application.

**Know the limits:** threat-intelligence and triage default to deterministic
offline outputs. External threat-intel providers (VirusTotal, AbuseIPDB,
URLhaus) and a real Wazuh active-response client both ship but are opt-in and
disabled by default; optional Jev triage requires an external service and API
key. In the default `offline` active-response mode, containment is simulated: a
successful action records `SUCCESS` and marks the incident `CONTAINED`, but does
not contact Wazuh or block network traffic. Production JWT/RBAC enforcement and
full SOAR functionality are not implemented. Keep this MVP in a trusted lab
environment.

See the [MVP scope](docs/mvp-scope.md) and
[security hardening requirements](docs/security-hardening.md) before deployment.

### ✍️ Authors

Maintained by [h26v](https://github.com/h26v).
Source code and project updates: [HyperSOC](https://github.com/h26v/HyperSOC).

## 🚀 Usage

After installation, connect your existing Manager using the
[Wazuh integration guide](docs/wazuh-integration.md). The integration signs alerts
with a shared secret; new alerts return `201`, and duplicate fingerprints return
`200`. Do not use an unsigned POST to test ingestion.

### Review and correlate alerts

```bash
curl -fsS 'http://localhost:8000/api/v1/alerts?limit=10'
curl -fsS -X POST http://localhost:8000/api/v1/correlation/run
curl -fsS 'http://localhost:8000/api/v1/incidents?status=NEW'
```

Correlation is invoked separately from ingestion. Related alerts must be present
before it can produce an incident.

### Triage an incident

Replace `<incident-id>` with an ID returned by the incidents API:

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/incidents/<incident-id>/triage'
curl -fsS 'http://localhost:8000/api/v1/incidents/<incident-id>/analysis'
```

Triage is offline by default. To opt into TypeSafe Jev, configure
`AI_TRIAGE_PROVIDER_MODE=jev` and `TYPESAFE_API_KEY` in your private `.env`, then
recreate the backend container. Review the
[AI triage configuration and data boundaries](docs/ai-triage.md) before enabling
external processing. Jev supplies typed decisions; the backend renders narrative,
evidence references, and recommendations deterministically from sanitized context.

### Inspect the dashboard data

```bash
curl -fsS http://localhost:8000/api/v1/dashboard/summary
```

Explore the interactive API documentation at <http://localhost:8000/docs>.
Response actions follow `PENDING → APPROVED → EXECUTING → SUCCESS/FAILED`, with
rejection available for pending actions. Only `BLOCK_IP` is enabled, and the
default policy denies private management-subnet targets.

### Go further

| Guide | What it covers |
| --- | --- |
| [Wazuh integration](docs/wazuh-integration.md) | Manager setup, HMAC signing, topology, and troubleshooting |
| [Threat intelligence](docs/threat-intelligence.md) | IOC extraction, offline results, and caching |
| [Correlation](docs/correlation.md) | Incident rules and idempotency behavior |
| [AI triage](docs/ai-triage.md) | Providers, typed output, and configuration |
| [Prompt-injection controls](docs/prompt-injection-protection.md) | Sanitization and untrusted-data boundaries |
| [Knowledge base](docs/knowledge-base.md) | Local indexing, metadata, and retrieval |
| [Frontend](frontend/README.md) | Static dashboard shell and API mapping |
| [MITRE visualization](docs/mitre-visualization.md) | Technique rendering contract |
| [Demo walkthrough](demo/full_attack_chain/README.md) | Lab telemetry through simulated containment |

Scripts in [`attacks/`](attacks/README.md) are **LAB ONLY** benign telemetry
scaffolding. Never run them on production hosts. AI recommendations must not be
turned into arbitrary shell, Bash, or PowerShell execution.

## ⬇️ Installation

### Requirements

- Git, Docker Engine, and Docker Compose v2.
- An available host port `8000` for the backend.
- A long random application secret shared with the Wazuh integration.
- An existing Wazuh Manager to forward real alerts; it is not included in Compose.

Python and database dependencies are installed in containers; a host Python
installation is not required. Initial image builds and dependency downloads need
network access. The default providers operate offline after setup.

### Start the stack

```bash
git clone https://github.com/h26v/HyperSOC.git
cd HyperSOC
cp .env.example .env
```

Edit `.env` and replace the `APP_SECRET_KEY` placeholder with a long random
secret **before starting the backend**. Never commit `.env` or print credentials
in logs.

```bash
docker compose up -d --build
docker compose exec backend alembic upgrade head
```

Verify the application and database connection:

```bash
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/ready
```

Compose starts the backend, PostgreSQL, and a reserved Redis service. It does not
replace or reconfigure an existing Wazuh Manager, Indexer, or Dashboard.
PostgreSQL and Redis have no published host ports; the backend publishes `8000`.
Restrict access to that port because production authentication and authorization
are not implemented.

For Wazuh forwarding, use a backend URL reachable **from the Manager**, not a
Compose service name or `localhost` unless appropriate for your deployment.
Follow the [integration guide](docs/wazuh-integration.md) for installation,
permissions, shared-secret configuration, and HTTPS routing.

## 💭 Feedback and Contributing

Found a bug or have an idea? [Open an issue](https://github.com/h26v/HyperSOC/issues)
with reproduction steps, expected behavior, and sanitized logs. Never include
API keys, credentials, or sensitive production telemetry.

Contributions are welcome: improve documentation, add representative sanitized
fixtures, strengthen correlation and policy tests, or propose provider adapters.
For larger changes, open an issue first to agree on scope and security boundaries.
Submit changes through a pull request with tests and a clear description of what
was verified.

Start with the [testing guide](docs/testing.md). Supporting guidance includes
[AI evaluation](docs/ai-evaluation.md),
[token and cost controls](docs/llm-cost-token-control.md),
[observability](docs/observability.md), and
[security hardening](docs/security-hardening.md).

README structure adapted from
[banesullivan/README](https://github.com/banesullivan/README/blob/main/TEMPLATE.md).
