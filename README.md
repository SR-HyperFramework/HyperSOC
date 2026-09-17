# AI SOC Lab

Backend nhận alert từ Wazuh, normalize, và lưu vào PostgreSQL. Xem `AI SOC Lab Implementation Plan.md` ở thư mục cha để biết toàn bộ roadmap.

## Chạy local (cần Docker)

Tạo cấu hình local từ template và thay secret bằng một giá trị ngẫu nhiên:

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec backend alembic upgrade head
```

Kiểm tra:

```bash
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8000/ready
```

Compose chỉ chạy backend, PostgreSQL và Redis dự phòng; Wazuh Manager,
Indexer và Dashboard hiện có của bạn không bị thay thế hay chạy thêm.
PostgreSQL/Redis chỉ cần mạng nội bộ Compose; backend là dịch vụ duy nhất
công bố cổng 8000.

## Chạy test (không cần Postgres, dùng fake session)

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest tests/ -v
```

## Nối Wazuh hiện có vào backend (Phase 3)

Xem hướng dẫn đầy đủ, topology và troubleshooting tại
[`docs/wazuh-integration.md`](docs/wazuh-integration.md). Tóm tắt:

1. Trên Wazuh Manager, cài `integrations/wazuh/custom-ai-soc.py` vào
   `/var/ossec/integrations/custom-ai-soc.py` với owner `root:wazuh` và mode
   `750`.
2. Đặt cùng một secret ngẫu nhiên vào `APP_SECRET_KEY` của backend và thẻ
   `<api_key>` của Wazuh. Không commit secret thật.
3. Trong `/var/ossec/etc/ossec.conf`, dùng URL **routable từ manager** (không
   dùng `backend` hoặc `localhost` trừ khi chạy cùng host):

   ```xml
   <integration>
     <name>custom-ai-soc</name>
     <hook_url>https://SOC_BACKEND_HOST/api/v1/alerts</hook_url>
     <api_key>SHARED_HMAC_SECRET</api_key>
     <alert_format>json</alert_format>
   </integration>
   ```

4. Restart `wazuh-manager` và theo dõi
   `/var/ossec/logs/integrations.log`. Tạo một alert lab an toàn rồi kiểm tra
   `GET /api/v1/alerts`; alert mới trả `201`, replay cùng fingerprint trả `200`.

`POST /api/v1/alerts` yêu cầu HMAC headers `X-SOC-Timestamp` và
`X-SOC-Signature`; payload được giữ nguyên dưới `raw` sau khi chuẩn hóa.

## Phase 4 — Canonical Normalization Layer

Phase 3's manager adapter still sends the signed transport envelope
`source` / `timestamp` / `agent` / `rule` / `event` / `raw`. Phase 4 adds a
backend-owned, provider-neutral `NormalizedAlert` for future enrichment and
correlation; it does **not** change the manager configuration, webhook format,
or current flat alert API.

The pure entry point is `app.services.normalization.normalize_wazuh_alert()`. It
accepts either native Wazuh JSON or the existing Phase 3 envelope (using its
`raw` member when available) and returns typed sections:

```text
id, timestamp, host, identity, network, process, file, detection, raw_ref
```

Supported Wazuh evidence families are Windows authentication, Sysmon,
PowerShell, Linux SSH, auditd, FIM, and nginx. The canonical sections preserve
stable correlation/enrichment fields such as host id/name/IP, auth actor/target
and outcome, network IP/port/domain/URL/DNS data, process image/command/parent
metadata, file path/hash/action, rule metadata, event family/kind, status,
outcome, provider, decoder, groups, and MITRE IDs.

Missing or malformed optional fields become absent canonical evidence rather
than inferred values. `NormalizedAlert.id` is a canonical UUID supplied by the
caller or generated locally; the native Wazuh alert id remains `raw_ref`
provenance. Native log content remains untrusted; `raw_ref` is only provenance
metadata, while the full raw event remains in the existing Phase 3 storage path.
Sanitization for LLM use is a later phase.

## Phase 5 — Threat Intelligence Enrichment

Phase 5 adds offline-first IOC enrichment before future AI/correlation work. The
backend enriches bounded indicators extracted from the Phase 4 `NormalizedAlert`
contract; it does not query or embed raw Wazuh JSON in enrichment output.

Supported indicator types are `ip`, `domain`, `hash`, and `url`. Results follow a
unified shape with `indicator`, `type`, sanitized `providers`, `risk_score`,
`verdict`, `cached`, `cached_until`, and `last_lookup_at`. Cache TTLs match the
roadmap: IP and URL results cache for 6 hours, domains for 12 hours, and hashes
for 24 hours.

The default provider mode is deterministic and offline, so local testing does not
require VirusTotal, AbuseIPDB, URLHaus, Redis, or internet access. External
provider settings remain placeholders for a later pass.

Example API calls:

```bash
curl -fsS 'http://localhost:8000/api/v1/threat-intel/lookup?type=ip&indicator=10.10.10.50'
curl -fsS -X POST 'http://localhost:8000/api/v1/alerts/<alert-id>/threat-intel'
curl -fsS 'http://localhost:8000/api/v1/alerts/<alert-id>/threat-intel'
```

Threat-intel cache rows are stored separately from `alerts.raw_event`, and alert
associations are replay-safe. See
[`docs/threat-intelligence.md`](docs/threat-intelligence.md) for the detailed
contract and offline provider behavior.

## Phase 6 — Rule-based Correlation Engine

Phase 6 turns related normalized/enriched alerts into incidents without using AI.
The correlation engine consumes persisted alerts through the Phase 4
`normalize_persisted_alert()` bridge and may read sanitized Phase 5 enrichment
associations; it does not parse raw Wazuh JSON directly and does not run from the
signed ingest endpoint.

The first rules are deterministic: related alerts sharing host and source IP
within the default 10-minute window become one incident, with additional scoring
for brute-force, PowerShell, persistence, and malware/hash chains. Incidents keep
status, severity, confidence, first/last seen timestamps, primary host/user/source
IP, MITRE IDs, alert count, and related alert IDs.

Example API calls:

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/correlation/run' \
  -H 'Content-Type: application/json' \
  -d '{"lookback_minutes":60,"window_minutes":10,"min_alerts":2}'
curl -fsS 'http://localhost:8000/api/v1/incidents?status=NEW'
curl -fsS 'http://localhost:8000/api/v1/incidents/<incident-id>'
```

See [`docs/correlation.md`](docs/correlation.md) for rule details and
idempotency behavior.

## Phase 7 — Offline AI Incident Triage

Phase 7 adds incident-level AI triage after correlation. The triage service builds
a bounded context from the incident, Phase 4 normalized alert evidence, and Phase
5 sanitized enrichment summaries; it does not send `alerts.raw_event`, native
Wazuh JSON, signed ingest bodies, or raw provider payloads to the AI provider.

The default provider is deterministic and offline, so local tests and demos do not
require a real LLM endpoint, internet access, or API keys. A successful run stores
a short validated summary in `incidents.ai_summary` and compact schema-validated
JSON in `incidents.ai_analysis`. AI recommendations are advisory only and do not
execute response actions or automatically change incident lifecycle fields.

Example API calls:

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/incidents/<incident-id>/ai-triage' \
  -H 'Content-Type: application/json' \
  -d '{"force":true}'
curl -fsS 'http://localhost:8000/api/v1/incidents/<incident-id>'
```

See [`docs/ai-triage.md`](docs/ai-triage.md) for the strict output schema,
configuration, and security boundaries.

## Phase 8 — Prompt Injection Protection

Phase 8 makes the AI triage boundary explicit: normalized incident evidence passes
through a dedicated sanitizer before provider analysis, then is serialized as
structured JSON inside `<UNTRUSTED_EVENT_DATA>` delimiters for future real LLM
providers. The sanitizer strips control characters, removes binary-like values and
huge blobs, redacts secret-like tokens, truncates long fields, and caps context
size, JSON depth, and list lengths.

See [`docs/prompt-injection-protection.md`](docs/prompt-injection-protection.md)
for the sanitizer controls and prompt boundary.

## Phase 9 — Offline RAG Knowledge Base

Phase 9 adds a local SOC knowledge base for MITRE ATT&CK, Wazuh notes, Sigma
explanations, internal playbooks, and Windows/Linux references. Markdown documents
are chunked deterministically and searched offline through a replaceable
`VectorStore` interface. Retrieved chunks populate AI triage MITRE/playbook
context and remain subject to Phase 8 sanitization and strict output validation.

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/knowledge/index'
curl -fsS 'http://localhost:8000/api/v1/knowledge/search?mitre_ids=T1110&alert_types=ssh&top_k=5'
```

The default mode requires no Qdrant, embeddings, network access, or API keys. See
[`docs/knowledge-base.md`](docs/knowledge-base.md) for sources, metadata, limits,
and retrieval behavior.

## Phases 10–22 — Analyst workflow through MVP closure

Later roadmap phases add analyst-facing APIs, a static dashboard shell, response
action approval/execution flow, MITRE visualization guidance, safe lab automation,
observability/cost/eval/hardening/testing docs, and final MVP scope tracking.

Key additions:

- Analyst APIs: `/api/v1/incidents/{id}/triage`, `/reanalyze`, `/analysis`, and
  `/api/v1/dashboard/{summary,mitre,timeline}`.
- Response APIs: `/api/v1/incidents/{id}/actions`, `/api/v1/actions/{id}/approve`,
  `/reject`, and `/execute`.
- Static dashboard shell in `frontend/`.
- Safe LAB ONLY telemetry scripts in `attacks/` and demo checklist in
  `demo/full_attack_chain/`.
- Final documentation in `docs/mitre-visualization.md`, `docs/observability.md`,
  `docs/llm-cost-token-control.md`, `docs/ai-evaluation.md`,
  `docs/security-hardening.md`, `docs/testing.md`, and `docs/mvp-scope.md`.

The default active-response provider is offline: it records an approved BLOCK_IP
execution result and marks the incident `CONTAINED` without contacting a real
Wazuh manager. Replace the `SIEMProvider` adapter when enabling a real Wazuh API.

## Definition of Done — Phase 3

```bash
curl -fsS 'http://localhost:8000/api/v1/alerts?limit=50'
```

phải trả về alert vừa được Wazuh forward sang. Chi tiết xác nhận end-to-end
với manager hiện có nằm trong tài liệu tích hợp.

## Tài liệu tham khảo

- [Wazuh external API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [Hướng dẫn nối Wazuh hiện có](docs/wazuh-integration.md)

Nguồn Wazuh chính thức mô tả custom integration nhận lần lượt alert file,
`api_key` và `hook_url`, yêu cầu tên script bắt đầu bằng `custom-`, executable
`root:wazuh`, và `alert_format` là `json`.

## Status

Đây là MVP của luồng Wazuh Manager → webhook ký HMAC → FastAPI → PostgreSQL,
với Phase 4 canonical normalization, Phase 5 offline-first threat intelligence
enrichment, Phase 6 rule-based incident correlation, Phase 7 offline AI incident
triage, Phase 8 prompt-injection protection, và Phase 9 offline RAG knowledge
base cho downstream services. Wazuh API/Indexer polling, real external
threat-intel providers, real LLM provider calls, frontend và active response là
các phase tiếp theo, chưa được triển khai trong codebase này.
