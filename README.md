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
với Phase 4 canonical normalization cho downstream services. Wazuh API/Indexer
polling, threat intelligence, correlation, AI, frontend và active response là
các phase tiếp theo, chưa được triển khai trong codebase này.
