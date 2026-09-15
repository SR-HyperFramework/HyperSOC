# Wazuh integration

This repository receives alerts from an existing Wazuh manager. It does **not**
install or replace the Wazuh manager, Wazuh indexer, or Wazuh dashboard.

## Topology

```text
Wazuh manager  -- outbound HTTPS -->  SOC host:8000 (or reverse proxy)
                                           |
                                           +--> backend container:8000
                                           +--> postgres (private Compose network)
```

The manager must use a routable host name or IP for the SOC host. It must not
use the Compose DNS name `backend`, and `localhost` only works when the manager
and the published backend port run on the same host. TCP port `8000` is the
local development ingress; production deployments should put the endpoint
behind a TLS reverse proxy and allow inbound traffic only from the manager's
address (or a private network/VPN).

The backend's `/health` endpoint checks process liveness. `/ready` checks
PostgreSQL connectivity; it does not run migrations. Apply migrations before
enabling the Wazuh integration:

```bash
docker compose up -d --build
docker compose exec backend alembic upgrade head
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/ready
```

Only the backend ingress should be reachable from the manager. PostgreSQL and
Redis remain on the private Compose network.

## Configure the manager

The current Wazuh Integrator contract invokes the executable as
`<alert_file> <api_key> <hook_url>`. The script name in `ossec.conf` must match
the executable in `/var/ossec/integrations/` and begin with `custom-`.

Copy the adapter to the manager and set the permissions required by Wazuh:

```bash
sudo install -o root -g wazuh -m 750 \
  integrations/wazuh/custom-ai-soc.py \
  /var/ossec/integrations/custom-ai-soc.py
```

Choose a long random secret. Configure it as `APP_SECRET_KEY` for the backend
and as the Wazuh `<api_key>` value. Keep the secret out of Git and out of
logs. Add this block inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-ai-soc</name>
  <hook_url>https://soc.example.internal/api/v1/alerts</hook_url>
  <api_key>REPLACE_WITH_THE_SHARED_SECRET</api_key>
  <alert_format>json</alert_format>
  <!-- Optional filters can reduce volume. Without them all alerts are sent. -->
  <!-- <level>5</level> -->
</integration>
```

Replace the example URL with the actual address reachable from the manager.
After validating the configuration, restart the manager:

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/integrations.log
```

The adapter sends the normalized envelope expected by `POST /api/v1/alerts`:
agent, rule, common network/process/file fields, and the complete native alert
under `raw`. It signs the exact JSON bytes with HMAC-SHA256 over
`<unix_timestamp>.<body>` and sends `X-SOC-Timestamp` and `X-SOC-Signature`.
The backend accepts timestamps within
`INGEST_SIGNATURE_MAX_SKEW_SECONDS` (300 seconds by default), so synchronize
clocks on the manager and SOC host.

## Phase 4 canonical normalization

The manager adapter remains responsible for the signed Phase 3 transport
envelope. The backend separately exposes the pure
`app.services.normalization.normalize_wazuh_alert()` service for downstream
SOC code. It accepts native Wazuh JSON or the envelope's `raw` object and emits
a provider-neutral `NormalizedAlert` with `host`, `identity`, `network`,
`process`, `file`, and `detection` sections plus `id`, `timestamp`, and
`raw_ref` provenance.

The parser recognizes Windows authentication, Sysmon, PowerShell, Linux SSH,
auditd, FIM, and nginx layouts. It preserves host id/name/IP, authentication
actor/target/status/outcome, network IP/port/domain/URL/DNS data, process
image/command/parent/script metadata, file path/hash/action, rule metadata,
event family/kind, provider, decoder, groups, and MITRE IDs. Missing or
malformed optional fields are omitted instead of inferred.

It does not alter webhook delivery, database deduplication, or the public Phase
3 alert API. `NormalizedAlert.id` is a caller-supplied or generated canonical
UUID; the native Wazuh alert id remains `raw_ref` provenance only. The stored
native event remains untrusted evidence; do not pass `raw_event` directly to an
LLM. Phase 5 threat-intelligence enrichment consumes bounded canonical
indicators from `NormalizedAlert`; see [`threat-intelligence.md`](threat-intelligence.md).

## Validate delivery

From the manager, first verify that the SOC host and port are reachable. Then
trigger a safe lab event that already generates a Wazuh alert (for example, a
controlled authentication failure). Check the manager integration log and query
the backend:

```bash
curl -fsS http://SOC_HOST:8000/health
curl -fsS 'http://SOC_HOST:8000/api/v1/alerts?limit=20'
```

A newly accepted alert returns HTTP `201`; replaying the same fingerprint returns
HTTP `200` and does not create a second row. The read endpoint is intended for
local/lab inspection; place it behind the same access controls as the rest of
the backend before exposing it to analysts.

## Troubleshooting and rollback

- **No request in the backend:** confirm the manager can route to the SOC host,
  firewall rules allow the ingress, and the URL is not `localhost` or the
  Compose-only name `backend`.
- **401 from the backend:** compare the manager `<api_key>` with
  `APP_SECRET_KEY`, check clock synchronization, and ensure a proxy has not
  rewritten the request body or removed the two `X-SOC-*` headers.
- **400 from the backend:** inspect the normalized payload and the original
  alert file; the adapter requires a parseable Wazuh `timestamp`.
- **Integration errors:** inspect `/var/ossec/logs/integrations.log`. Delivery
  retries briefly for transient failures and exits nonzero after exhausting
  them, while malformed alert files are rejected without a traceback.
- **Rollback:** remove or comment out the `<integration>` block, restore the
  previous script if one existed, then restart `wazuh-manager`. Rotate the
  shared secret in both systems if it may have been exposed.

The settings named `WAZUH_API_URL`, `WAZUH_API_USERNAME`, and
`WAZUH_API_PASSWORD` are reserved for a future backend-to-Wazuh API adapter.
The current integration is manager-to-backend webhook delivery and does not
require the Wazuh API, indexer, or dashboard ports.
