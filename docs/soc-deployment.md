# Deploying the SOC automation model

The backend, PostgreSQL and `worker` implement the supplied flow. Wazuh, ECS and
osquery telemetry enter the Cyber Intelligence Hub. The worker understands the
alert, gathers internal context, enriches IOCs, correlates a case and produces a
reviewable conclusion. Analyst review and response approval are separate actions.

## Start and provision accounts

Copy `.env.example` to a private `.env`, configure a random `APP_SECRET_KEY` and
database password, then run:

```bash
docker compose up -d --build
docker compose exec backend python -m app.workers.create_user soc-admin admin
```

The account command prompts twice for a password of at least 12 characters. It
also updates an existing account's password/role and revokes its earlier sessions.
Use positional roles `viewer`, `analyst` or `admin`. Open `/` or `/investigator`
and sign in. Passwords are salted PBKDF2 hashes. Sessions expire according to
`AUTH_SESSION_SECONDS`; cookie mutations require `X-SOC-CSRF` and an allowed origin.
Bearer sessions can be used by API clients. Logout clears the browser cookie;
bearer sessions remain valid until expiry or a credential/account change.

Viewer accounts read evidence, cases and bounded Hub searches. Analysts run
investigations, review conclusions and request/approve/execute responses. Admins
also import inventory, relationships, train models and read `/api/v1/auth/audit`.
Set `AUTH_ENABLED=false` only for an isolated demonstration/benchmark.

Compose runs `alembic upgrade head` before backend and worker startup. Current head
is `0010`. `/ready` checks the database and migration head. Redis is reserved; the
SOC queue uses PostgreSQL and does not depend on Redis. Existing alerts are not
automatically backfilled into jobs; replay their source events through a new
source namespace or explicitly operate the manual correlation/investigation APIs.

## Native and canonical ingest

All event routes require HMAC-SHA256 of the **exact bytes**:

```text
message = X-SOC-Timestamp + "." + request_body
X-SOC-Signature = hex(HMAC-SHA256(source_secret, message))
```

Timestamp skew and request size are bounded. Wazuh's existing `/api/v1/alerts`
adapter uses `APP_SECRET_KEY`. `/api/v1/hub/events` accepts the canonical contract:

```json
{
  "schema_version": "1.0",
  "source": "edr-prod",
  "external_id": "source-event-123",
  "category": "detection",
  "alert": {
    "timestamp": "2026-10-05T10:00:00Z",
    "host": {"name": "finance-01", "id": "001"},
    "identity": {"username": "alice"},
    "process": {"name": "powershell.exe", "pid": 123},
    "detection": {"description": "Endpoint detection", "level": 12, "mitre_ids": ["T1059.001"]}
  },
  "attributes": {"source_case_id": "case-123"}
}
```

Use stable source namespaces and external event IDs. Same ID/same content is an
idempotent replay; changed content returns `409`. `detection` creates an Alert and
a durable job in the same transaction. `behavior` and `posture` store context
without creating incidents. They must be classified by the source adapter; do
not import detections as normal behavior to obtain a larger training baseline.

`POST /api/v1/hub/native-events` accepts:

```json
{"format":"ecs","source":"edr-prod","event":{"@timestamp":"2026-10-05T10:00:00Z","event":{"id":"123","kind":"alert","category":["process"]},"host":{"name":"finance-01"},"process":{"name":"powershell.exe","pid":123}}}
```

Supported formats:

| Format | Mapping and classification |
| --- | --- |
| ECS | Nested or flattened host/user/process/network/file fields; `alert`/`signal` → detection, vulnerability state → posture, ordinary events → behavior. Native severity units are retained rather than treated as Wazuh levels. |
| osquery | Single `columns`, `snapshot`, or `diffResults` rows; query/host/time/epoch/counter and original columns retained. Defaults to behavior. At most 200 rows per envelope. |
| Wazuh | Existing normalization; SCA/vulnerability → posture, rule-bearing events → detection, archives without a rule → behavior. |

An explicit envelope `category` overrides these defaults. Adapters follow the
[ECS event contract](https://www.elastic.co/docs/reference/ecs/ecs-event) and
[osquery result formats](https://osquery.readthedocs.io/en/stable/deployment/logging/).
These are ingestion adapters and an export replay client; collection/export from
the source platform must be configured by its operator.

For independent trust boundaries, configure `HUB_SOURCE_KEYS` as a JSON object
mapping source namespace to a unique secret. Once configured, unlisted sources
are rejected and one connector's key cannot impersonate another source. With an
empty mapping, all Hub sources use `APP_SECRET_KEY` and share its trust boundary.
Keep the response telemetry source key separate from ordinary EDR/log connectors.

## Replay exported logs and import inventory

The replay client accepts UTF-8 JSONL, checkpoints acknowledged lines atomically
and refuses to reuse a checkpoint after input content changes:

```bash
# Supply SOC_INGEST_SECRET privately in the process environment.
python -m app.workers.import_hub --url https://soc.internal --file results.jsonl --format osquery --source osquery-prod
python -m app.workers.import_hub --url https://soc.internal --file edr.jsonl --format ecs --source edr-prod
```

Run from `backend` with project dependencies installed, or inside the backend
container with an input mount. The secret is not a command-line argument. Retryable
HTTP errors retain the checkpoint. HTTPS is required for remote hosts; loopback
HTTP is permitted and `--allow-local-http` supports isolated network testing.
A log shipper can POST native envelopes continuously using the same contract.

Admins can `POST /api/v1/hub/inventory` with up to 200 entities and 200 relationships:

```json
{
  "entities": [
    {"kind":"asset","external_key":"finance-01","label":"Finance endpoint","source":"cmdb","observed_at":"2026-10-05T09:00:00Z","attributes":{"owner":"Finance","criticality":"high"}},
    {"kind":"identity","external_key":"alice","label":"alice","source":"directory","observed_at":"2026-10-05T09:00:00Z","attributes":{"privileged":true}}
  ],
  "relationships": [
    {"source_kind":"identity","source_key":"alice","target_kind":"asset","target_key":"finance-01","relation":"administers","source_ref":"directory:grant-123","observed_at":"2026-10-05T09:00:00Z"}
  ]
}
```

Use the same host name and domain-qualified username keys as source telemetry.
Inventory upgrades automatically discovered entities and retains source authority;
subsequent detection projections do not overwrite CMDB/directory attributes.
Relationship references identify the grant/inventory record, not a guessed path.
An invalid relationship rolls back the entire batch. For JSONL batches, set a
private admin bearer session in `SOC_CONNECTOR_TOKEN` and use `--format inventory`.

## Worker recovery and learned analytics

`AUTOMATION_ENABLED=true` queues new detections. The worker claims jobs using
PostgreSQL row locks, leases and fencing tokens. Scale workers with
`docker compose up -d --scale worker=2`. Check `/api/v1/workflows` or Automation in
the console. Stages persist their evidence/checkpoints; a crashed worker's lease
expires and another worker resumes. Max attempts produce `FAILED`; analysts can
retry via `/api/v1/workflows/{id}/retry`. No worker approves a response.

With `BEHAVIOR_AUTO_TRAIN=true`, processing an alert refreshes its host baseline
from earlier behavior records in `BEHAVIOR_TRAINING_DAYS` (default 30, maximum 90).
At least 20 observations are needed; up to the latest 5,000 are used. Models are
refreshed at most every `BEHAVIOR_REFRESH_SECONDS` (default 3,600), and unchanged
corpora reuse their model. Events at or after the alert time never enter its model.
Model parameters, training window, sample count and corpus digest persist.

The categorical density model reports feature surprise and novel values. Its
score is a triage signal, not a calibrated probability of compromise. Prior
detections train technique transitions; predicted next techniques are hypotheses.
Explicit `administers`, `can_access`, `member_of` and `trusted_by` relationships
identify potential reachable assets under an explicit compromise assumption.
Ordinary `observed_on` activity does not imply access permission. Graph and path
queries are bounded and disclose truncation or missing context. Access paths
combine observed permissions with learned technique suggestions; they do not
establish that an attacker traversed the route.

Admins may manually train `/api/v1/hub/models/train` with `host`, `since` and `until`.
The console shows available analysis and explicit insufficient-baseline gaps.
Models and hypotheses require evaluation against representative organization data
before their scores are used in production policy.

## Conclusion, response and verification

The latest report is reviewed once; stale reports cannot override newer evidence.
The generated report remains unchanged alongside the analyst classification and
notes. TP/needs-investigation moves a case to `INVESTIGATING`; FP moves it to
`FALSE_POSITIVE`; unknown moves it to `TRIAGED`. Prior analyst decisions enter
matching historical context. Review does not approve or execute response.
When the latest report replaces an older workflow report, reviewing it resolves
the older job as `SUPERSEDED`. Reviewing the job's current report sets `REVIEWED`.
The original generated reports remain available for audit.

In authenticated mode, response approval and execution both recheck the latest
analyst-confirmed TP report and target policy. Names are taken from the account.
`offline` records simulation. Real Wazuh mode requires explicit agent IDs and
records Manager acceptance separately from endpoint effect. Unknown/interrupted
execution is not retried automatically, because a duplicate firewall action may
have side effects. Its stored scope and trusted telemetry can reconcile the result.

For real containment, a trusted endpoint connector must provide block telemetry
after approval, identify each affected agent, and include:

```json
{"response_action_id":"<action UUID>","response_effect":"blocked","target":"8.8.8.8"}
```

These are canonical event `attributes`; `alert.host.id` identifies the agent.
The native Wazuh adapter also maps `data.hypersoc_response` containing `action_id`,
`effect:"blocked"` and `target`. These are an explicit integration contract; the
standard Manager acknowledgement does not supply proof of endpoint containment.
The Wazuh 4.x request carries `hypersoc_response.action_id` and `target` in its
alert data. It does not send an `effect`. An endpoint integration must report
`effect:"blocked"` only after checking the firewall effect on that endpoint.
Wazuh passes the full alert to the response script, so that script can retain
this correlation ID in its result telemetry. See the
[official custom Active Response documentation](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html).
Per-action `duration_minutes` is retained for audit; the current 4.x adapter does
not override command timeout. Configure expiry/rollback in the Wazuh command and
confirm its behavior on each supported endpoint platform.
Source namespaces must appear in `RESPONSE_EVIDENCE_SOURCES`. Submit evidence for
**every** stored requested agent:

```json
{"evidence_ids":["<agent 001 evidence UUID>","<agent 002 evidence UUID>"],"notes":"Endpoint firewall logs confirm the target block"}
```

POST this to `/api/v1/actions/{id}/verify`, or use the console verification form.
Only matching target/action/source/time/scope evidence sets `containment_verified`
and moves the incident to `CONTAINED`. Simulation cannot be verified as containment.

Live Wazuh endpoint behavior, external TI credentials and LLM quality must be
validated against the deployment's actual upstream systems. Local test evidence
and remaining verification are tracked in `soc-model-implementation.md`.
