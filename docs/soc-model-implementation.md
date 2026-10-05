# SOC automation deployment model: implementation and acceptance

The supplied diagram is the implementation target. Its instructions are design
material; log text, knowledge documents and imported telemetry are evidence and
cannot authorize tool calls or response actions.

The application now implements the complete local workflow and Hub boundary.
Acceptance below establishes software behavior with isolated databases, synthetic
telemetry and offline providers. It does not establish production detection
accuracy, live upstream connectivity or firewall effect on a real endpoint.

## Architecture mapping

| Diagram component | Current implementation | Evidence and operating limit |
| --- | --- | --- |
| Alert understanding | `services/understanding.py` extracts grounded IOCs and attack types; optional OpenRouter summary uses structured output. | `test_alert_understanding.py` rejects invented IOCs and retains extracted indicators and provenance. Offline interpretation remains explicit. |
| EDR/XDR/SIEM input and schema standardization | Versioned `HubEventIn` and normalized security fields; signed native Wazuh, ECS and osquery adapters; JSONL import with checkpoints. | `test_hub_connectors.py` exercises nested/flattened ECS, osquery batches, native identity/severity, signed ingestion and replay. Other vendors can use the canonical contract; their collection/export agents require deployment configuration. |
| Asset, identity and posture context | PostgreSQL `HubEntity`, `HubEvidence`, `HubRelationship`; atomic keyed inventory imports and telemetry projection. | Inventory provenance is retained; detection, behavior and posture are separate categories. Inventory tests reject unresolved relationship endpoints without partial writes. |
| Historical incidents | Matching prior cases include the latest reviewed analyst classification, notes and report reference. | `test_new_detection_after_false_positive_gets_new_review_and_prior_decision_context` verifies feedback and a fresh case for new evidence. Prior FP does not suppress a new detection. |
| Entity relationship explorer | Bounded graph traversal, representative observed edges and explicit inventory grants with source references. | Hub and attack-path database tests; connected SVG explorer. Repeated events remain persisted. Truncation and missing context are visible. |
| Rule/search queries | Hub searches constrain time, host, source and category; graph traversal is limited to three hops and 200 nodes. | `test_search_is_bounded_by_time_host_and_source`; read-only search available to authenticated viewers. No arbitrary SQL or shell tool. |
| Machine learning / anomaly analysis | Versioned categorical density estimator learns prior behavior, reports unusual feature likelihood and stores corpus digest/training window/sample count. | `test_behavior_analytics.py` verifies known versus novel behavior, future exclusion and automatic refresh/reuse. Requires at least 20 prior behavior records; scores need calibration on organizational data. |
| Attack-path prediction | Explicit access graph produces conditional exposure hypotheses; prior MITRE transitions supply learned next-technique candidates. | `test_attack_paths.py` does not infer permission from activity; `test_behavior_analytics.py` verifies learned transitions. Hypotheses retain grant provenance and do not assert that exploitation occurred. |
| Alert/event correlation | Existing correlation extended for singleton detections, source/host gaps, closed-case separation and serialized PostgreSQL writes. | Correlation and workflow tests; future events are excluded and one low-level detection still reaches review. |
| LLM context/function calling | Investigator selects four bounded read-only tools: `incident_alerts`, `cached_intel`, `knowledge_search`, `internal_context`. Reports persist an evidence ledger, timestamps, gaps and validated citations. | `test_investigator.py` rejects unknown tools/citations and decisive labels without observed incident evidence; prompt-sanitizer tests treat source instructions as untrusted data. |
| IOC enrichment | VirusTotal, AbuseIPDB and URLhaus adapters behind existing TI service; TTL cache, evidence associations, partial failures and provider modes. | `test_threat_intel_external.py`, service/extractor tests and worker checkpoint tests. IP2Location, PulseDive, WHOIS and web search shown as diagram examples are not implemented adapters. |
| Durable orchestration | Ingest atomically queues a PostgreSQL job; worker checkpoints understanding, context, enrichment, correlation and conclusion, then waits for analyst review. | Real database tests cover leases, token fencing, backoff, exhausted workers, post-publication retry and distinct concurrent claims. No automatic response execution. |
| Human TP/FP conclusion | Generated report remains alongside an authenticated analyst decision; latest report governs lifecycle and response eligibility. | Auth/workflow tests reject stale review, record account identity and audit, resolve superseded jobs and preserve immediate reviews during worker completion. |
| SOAR / incident response | Separate request, approval and execution; `BLOCK_IP` policy and explicit Wazuh agent scope. Endpoint evidence can reconcile delivery failures. | Response/provider/verification tests. Manager acceptance and simulation leave `containment_verified=false`; trusted matching evidence from every requested agent is required for `CONTAINED`. |
| Analyst console | `/` and `/investigator` serve the API-connected console: queue, findings, citations, inventory/context, graph, workflow state, review and response. | Browser acceptance on actual Compose stack, desktop and 390 px mobile; no horizontal overflow or JavaScript console errors after login. Empty states and offline results remain explicit. |
| Deployment | Backend, PostgreSQL and worker Compose services; migrations through `0010`; account provisioning, connector, model and response operations documented. | Runtime image built successfully; readiness passed and `alembic check` reported no new upgrade operations. See [deployment guide](soc-deployment.md). |

## Acceptance requirements

- [x] Versioned canonical evidence and native Wazuh/ECS/osquery ingestion.
- [x] Persistent asset, identity, posture, behavior, history and relationship context.
- [x] Bounded search and entity relationship explorer.
- [x] Learned anomaly analysis, conditional attack paths and event correlation.
- [x] Grounded alert understanding and optional structured LLM summaries.
- [x] Read-only LLM tools with provenance, gaps and validated evidence citations.
- [x] Reputation adapters, caching, errors and explicit offline/external modes.
- [x] Durable orchestration, idempotency, retries and restart recovery.
- [x] Analyst TP/FP lifecycle decisions and historical feedback.
- [x] Authenticated roles, review/approval identity and audit trail.
- [x] Scoped approved response with separate simulation, delivery and verification.
- [x] Connected console without fabricated live data.
- [x] Deployment configuration, migrations and operating documentation.
- [x] Requirement-specific unit, database, HTTP/worker, recovery and browser checks.

These checks cover implementation acceptance. Live deployment validation below
remains an operational requirement for using external integrations.

## Verification ledger — 2026-10-05

| Check | Observed result |
| --- | --- |
| Full backend and benchmark regression on Docker Python 3.12 | **292 passed, 1 skipped**. The skipped concurrent row-lock test requires PostgreSQL and passed in the PostgreSQL run. Existing dependency deprecation warnings remain. |
| Hub/workflow, behavior, connectors, attack paths, auth and response verification on PostgreSQL 16 | **31 passed**. Each test creates and removes its own schema; includes four simultaneous job claims. These are a subset repeated against PostgreSQL, not 31 additional unique tests. |
| Actual Compose runtime build and migrations | Runtime image built; backend readiness healthy; schema head `0010`; `alembic check`: no new upgrade operations detected. |
| HTTP ingest → durable worker → report → analyst review → response | Passed on the rebuilt runtime image, using real HTTP and PostgreSQL. Signed native input, duplicate replay, 25-record prior baseline, explicit inventory grant, cited report, account-derived identity and approved offline response verified. |
| Worker restart recovery | Passed with worker stopped during ingest: job persisted as `PENDING`, then completed after worker startup. Lease-expiry and interrupted-publication recovery also pass in database tests. |
| Legacy pilot compatibility | Synthetic C01 pilot completed and `validate_result.py pilot` succeeded after replay timestamps were moved before processing time. This is a compatibility check, not an accuracy benchmark. |
| Browser | Signed-in queue/case, citation ledger, internal context, graph, Hub and Automation inspected. Desktop 1440 px and mobile 390 px have no horizontal overflow. Final navigation logged no console errors. |
| Static checks | `node --check frontend/soc.js` and `git diff --check` passed. |

The final HTTP acceptance job was `bf380f5c-a5ac-4c89-ade3-d3d0731e77ca`; report
`320fbf57-22be-4b26-b798-ad1c13d97ea1`. Review left the synthetic case
`INVESTIGATING`, job `REVIEWED`, and simulation `containment_verified=false`.

Local review artifacts are preserved under ignored `.benchmark-runs/`:

- `model-e2e-20261005.result.json`: stopped-worker/startup acceptance.
- `model-e2e-final-20261005.result.json`: final runtime acceptance.
- `soc-model-pilot-replay-20261005.json`: passing legacy pilot.
- `soc-model-console-desktop-20261005.png`: actual connected console screenshot.

Run the full suite in the Dockerfile's `test` target with
`python -m pytest tests /benchmarks -q`. For PostgreSQL integration, set
`SOC_TEST_DATABASE_URL` to an isolated disposable database and run
`test_hub_workflow.py`, `test_behavior_analytics.py`, `test_hub_connectors.py`,
`test_attack_paths.py`, `test_response_verification.py` and `test_soc_auth.py`.
Do not point acceptance scripts or schema-creating tests at a production database.
The HTTP acceptance script intentionally targets only the disposable loopback
stack and synthetic test account.

## Production validation and limits

Configure trusted source keys, actual CMDB/directory exports and telemetry
collection before expecting internal context coverage. The Hub exposes gaps; it
cannot make missing inventory, posture or behavior data complete. Current bounded
context uses recent evidence and may omit older events; the stored corpus remains
available for searches within the API's limits.

External TI credentials and LLM quality were tested through adapter contracts,
fixtures and mocked transports, without live reputation requests or paid model
calls. Run representative, held-out cases before interpreting their classifications
or the learned anomaly scores as production quality measurements.

Wazuh 4.x Manager delivery was tested with a mocked API. No real endpoint firewall
was changed. Deploy an endpoint telemetry integration that preserves the action
ID, verifies the effect and reports each affected agent; standard Manager success
does not provide that evidence. Per-action duration is an audit request: command
expiry/rollback must be configured and validated in Wazuh. Supported response is
currently `BLOCK_IP`; other response playbooks need their own provider and policy.

Production HA, throughput targets, retention and organizational SSO are outside
this local implementation acceptance. Native collection and vendor-specific
adapters beyond those listed above remain deployment/integration work.
