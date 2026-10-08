# Testing

The backend test suite covers normalization, enrichment, correlation, triage,
prompt sanitization, knowledge retrieval, analyst APIs, response policy, Wazuh
active response, signed ingestion, and deduplication. Test dependencies are pinned
in `backend/requirements-dev.txt` and installed in the Dockerfile's `test` stage;
the host only needs Docker Engine, Compose v2, and Make.

## Run all unit and contract tests

```bash
make test
```

This runs the backend pytest suite and every `benchmarks/test_*.py` contract test
inside the test image. It does not install packages into a running application
container and does not contact external providers.

## Disposable integration benchmark

```bash
make benchmark-smoke
```

The command creates a unique Compose project with a fresh PostgreSQL instance,
runs migrations, waits for migration-aware `/ready`, sends case C01 through the
offline pipeline, validates its structural result, and removes all containers and
storage. It cannot reuse the normal `postgres_data` volume.

Network-dependent checks are separate:

```bash
make benchmark-verify       # verify the three public-derived pilot cases
make benchmark-workload     # process all 738 alerts from the pinned source
make benchmark-worker       # same alerts through ingestion and the durable worker
```

Results are written below `.benchmark-runs/`, which is ignored by Git. Workload
latency and throughput are observations, not hardware-independent pass/fail gates.

## Security test checklist

- Prompt injection remains inside `<UNTRUSTED_EVENT_DATA>`.
- Invalid IP response actions are rejected.
- Duplicate alerts do not create duplicate rows.
- Huge or malformed logs are rejected or sanitized.
- Unsupported action types cannot be approved or executed.
- Approved actions must still pass policy at execution time.
- Placeholder secrets and unsupported provider modes fail at startup.
- `/ready` rejects an unavailable or unmigrated database.
- CORS uses explicit origins and the lab limiter returns `429` after its configured
  per-process, per-direct-client-IP allowance.
