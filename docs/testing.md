# Phase 21 — Testing

The backend test suite covers the current MVP layers:

```text
normalizer
IOC extraction and canonicalization
threat-intel risk scoring/cache
correlator
AI triage schema validation
prompt sanitizer
RAG knowledge base
analyst API/dashboard
response policy engine
Wazuh active-response offline execution
signed ingest and deduplication
```

## Run tests

```bash
ENV_FILE=.env.example docker compose run --rm --no-deps backend sh -lc \
  'pip install --quiet pytest httpx && python -m pytest tests/ -v'
```

## Security test checklist

- Prompt injection remains inside `<UNTRUSTED_EVENT_DATA>`.
- Invalid IP response actions are rejected.
- Duplicate alerts do not create duplicate rows.
- Huge/malformed logs are rejected or sanitized.
- Unsupported action types cannot be approved or executed.
- Approved actions must still pass policy at execution time.
