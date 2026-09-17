# Prompt injection protection

Phase 8 protects the AI pipeline from malicious log and event data. Wazuh and
endpoint evidence can contain attacker-controlled strings, so AI-bound evidence is
sanitized and isolated before any provider receives it.

## Pipeline

AI triage follows the Phase 8 roadmap pipeline:

```text
Raw Event
   ↓
Parser
   ↓
Normalizer
   ↓
Sanitizer
   ↓
Structured JSON
   ↓
LLM / offline provider
```

The backend does not concatenate raw logs with system prompts. The triage path
starts from correlated incidents, converts linked alerts through the Phase 4
`normalize_persisted_alert()` bridge, then passes allowlisted context through the
Phase 8 `PromptSanitizer`.

## Untrusted evidence boundary

Future real-provider prompts must keep instructions separate from evidence and
wrap sanitized event data in explicit delimiters:

```text
<UNTRUSTED_EVENT_DATA>
{...sanitized structured JSON...}
</UNTRUSTED_EVENT_DATA>
```

All text inside that block is evidence only. Usernames, process command lines,
filenames, URLs, hostnames, rule descriptions, user agents, and provider summaries
must never be treated as instructions.

## Sanitizer controls

`backend/app/services/prompt_sanitizer.py` applies deterministic controls before
provider analysis:

- strips control characters.
- replaces binary-like data with `[BINARY_DATA_STRIPPED]`.
- strips huge blobs with `[HUGE_BLOB_STRIPPED]`.
- redacts secret-like values such as `password=`, `token=`, `api_key=`, bearer
  tokens, and sensitive URL query parameters.
- truncates long fields.
- caps total AI context characters.
- caps JSON nesting depth.
- caps list and mapping entries.
- records sanitizer metadata counters for truncation, redaction, stripping,
  depth limiting, and dropped items.

The sanitizer is pure and does not mutate caller-owned objects.

## Configuration

Default `.env.example` limits are intentionally conservative for lab use:

```dotenv
AI_TRIAGE_MAX_ALERTS=25
AI_TRIAGE_MAX_TEXT_CHARS=1000
AI_TRIAGE_MAX_CONTEXT_CHARS=20000
AI_TRIAGE_MAX_JSON_DEPTH=6
AI_TRIAGE_MAX_LIST_ITEMS=50
AI_TRIAGE_BINARY_PLACEHOLDER=[BINARY_DATA_STRIPPED]
```

Offline mode still requires no LLM API key, model, internet access, or hosted
provider.

## Security guarantees

Phase 8 preserves the previous trust boundary:

- `alerts.raw_event` is not sent to AI providers.
- native Wazuh JSON and signed ingest bodies are not sent to AI providers.
- raw threat-intel provider payloads are not sent to AI providers.
- provider output must validate against strict Pydantic schemas before storage.
- LLM recommendations remain advisory; response actions are not executed by Phase
  8 and still require later human approval and policy checks.

## Testing

Phase 8 tests cover prompt-injection strings, binary/control data, huge blobs,
field and total context truncation, depth limiting, list caps, secret redaction,
non-mutation, untrusted-data delimiters, raw-event exclusion, and alert-count
limits.
