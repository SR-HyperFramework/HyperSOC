# Phase 18 — LLM Cost & Token Control

AI triage must never send unlimited incident data to an LLM provider.

## Implemented controls

The current AI triage context builder enforces:

- `AI_TRIAGE_MAX_ALERTS`
- `AI_TRIAGE_MAX_TEXT_CHARS`
- `AI_TRIAGE_MAX_CONTEXT_CHARS`
- `AI_TRIAGE_MAX_JSON_DEPTH`
- `AI_TRIAGE_MAX_LIST_ITEMS`
- strict `AITriageResult` schema validation
- sanitized RAG context limits through `RAG_TOP_K`, `RAG_MAX_CHUNK_CHARS`, and
  `RAG_MAX_CONTEXT_CHARS`

## Prioritization policy

When context must be reduced, prefer evidence in this order:

1. High-severity detections.
2. Unique rules and MITRE IDs.
3. Authentication changes and success-after-failure events.
4. Process execution and persistence evidence.
5. IOCs and threat-intel summaries.
6. Representative timeline events.

## Provider guidance

The offline provider is the default. A real provider must add request/response
usage logging, timeout handling, schema validation, and cost monitoring before it
is enabled outside a lab.
