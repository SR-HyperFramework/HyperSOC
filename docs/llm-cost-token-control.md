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
- one batched Jev call containing three parallel, atomic questions

## Prioritization policy

When context must be reduced, prefer evidence in this order:

1. High-severity detections.
2. Unique rules and MITRE IDs.
3. Authentication changes and success-after-failure events.
4. Process execution and persistence evidence.
5. IOCs and threat-intel summaries.
6. Representative timeline events.

## Provider guidance

The offline provider remains the default. The Jev provider uses the configured
`AI_TRIAGE_TIMEOUT_SECONDS`, accepts only typed Choice/Noul answers, validates
all values before persistence, and keeps the existing incident context bounds.
Production deployments should additionally export TypeSafe request usage and
latency into the observability stack and alert on provider errors and cost drift.
