# Phase 19 — AI Evaluation

The initial eval fixtures live in `backend/tests/fixtures/incidents/`:

- `ssh_bruteforce.json`
- `powershell.json`
- `persistence.json`
- `malware.json`
- `false_positive.json`

## Scoring dimensions

Each eval case should check:

```text
correct classification
correct MITRE mapping
severity accuracy
hallucination avoidance
IOC interpretation
response recommendation quality
false-positive handling
```

## Current status

The offline provider is deterministic and schema-validated. These fixtures define
the target behavior for a future real LLM provider, where runs should be compared
against expected classification, severity, MITRE IDs, and hallucination checks.
