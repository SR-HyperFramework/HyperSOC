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

The offline provider is deterministic and schema-validated. The Jev provider can
be evaluated against the same fixtures for classification, severity, false-positive
probability, confidence calibration, and prompt-injection resistance. MITRE IDs,
evidence references, and recommendations remain deterministic backend output and
should be checked separately from Jev's typed decisions.
