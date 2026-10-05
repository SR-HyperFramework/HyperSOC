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

For a paired comparison against manual Wazuh investigation, use the
[SOC workflow benchmark](soc-workflow-benchmark.md). It defines the baseline,
case collection procedure, scoring formula, and results sheet. The five summary
fixtures above are service-test material, not a timed human baseline. The runnable
11-case pilot and pinned 738-alert workload live in `benchmarks/`; run their
offline unit/integration paths with `make test` and `make benchmark-smoke`.
Neither produces the independently adjudicated evidence required for a reportable
100-point study score.

Jev evaluation must record prompt/context version, classification/severity/NOUL
and confidence distributions, evidence coverage/truncation, provider latency, and
Jev-versus-offline agreement by incident-size bucket. Agreement is not accuracy.
Per-alert source labels may be reported only as diagnostic covariates for mixed
incidents; they must not be promoted to incident ground truth or used to tune a
target class distribution.
