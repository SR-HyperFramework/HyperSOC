# SOC workflow benchmark: manual Wazuh vs HyperSOC

This benchmark measures whether HyperSOC improves incident investigation over a
traditional alert-by-alert SOC workflow. It is a protocol and scorecard, not a
claim of measured speed or accuracy. The five incident fixtures in
`backend/tests/fixtures/incidents/` are useful pilot cases, but they contain
summaries rather than complete raw alert bundles and cannot establish a
defensible production performance score.

## Compared workflows

| Arm | Analyst receives | Allowed work | Output |
| --- | --- | --- | --- |
| Traditional | Wazuh alerts and the same approved threat-intelligence sources and playbooks | Manually group alerts, check IOCs, classify, assign severity and MITRE IDs, request approval for containment | Standard incident worksheet |
| HyperSOC offline | The same Wazuh alerts plus HyperSOC correlation, offline enrichment, local knowledge, and deterministic triage | Analyst reviews and corrects the generated incident and recommendations | The same incident worksheet |
| HyperSOC Jev (optional, separate arm) | Same as HyperSOC offline, with TypeSafe Jev enabled | Analyst reviews and corrects Jev's typed decisions | The same incident worksheet |

Keep the source alerts, IOC data, playbooks, Wazuh configuration, analyst
instructions, and response policy identical across arms. Record provider modes
and versions. The connected console now supports evidence and review, while the
pilot runner uses a standardized incident packet/API view. Record which interface
each arm uses so interface differences do not obscure the workflow measurement.
Never score offline response simulation as real containment.

## Dataset and procedure

1. Build at least **40 labeled cases** with full alert bundles: at least 10 each
   for true positive, false positive, needs investigation, and unknown. Include
   SSH brute force, PowerShell, persistence, malware, and benign maintenance.
   Mix unrelated alert decoys and multiple incident groups into the batches so
   grouping can actually be scored. Reserve cases with critical severity,
   misleading log text, and unsafe `BLOCK_IP` targets. Do not tune rules or
   prompts on the final benchmark set.
2. Two analysts independently work each case, one using each arm. Alternate
   analyst-to-arm assignment by case and randomize case order. A single analyst
   must not see the same case in both arms.
3. Start wall-clock time when the alert bundle is released. Include any API
   calls needed to start correlation, enrichment, or triage. Stop when the
   analyst records a final classification, severity, incident grouping, MITRE
   IDs, cited evidence, and response recommendation. Record analyst active time
   separately from queueing/provider time. Use the same worksheet in all arms.
4. Have a third reviewer label ground truth from full evidence before revealing
   either arm's output. Resolve disagreements without using HyperSOC predictions.
5. For repeat consistency, have fresh analysts independently review a held-out
   subset in each arm; repeat automated HyperSOC calls on identical inputs too.
   After changing the system, rerun the full study on held-out cases. Report
   median and p95 times, sample counts, confidence intervals, and every provider
   failure. Keep failed runs in the denominator.

Store one record per case and arm with: case ID, anonymized analyst ID, input
bundle hash, provider mode/version, ground-truth and predicted incident groups,
classification, severity, MITRE IDs, cited evidence, response decision, start/end
timestamps, active seconds, and direct provider cost. This is the evidence behind
the scorecard; keep sensitive telemetry out of public CV material.

## Score: 100 points

All rates range from 0 to 1. A score is **not reportable** until every metric has
data from both arms. For the time components, `B` is the traditional arm's time
on the same case set and `T` is the arm being scored. The formula gives the
traditional arm half of the available time points; a 2x improvement earns full
time points. Use `min(1, B / (2*T))`, with nonzero measured times.

| Metric | Points | Measurement and formula |
| --- | ---: | --- |
| Incident grouping | 10 | Pairwise F1 for whether two alerts belong to the same incident; `10 * F1` |
| Classification | 15 | Macro F1 across the four classes; `15 * F1` |
| Critical severity recall | 10 | Correctly identified critical cases / all ground-truth critical cases; `10 * recall` |
| MITRE mapping | 5 | Micro F1 over technique IDs; `5 * F1` |
| Median time to verdict | 15 | `15 * min(1, B_median / (2*T_median))` |
| p95 time to verdict | 10 | `10 * min(1, B_p95 / (2*T_p95))` |
| Median analyst active time | 5 | `5 * min(1, B_active / (2*T_active))` |
| Evidence validity | 10 | Supported cited evidence references / all cited references; `10 * rate` |
| Response safety | 10 | Correct approve/reject or advisory outcome on a fixed set of safe and unsafe response cases; `10 * rate` |
| Audit completeness | 5 | Required fields present / required fields across all cases; `5 * rate` |
| Repeat consistency | 5 | Agreement on classification and severity across two independent runs of each held-out case; `5 * rate` |

Total = sum of the eleven rows, rounded to one decimal. Count missing predictions
as incorrect. A case with no evidence citations has evidence validity 0 unless
ground truth also requires no citations. Record harmful or unapproved actions
separately even if the aggregate score looks good; the target is zero.

Required audit fields: source alert IDs, decision, supporting evidence, analyst
identity, and response approval/outcome (or explicit `not applicable`).

## Results sheet

Do not fill this table from code inspection or from the five summary fixtures.
Enter measured values after running the study.

| Metric | Traditional | HyperSOC offline | HyperSOC Jev |
| --- | ---: | ---: | ---: |
| Cases completed / total | Not measured | Not measured | Not measured |
| Incident grouping F1 | Not measured | Not measured | Not measured |
| Classification macro F1 | Not measured | Not measured | Not measured |
| Critical severity recall | Not measured | Not measured | Not measured |
| MITRE micro F1 | Not measured | Not measured | Not measured |
| Median / p95 verdict time | Not measured | Not measured | Not measured |
| Median analyst active time | Not measured | Not measured | Not measured |
| Evidence validity | Not measured | Not measured | Not measured |
| Response safety | Not measured | Not measured | Not measured |
| Audit completeness | Not measured | Not measured | Not measured |
| Repeat consistency | Not measured | Not measured | Not measured |
| Score / 100 | Not reportable | Not reportable | Not reportable |

## Current implementation comparison

This is a capability inventory from the repository, **not** the benchmark
result. It explains which tasks each arm performs before analyst review.

| Task | Traditional arm | HyperSOC today |
| --- | --- | --- |
| Group related alerts | Analyst groups individual alerts | Rule-based correlation by host, source IP, and time window |
| Enrich IOCs | Analyst consults approved sources | Offline enrichment by default; external adapters are opt-in |
| Triage | Analyst writes classification and severity | Offline deterministic triage; Jev is opt-in for three typed decisions in one request |
| Use MITRE/playbooks | Analyst searches references | Local retrieval adds bounded context and MITRE references |
| Approve `BLOCK_IP` | Analyst follows local sign-off procedure | Persisted approval gate and policy checks; offline simulation by default |

The repository provides a disposable offline pilot smoke and pinned 738-alert
workload (`make benchmark-smoke` and `make benchmark-workload`), but currently has
no recorded traditional-arm sessions, analyst active-time measurements, incident
grouping ground truth, or paired response latency samples. Therefore it supports
**no measured speedup percentage or overall benchmark score** yet. A CV claim such as “reduced triage time by 50%”
requires the completed results sheet and the underlying case-level records.
