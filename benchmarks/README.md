# HyperSOC vs traditional SOC: runnable pilot

This folder provides **11 pilot cases** and a paired timing harness: eight
synthetic cases (`C01`–`C08`) plus three cases (`C09`–`C11`) derived from
publicly observed Wazuh alerts. The case IDs are opaque, and `prepare` creates
packets without the provisional labels, scenario descriptions, or provenance
metadata in `cases.json`. Give analysts only the packet files, never the
catalog.

The observed cases are selected, field-projected alerts from Kholil Haq Alim
Hakim's [Wazuh Alerts Dataset](https://huggingface.co/datasets/kholil-lil/wazuh-alerts),
which the publisher describes as live Wazuh manager `alerts.json` data and
licenses under MIT. Source revision:
`13cc552c9de42eecee22f6e4c2fe34c80ae3f5d8`; file SHA-256:
`487bc73ace742995e5e09622494c0b750f513c3a9328dd2276c50444ab0df532`.
The selected source alert IDs are recorded per case in `cases.json`. We kept
behavioral fields but replaced public source IPs with TEST-NET addresses,
pseudonymized the agent and attempted usernames, and shift top-level timestamps for replay. These are
**real-log-derived, not independently verified real incidents**. The dataset's
per-alert true/false-positive labels do not establish incident-level ground
truth; all labels here remain provisional. Current IOC reputation for the
redacted IPs is invalid for judging the original 2025 events, and HyperSOC's
offline provider may call TEST-NET addresses benign. Do not use these cases to
score threat-intelligence accuracy.

To independently re-check the source file hash and every selected alert's
behavior fields against the pinned revision, run:

```powershell
python benchmarks/verify_observed_source.py
```

## Container-first commands

The repository provides isolated commands that require Docker Compose but no host
Python. Each integration command creates a unique project and fresh database,
runs migrations, forces offline providers, and removes all benchmark storage:

```powershell
make test
make benchmark-smoke
make benchmark-verify
make benchmark-workload
```

Results are stored below `.benchmark-runs/`. Set `BENCHMARK_KEEP_STACK=1` only for
local troubleshooting and run `make benchmark-clean` afterward. These commands
never use the normal Compose project or its `postgres_data` volume.

To compare offline triage with Jev via OpenRouter, run two fresh, disposable
stacks. Put `OPENROUTER_API_KEY` in a private `.env` or export it in the shell;
never commit the key. OpenRouter must have available credit. These commands
send one sanitized incident context per correlated incident to OpenRouter and
may incur cost:

```powershell
make benchmark-triage
make benchmark-jev
python benchmarks/compare_triage.py .benchmark-runs/<offline-result>.json .benchmark-runs/<jev-result>.json
```

The exact result paths are printed by each command. Jev uses the pinned
`jev-1.13` model and `https://openrouter.ai/api`. `benchmark-workload` remains
offline and does not perform triage. The Docker environment exposes the key to
the benchmark backend container, so run it only on a trusted machine; the
result JSON does not store the key.

## Full-dataset workload replay

`batch_replay.py` processes **all 738 alerts** from the pinned source. It
downloads into memory, verifies SHA-256, discards the publisher's labels,
replaces IPv4 addresses consistently with TEST-NET addresses, and shifts
top-level timestamps so the latest alert is two minutes old. Relative event
spacing is preserved and alerts are sent chronologically, but there is no
real-time waiting.
No raw alert file or IP mapping is written to the result JSON.

Use a fresh, disposable backend/database, set its `APP_SECRET_KEY` in the
benchmark shell, and keep threat intelligence offline. From the repository
root:

```powershell
python benchmarks/batch_replay.py --isolated-db --output .benchmark-runs/full-workload.json
```

The default run ingests all alerts, enriches each **unique persisted** alert,
and correlates once. It records submitted count, backend deduplication,
ingest/enrichment median and p95 latency, request throughput, correlation
duration, incident count, and linked/unlinked alerts. A failed stage stops the
run and writes a partial failure record; the result file is never overwritten.
Only loopback backends are accepted, and the database must start empty.

To include one triage request per correlated incident, add `--triage` with a
different output path. This uses the backend's configured provider; Jev can
incur cost and receive sanitized, IP-redacted incident context. Keep offline and Jev results in
separate runs with a fresh database each time.

Triage runs now include `triage.results`: one whitelisted decision per incident
(`classification`, `severity`, `confidence`, false-positive probability, provider,
and latency). `incident_key` is a SHA-256 hash of the sorted original Wazuh alert
IDs in that incident, so results can be paired across fresh databases without
writing source IDs, database UUIDs, raw logs, or provider narratives. A failed
triage request leaves a partial record with only its error type; the run fails.
Compare two completed triage runs with:

```powershell
python benchmarks/compare_triage.py .benchmark-runs/offline.json .benchmark-runs/jev.json
```

The comparison reports matched/unmatched incident keys and decision agreement,
**not accuracy**. Older triage result files without `triage.results` must be rerun
before comparison.

This is a **workload/coverage benchmark**, not an accuracy or traditional-
analyst comparison. The dataset's labels are per alert, while HyperSOC
produces incidents; many active-response notices labeled false positive
co-occur with attack alerts. Masked agent identities and redacted IPs also
invalidate incident grouping and IOC-reputation ground truth. Do not turn
batch timings into a CV claim about manual time saved.

This is a smoke/pilot dataset, **not** the final study described in
[`docs/soc-workflow-benchmark.md`](../docs/soc-workflow-benchmark.md). In
particular, it is too small, is not class-balanced, has no decoy or multi-group
cases, and its labels have not been independently reviewed. Do not use its
numbers as a CV speedup claim.

## Run the pilot

From the repository root in PowerShell:

```powershell
python -m unittest discover -s benchmarks -p test_soc_benchmark.py -v
python benchmarks/soc_benchmark.py prepare --output .benchmark-runs/pilot-01/packets
python benchmarks/soc_benchmark.py review --arm traditional --packet .benchmark-runs/pilot-01/packets/C01.json --analyst A01 --output .benchmark-runs/pilot-01/results.jsonl
```

For the HyperSOC arm, start the backend against a **disposable, empty,
isolated database**. Use offline TI and either offline triage or Jev triage;
run those two triage modes in separate result files. Set `APP_SECRET_KEY` in
the benchmark shell to the same value as the backend; do not paste it into a
command line or result file. Then:

```powershell
python benchmarks/soc_benchmark.py review --arm hypersoc --packet .benchmark-runs/pilot-01/packets/C01.json --analyst A02 --output .benchmark-runs/pilot-01/results.jsonl --isolated-db
python benchmarks/soc_benchmark.py report --results .benchmark-runs/pilot-01/results.jsonl
```

Reset the isolated database before **each** HyperSOC case. The runner rejects
a database containing existing alerts and only accepts a loopback HTTP URL.
It ingests the raw Wazuh alerts through the project's adapter, calls offline
enrichment, runs correlation, and calls triage. The analyst sees the source
alerts and generated output, then records a final decision. Both arms use the
same packet hash. Re-run `prepare` if packets become older than the backend's
60-minute correlation lookback. Do not run synthetic cases against production
Wazuh or a live response provider.

Case `C11` deliberately has no source IP. HyperSOC's current correlator may
create no incident; the harness records `no_matching_incident` and still lets
the analyst finish the review. This is coverage information, not a crashed
run.

The timer starts when the case is released and stops when the worksheet is
complete. `elapsed_seconds` is end-to-end wall time; `pipeline_seconds` and
per-stage timings are recorded for the HyperSOC arm. The CLI does **not**
reliably measure analyst active time or third-party cost. Analysts in the
traditional arm may use the same approved TI sources and playbooks as the
system arm, but must manually group, investigate, and document the alerts.
Use separate analysts per case and alternate arm assignments; do not let one
analyst see the same case twice. Keep local versions/configuration identical
and document any external lookup or provider failures.

`report` compares only case pairs with the exact same packet hash and different
analyst IDs. It reports classification accuracy/macro-F1, severity accuracy,
critical recall, MITRE micro-F1, automation coverage, and median/p95 wall time. Failed runs remain
in quality denominators, and incomplete pairs do not yield a time ratio. Even
a complete pilot report stays `reportable: false`; the full
100-point scorecard requires a larger independently labeled set, evidence and
response-safety scoring, repeatability measurements, and confidence intervals.
