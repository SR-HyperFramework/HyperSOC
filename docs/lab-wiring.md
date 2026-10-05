# VMware Wazuh lab wiring

Lab: `h26v@192.168.248.182`, SSH alias `wazuh-lab`. Shared checkout:
`/mnt/hgfs/HyperSOC/ai-soc` (Windows `C:\Users\ADMIN\HyperSOC\ai-soc`).

## Running topology

- Existing Wazuh 4.9.0 manager, indexer and dashboard remain in `single-node_default`.
- Docker Compose project `hypersoc-lab` runs PostgreSQL, migration, backend, worker and a read-only Wazuh API collector. Redis is reserved and not started.
- Backend joins the existing Wazuh network as `hypersoc-backend`. The existing `custom-ai-soc` integration posts signed native events to `http://hypersoc-backend:8000/api/v1/hub/native-events`, preserving its level-5 filter.
- Collector imports agent inventory, bounded process snapshots (100 per active agent) and SCA policies every five minutes. It retains source scan timestamps and stable event IDs. Internal requests bypass host HTTP proxies. TLS verifies the exported manager certificate; hostname matching is disabled because the default certificate CN differs from the Docker service name.
- Backend publishes only `127.0.0.1:8000` in the VM. Access from Windows uses an SSH tunnel to `127.0.0.1:8021`.

## Configuration and credentials

Private VM state is in `~/.config/hypersoc-lab/`, outside the shared checkout: `lab.env`, `compose.json`, `collector.json`, the Wazuh API public certificate, admin credentials, backups and verification results. Directory permissions are 700; credential files are 600.

Console admin username: `h26v`. Read its generated password locally:

```powershell
ssh wazuh-lab 'cat ~/.config/hypersoc-lab/admin-credentials.json'
```

Provider modes copied from the existing project configuration:

| Stage | Live lab mode |
|---|---|
| Alert understanding | OpenRouter, configured DeepSeek model |
| AI triage | Jev / TypeSafe through OpenRouter |
| Investigation and conclusion | OpenRouter, configured DeepSeek model |
| Threat intelligence | Offline; external provider keys are not configured |
| Wazuh active response | Offline; analyst review remains required |

The structured-output provider disables reasoning for its bounded 1,600-token calls. Live diagnosis showed the default reasoning consumed all 1,600 tokens and returned empty content. Truncated responses are rejected; evidence citation and IOC validation remain enforced.

This follows OpenRouter's documented [reasoning and output token budget](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens).

## Operations

Reopen the tunnel when the Windows SSH process exits:

```powershell
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -L 127.0.0.1:8021:127.0.0.1:8000 wazuh-lab
```

Then open `http://127.0.0.1:8021`.

Run the helper on the VM:

```sh
cd /mnt/hgfs/HyperSOC/ai-soc
python3 scripts/wire_lab.py start          # build one shared image, migrate and start backend/worker
python3 scripts/wire_lab.py collector      # provision/recreate read-only collector
python3 scripts/wire_lab.py snapshot       # sanitized DB counts and workflow/report status
python3 scripts/wire_lab.py probe          # emit an explicitly labeled, benign wiring log
python3 scripts/wire_lab.py retry-probes   # retry only failed/retrying rule-110901 probe jobs
python3 scripts/wire_lab.py verify         # match native Wazuh ID to persisted review workflow
```

Shared source synchronization does not rebuild running images. Run `start` after backend/frontend source changes. The collector directory is mounted read-only; restart its container to reload Python changes. `wire` backs up configuration, refreshes the manager integration, validates Integrator configuration and restarts the manager; use it deliberately because ingestion pauses during restart.

The controlled probe uses local rule `110901` and `/var/ossec/logs/hypersoc-wiring.log`. It creates no attack or response action. Backups include original host/runtime configuration and adapter files; retain them for rollback.

## Acceptance evidence and limits

- Wazuh native detection reached Hub and queued the worker.
- Collector completed a live cycle with 4 assets, 120 process records and 2 SCA records, zero skipped. Counts describe processed observations; repeated snapshots are deduplicated.
- Final workflow/provider proof is stored in `wiring-result.json` and `snapshot.json` in the private VM state directory.
- Fresh probe `1791218652.49602` reached workflow `98a4fe79-38a2-4526-9de0-ab6d42f43981`, status `AWAITING_REVIEW`, with investigation `fbd87f6b-d15b-417c-89fb-8c68aaf75c6b`. Context included posture and a behavior baseline; remaining gaps included authoritative identity inventory and absent learned technique transitions.
- Snapshot confirmed 120 unique behavior records, 6 posture records, 2 stored triage results and 2 OpenRouter investigations using `deepseek/deepseek-v4.1-flash`. Both workflows reached review with no remaining error. One `categorical-density-v1` model trained on 20 source observations; this proves baseline wiring, not model quality or production coverage.
- Windows tunnel `/ready` returned HTTP 200 with database ready and migration head `0010`. Backend and PostgreSQL were healthy; worker and collector were running. Backend tests: 272 passed, 1 skipped (PostgreSQL-only concurrency test in this local run).
- Agents `001` (Win10-Endpoint) and `002` (Ubuntu-Endpoint) were disconnected at inspection; only active agents supply current process snapshots.
- The VM has approximately 4 GB RAM and exhibits high load. This is a functional lab deployment; no throughput or production availability claim has been established.
- External IOC reputation and live response execution are not enabled. Do not interpret offline enrichment as a clean reputation verdict.

See `soc-model-implementation.md` for the architecture mapping and `soc-deployment.md` for broader deployment acceptance criteria.
