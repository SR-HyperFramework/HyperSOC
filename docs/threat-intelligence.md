# Threat intelligence enrichment

Phase 5 enriches bounded indicators of compromise before future correlation and
AI triage. It is offline-first by default: the backend can score and cache IOC
results deterministically without VirusTotal, AbuseIPDB, URLHaus, Redis, internet
access, or provider API keys.

## Scope

Threat-intel enrichment consumes the Phase 4 `NormalizedAlert` contract, not raw
Wazuh JSON. The service extracts only these canonical fields:

- IPs: `network.src_ip`, `network.dst_ip`, and `host.ip`
- Domains: `network.domain`, `network.dns_query`, and the hostname of an absolute
  URL
- Hashes: `file.hash` and `process.hash`
- URLs: absolute `http` or `https` values from `network.url`

The service intentionally does not parse `raw_event`, process command lines,
PowerShell script blocks, HTTP bodies, or arbitrary provider payloads for more
IOCs. Native Wazuh evidence remains untrusted and must not be sent directly to an
LLM.

## Configuration

Default settings in `.env.example` keep enrichment offline and deterministic:

```dotenv
THREAT_INTEL_PROVIDER_MODE=offline
THREAT_INTEL_ENABLE_EXTERNAL_PROVIDERS=false
THREAT_INTEL_LOOKUP_TIMEOUT_SECONDS=5
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
URLHAUS_API_URL=
```

`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, and `URLHAUS_API_URL` are reserved for
future provider implementations. Do not commit real secrets.

## Cache behavior

Enrichment results are persisted separately from alert raw evidence:

- `threat_intel_indicators` stores one sanitized cache row per canonical
  `(type, indicator)`.
- `alert_threat_intel` links alerts to cached IOC rows and evidence paths.

Cache TTLs follow the roadmap:

| Type | TTL |
| --- | --- |
| `ip` | 6 hours |
| `domain` | 12 hours |
| `hash` | 24 hours |
| `url` | 6 hours |

A repeated lookup returns the cached row until it expires. Use `refresh=true` to
force recomputation. Alert associations are unique per alert, indicator, and
evidence path, so replaying enrichment does not create duplicate association
rows.

## Offline provider

The default `offline` provider is deterministic and bounded:

- local, private, link-local, multicast, documentation, and reserved IP addresses
  return benign/low-risk local reputation.
- reserved domains such as `.test`, `.example`, `.invalid`, `.localhost`, and
  example domains return benign/low-risk local reputation.
- unknown public indicators return `unknown` with low risk.
- a small fixture set and simple lexical URL/domain heuristics produce
  repeatable suspicious or malicious examples for tests and demos.

These results are local reputation hints, not external threat-intel assertions.

## API

Direct IOC lookup:

```bash
curl -fsS 'http://localhost:8000/api/v1/threat-intel/lookup?type=ip&indicator=10.10.10.50'
```

Alert enrichment:

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/alerts/<alert-id>/threat-intel'
curl -fsS 'http://localhost:8000/api/v1/alerts/<alert-id>/threat-intel'
```

Example response shape:

```json
{
  "indicator": "10.10.10.50",
  "type": "ip",
  "providers": {
    "offline": {
      "provider": "offline",
      "verdict": "benign",
      "risk_score": 0,
      "confidence": 100,
      "summary": "Non-routable, local, or reserved IP address",
      "metadata": {"source": "offline", "indicator_type": "ip"},
      "error": null
    }
  },
  "risk_score": 0,
  "verdict": "benign",
  "cached": false,
  "cached_until": "2026-09-16T18:00:00Z",
  "last_lookup_at": "2026-09-16T12:00:00Z"
}
```

Alert-level responses include `alert_id`, `indicators`, `max_risk_score`, and an
aggregate `verdict`.

## Operational notes

- The signed Wazuh ingest endpoint is unchanged; enrichment is not triggered from
  `POST /api/v1/alerts` in this phase.
- Existing alert reads remain backward-compatible.
- Provider results are sanitized summaries, not full raw provider responses.
- The read/enrichment endpoints are lab/local endpoints until authentication,
  RBAC, and rate limiting are added in later phases.
- Redis remains reserved for a future worker/queue design and is not required for
  Phase 5.
