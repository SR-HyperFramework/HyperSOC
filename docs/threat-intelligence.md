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
URLHAUS_AUTH_KEY=
```

`THREAT_INTEL_PROVIDER_MODE` accepts `offline` or `external`. Do not commit real
secrets.

To enable external lookups, set the mode to `external`, flip
`THREAT_INTEL_ENABLE_EXTERNAL_PROVIDERS=true`, and configure at least one
provider credential:

```dotenv
THREAT_INTEL_PROVIDER_MODE=external
THREAT_INTEL_ENABLE_EXTERNAL_PROVIDERS=true
VIRUSTOTAL_API_KEY=<key>
ABUSEIPDB_API_KEY=<key>
URLHAUS_API_URL=https://urlhaus-api.abuse.ch/v1
URLHAUS_AUTH_KEY=<abuse.ch auth key>
```

Each provider is registered only when its own setting is non-empty, so a single
key enables a single provider. Startup fails if `external` mode is selected
without external providers enabled or without any provider configured.

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

## External providers

The offline provider always runs, and external providers are layered on top of
it. Aggregation is unchanged: `aggregate_provider_results` takes the highest
risk score and ignores results that carry an `error`.

| Provider | Indicator types | Endpoint | Credential |
| --- | --- | --- | --- |
| `virustotal` | ip, domain, hash, url | VirusTotal API v3 | `VIRUSTOTAL_API_KEY` |
| `abuseipdb` | ip | AbuseIPDB v2 `/check` | `ABUSEIPDB_API_KEY` |
| `urlhaus` | ip, domain, hash, url | URLhaus v1 `/url/`, `/host/`, `/payload/` | `URLHAUS_API_URL` (+ optional `URLHAUS_AUTH_KEY`) |

Scoring is deterministic per provider:

- VirusTotal: 5 or more malicious engines is `malicious`, 1 to 4 is
  `suspicious`, suspicious-only detections score 40, and a clean multi-engine
  result is `benign`. Confidence tracks the number of engines that responded.
- AbuseIPDB: a whitelisted address is `benign`, an abuse confidence of 75 or
  more is `malicious`, 25 or more is `suspicious`, and the abuse confidence
  becomes the risk score directly.
- URLhaus: a listed URL is `malicious` (90 online, 70 offline), a host with
  online malware URLs scores 85, a host with historic URLs scores 55, and a
  listed payload hash scores 85.

### Indicators that are never sent outside

Private, loopback, link-local, multicast, and reserved IP addresses, reserved or
single-label domains (`.local`, `.internal`, `.corp`, `.lan`, bare hostnames),
and URLs pointing at those hosts are answered locally with an
`indicator_not_queryable` error instead of being sent to a third party. Internal
network topology must not leak into an external reputation service.

### Failure handling

An external provider never raises into enrichment. Timeouts, transport failures,
rejected credentials, rate limits, and malformed responses are recorded as
bounded result errors (`provider_timeout`, `provider_unavailable`,
`provider_unauthorized`, `provider_rate_limited`, `provider_invalid_response`),
so one dead provider degrades a lookup instead of breaking it.

Provider-controlled text such as URLhaus `threat` and `tags` values is reduced to
a bounded allowlist charset before it is stored, because enrichment output
reaches analyst UI and AI triage context; see
[`prompt-injection-protection.md`](prompt-injection-protection.md). Responses are
also size-capped, and only named scalar fields are kept — raw provider payloads
are never persisted.

Cache TTLs apply to external results too, which is the main defence against
free-tier rate limits. There is no request-level rate limiter yet; a rate-limited
provider simply reports `provider_rate_limited` until the cache warms.

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

- Signed ingestion queues a durable job; the worker enriches IOCs after gathering
  internal context. The ingest request returns before that processing completes.
- Existing alert reads remain backward-compatible.
- Provider results are sanitized summaries, not full raw provider responses.
- Read/enrichment endpoints require SOC sessions and role authorization by
  default. The local rate limit is per client address and backend process.
- Redis remains reserved; the SOC worker uses PostgreSQL jobs and leases.
- Phase 6 rule-based correlation consumes sanitized enrichment associations when
  scoring malware/hash chains; see [`correlation.md`](correlation.md).
