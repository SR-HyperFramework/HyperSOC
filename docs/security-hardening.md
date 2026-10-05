# Phase 20 — Security Hardening

The application enforces signed Wazuh/Hub ingest, optional per-source Hub keys,
request-size limits, explicit-origin CORS, a per-process rate limit, prompt
sanitization, schema validation, expiring authenticated sessions, role checks,
CSRF protection and audited human approval. Account provisioning and the operating
contract are documented in [SOC deployment](soc-deployment.md).

## Required controls

```text
enterprise SSO / centralized account lifecycle
distributed proxy-aware rate limiting
input validation
secret management
central audit retention and tamper-resistant archival
production CORS policy review
request body size limits
```

## Roles

```text
viewer   — read alerts/incidents/dashboard/Hub/workflows and bounded searches
analyst  — triage incidents and approve/reject response actions
admin    — analyst permissions plus Hub inventory/relationships/models and audit access
```

Only `analyst` and `admin` may approve response actions. Active response execution
must verify the stored approval and policy result immediately before execution.
Approval and execution also recheck the latest analyst-confirmed TP report. User
names supplied in request bodies do not override the authenticated account.
Simulation and Manager acknowledgement do not change a case to `CONTAINED`.
Matching endpoint evidence for every requested agent is needed for verification.

## Current lab controls

`CORS_ALLOWED_ORIGINS` is an explicit comma-separated allowlist; wildcard origins
are rejected and credentialed cross-origin requests are disabled.
`SECURITY_RATE_LIMIT_PER_MINUTE` is enforced per direct client IP in each backend
process. It deliberately ignores forwarded-client headers and does not coordinate
between replicas. Place production deployments behind an authenticated,
proxy-aware distributed limiter.

The application rejects the public example `APP_SECRET_KEY` placeholder and keys
shorter than 16 characters.

## Current configuration

```dotenv
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
SECURITY_RATE_LIMIT_PER_MINUTE=120
APP_SECRET_KEY=replace-with-a-random-secret
```

## Hardening notes

- Keep Wazuh, threat-intel, and LLM credentials out of logs.
- Never allow arbitrary shell, PowerShell, or bash as a response action.
- Deny localhost, link-local, multicast, and private management subnets by default.
- Keep lab-only scripts out of production hosts.
