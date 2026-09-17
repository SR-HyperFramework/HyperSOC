# Phase 20 — Security Hardening

The MVP already enforces signed Wazuh ingest, request-size limits, prompt
sanitization, schema validation, and human approval for response actions. Before
production use, add the controls below.

## Required controls

```text
JWT auth
RBAC
rate limiting
input validation
secret management
audit logging
CORS restriction
request body size limits
```

## Roles

```text
viewer   — read alerts/incidents/dashboard only
analyst  — triage incidents and approve/reject response actions
admin    — manage settings, policies, and integrations
```

Only `analyst` and `admin` may approve response actions. Active response execution
must verify the stored approval and policy result immediately before execution.

## Current configuration placeholders

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
