# Phase 14 — MITRE Visualization

The MVP represents attack chains as a compact, evidence-backed MITRE sequence.
The frontend shell renders the chain as ordered technique cards and the backend
exposes aggregate technique counts through:

```http
GET /api/v1/dashboard/mitre
```

## Demo chain

```text
Credential Access
T1110 Brute Force
   ↓
Initial Access
T1078 Valid Accounts
   ↓
Execution
T1059.001 PowerShell / Command and Scripting Interpreter
   ↓
Persistence
T1053 Scheduled Task / Job
```

## Data contract

Each highlighted technique should include:

```json
{
  "technique_id": "T1110",
  "alert_count": 47,
  "incident_count": 1,
  "total_count": 48
}
```

Incident detail pages should prefer the incident's ordered AI attack chain when
available, then fall back to incident `mitre_ids`, then dashboard aggregate counts.
Visualization must not infer techniques that are not present in normalized alert,
incident, RAG, or AI-triage evidence.

## Rendering rules

- Keep timeline order separate from tactic order when evidence timestamps differ.
- Show technique IDs and human-readable labels together.
- Link every technique to evidence or a knowledge-base document.
- Treat MITRE labels as analyst context, not proof of compromise.
