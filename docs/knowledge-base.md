# RAG knowledge base

Phase 9 provides SOC reference knowledge to AI triage. The default implementation
is local and deterministic: Markdown documents are loaded from the configured
`knowledge/` root, split into stable bounded chunks, and searched with a small
keyword-based vector-store substitute. No Qdrant, embeddings, network access, or
API key is required in offline mode.

## Sources

The initial corpus uses these categories:

- `knowledge/mitre/` — MITRE ATT&CK technique explanations.
- `knowledge/soc-playbooks/` — SSH brute-force, PowerShell, persistence, and
  malware investigation guidance.
- `knowledge/wazuh/` — Wazuh rule interpretation notes.
- `knowledge/sigma/` — Sigma detection explanations.
- `knowledge/references/` — Windows and Linux security references.

The repository uses `soc-playbooks` consistently for internal playbooks. Documents
are reference data only; they contain no executable payloads or secrets.

## Metadata and chunking

Each document is assigned a stable UUID from its repository-relative path. Chunks
carry:

```json
{
  "source": "MITRE",
  "technique": "T1110",
  "category": "mitre",
  "path": "mitre/T1110.md",
  "title": "MITRE T1110 — Brute Force"
}
```

Chunks are deterministic and bounded by `RAG_MAX_CHUNK_CHARS`. Re-indexing the same
corpus is idempotent in the local vector store.

## Retrieval

Search accepts the roadmap query dimensions:

- MITRE IDs (`mitre_ids`)
- alert types (`alert_types`)
- incident classification (`classification`)
- IOC types (`ioc_types`)

Results are ranked by deterministic token overlap with stable UUID tie-breaking.
The result count and aggregate context length are bounded.

Index and search the configured corpus:

```bash
curl -fsS -X POST 'http://localhost:8000/api/v1/knowledge/index'
curl -fsS 'http://localhost:8000/api/v1/knowledge/search?mitre_ids=T1110&alert_types=ssh&ioc_types=ip&top_k=5'
```

The API never accepts an arbitrary filesystem path; it indexes only the configured
knowledge root.

## AI triage integration

AI triage can receive retrieved chunks as `mitre_context` and `playbook_context`.
The flow remains:

```text
correlated incident
→ normalized alerts + sanitized enrichment
→ bounded RAG retrieval
→ Phase 8 PromptSanitizer
→ structured AI context inside <UNTRUSTED_EVENT_DATA>
→ strict output validation
```

Knowledge text is data, not instructions. It cannot override the AI system
instruction, authorize response execution, or bypass Phase 8 limits. Raw Wazuh
JSON and `alerts.raw_event` are not indexed or sent to RAG.

## Configuration

```dotenv
KNOWLEDGE_BASE_PROVIDER_MODE=offline
KNOWLEDGE_BASE_PATH=knowledge
RAG_TOP_K=5
RAG_MAX_CHUNK_CHARS=1200
RAG_MAX_CONTEXT_CHARS=6000
QDRANT_URL=
QDRANT_API_KEY=
```

`VectorStore` is a replaceable interface. A future Qdrant adapter can use the
existing placeholders without changing the knowledge service or AI triage
contracts. Qdrant is not a required Compose service for the local MVP.

## Operational notes

- Indexing is explicit through `POST /api/v1/knowledge/index`; search lazily
  indexes the configured local corpus if needed.
- Retrieval is bounded and offline-first.
- Retrieved content is sanitized together with incident evidence before provider
  analysis.
- Knowledge/AI endpoints require SOC sessions by default. Indexing requires admin
  permission; retrieval is available to authorized readers. Retrieved documents
  remain untrusted evidence and cannot change the agent's tool allowlist or policy.
