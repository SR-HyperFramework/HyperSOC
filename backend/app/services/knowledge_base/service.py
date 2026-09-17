from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable
from uuid import UUID, uuid5

from app.schemas.knowledge_base import (
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeIndexOut,
    KnowledgeSearchOut,
    KnowledgeSearchQuery,
    KnowledgeSearchResult,
)
from app.services.knowledge_base.vector_store import InMemoryVectorStore, VectorStore

_KNOWLEDGE_NAMESPACE = UUID("8c9b3b87-0d2a-4bf4-a4e3-84c9f9dd8c11")
_WORDS = re.compile(r"[a-z0-9_.-]+", re.IGNORECASE)
_METADATA_LINE = re.compile(r"^\s*-\s*([A-Za-z0-9_-]+)\s*:\s*(.+?)\s*$")
_SOURCE_BY_DIR = {
    "mitre": "MITRE",
    "wazuh": "Wazuh",
    "soc-playbooks": "SOC_PLAYBOOK",
    "sigma": "Sigma",
    "references": "Linux",
}
_SOURCE_VALUES = {
    "soc playbook": "SOC_PLAYBOOK",
    "soc_playbook": "SOC_PLAYBOOK",
    "mitre": "MITRE",
    "wazuh": "Wazuh",
    "sigma": "Sigma",
    "windows": "Windows",
    "linux": "Linux",
}


class KnowledgeBaseService:
    """Offline-first, deterministic knowledge loader and retrieval service."""

    def __init__(
        self,
        *,
        root: str | Path = "knowledge",
        vector_store: VectorStore | None = None,
        max_chunk_chars: int = 1200,
        max_context_chars: int = 6000,
        default_top_k: int = 5,
    ) -> None:
        self.root = Path(root).resolve()
        self.vector_store = vector_store or InMemoryVectorStore()
        self.max_chunk_chars = max_chunk_chars
        self.max_context_chars = max_context_chars
        self.default_top_k = default_top_k
        self._documents: dict[UUID, KnowledgeDocument] = {}
        self._indexed = False

    async def index(self) -> KnowledgeIndexOut:
        documents = self._load_documents()
        chunks = [chunk for document in documents for chunk in self._chunk_document(document)]
        await self.vector_store.upsert(chunks)
        self._documents = {document.document_id: document for document in documents}
        self._indexed = True
        return KnowledgeIndexOut(indexed_documents=len(documents), indexed_chunks=len(chunks))

    async def search(self, query: KnowledgeSearchQuery) -> KnowledgeSearchOut:
        if not self._indexed:
            await self.index()
        terms = self._query_terms(query)
        results = await self.vector_store.search(terms, top_k=min(query.top_k, self.default_top_k))
        bounded: list[KnowledgeSearchResult] = []
        total_chars = 0
        for result in results:
            remaining = self.max_context_chars - total_chars
            if remaining <= 0:
                break
            content = result.content[: min(self.max_chunk_chars, remaining)]
            if not content:
                break
            bounded.append(result.model_copy(update={"content": content}))
            total_chars += len(content)
        return KnowledgeSearchOut(query=query, results=bounded)

    async def retrieve_for_context(self, query: KnowledgeSearchQuery) -> list[KnowledgeSearchResult]:
        return (await self.search(query)).results

    def _load_documents(self) -> list[KnowledgeDocument]:
        if not self.root.is_dir():
            return []
        documents: list[KnowledgeDocument] = []
        for path in sorted(self.root.glob("**/*.md")):
            if not path.is_file():
                continue
            relative = path.relative_to(self.root).as_posix()
            parts = relative.split("/")
            source = _SOURCE_BY_DIR.get(parts[0], "Wazuh")
            title, content, metadata = self._parse_markdown(path)
            category = metadata.get("category", parts[0])[:64]
            technique = self._technique(relative, content, metadata)
            document_id = uuid5(_KNOWLEDGE_NAMESPACE, relative)
            documents.append(
                KnowledgeDocument(
                    document_id=document_id,
                    source=self._source(source, metadata),
                    path=relative,
                    category=category,
                    technique=technique,
                    title=title,
                    content=content,
                )
            )
        return documents

    def _parse_markdown(self, path: Path) -> tuple[str, str, dict[str, str]]:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        title = next((line.lstrip("# ").strip() for line in lines if line.startswith("#")), path.stem.replace("-", " ").title())
        metadata: dict[str, str] = {}
        for line in lines:
            match = _METADATA_LINE.match(line)
            if match:
                key, value = match.groups()
                metadata[key.lower().replace("-", "_")] = value
        content = text.strip()
        return title[:255], content, metadata

    def _source(self, fallback: str, metadata: dict[str, str]) -> str:
        return _SOURCE_VALUES.get(metadata.get("source", "").casefold(), fallback)

    def _technique(self, relative: str, content: str, metadata: dict[str, str]) -> str | None:
        if technique := metadata.get("technique"):
            return technique.upper()[:32]
        match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", relative + " " + content, re.IGNORECASE)
        return match.group(0).upper() if match else None

    def _chunk_document(self, document: KnowledgeDocument) -> list[KnowledgeChunk]:
        content = document.content
        chunks: list[KnowledgeChunk] = []
        for index in range(0, len(content), self.max_chunk_chars):
            chunk_content = content[index : index + self.max_chunk_chars].strip()
            if not chunk_content:
                continue
            chunk_key = f"{document.path}:{index}:{hashlib.sha256(chunk_content.encode()).hexdigest()}"
            chunk_id = uuid5(_KNOWLEDGE_NAMESPACE, chunk_key)
            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    document_id=document.document_id,
                    source=document.source,
                    path=document.path,
                    category=document.category,
                    technique=document.technique,
                    title=document.title,
                    content=chunk_content,
                    metadata={"document_path": document.path, "chunk_index": str(index // self.max_chunk_chars)},
                )
            )
        return chunks

    def _query_terms(self, query: KnowledgeSearchQuery) -> set[str]:
        values: Iterable[str] = [
            *query.mitre_ids,
            *query.alert_types,
            *(query.ioc_types),
            query.classification or "",
        ]
        return {token.casefold() for value in values for token in _WORDS.findall(value) if token}
