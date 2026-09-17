from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from app.schemas.knowledge_base import KnowledgeChunk, KnowledgeSearchResult


class VectorStore(Protocol):
    async def upsert(self, chunks: Iterable[KnowledgeChunk]) -> int:
        ...

    async def search(self, terms: set[str], *, top_k: int) -> list[KnowledgeSearchResult]:
        ...


class InMemoryVectorStore:
    """Deterministic keyword vector-store substitute for local/offline RAG."""

    def __init__(self) -> None:
        self._chunks: dict[str, KnowledgeChunk] = {}

    async def upsert(self, chunks: Iterable[KnowledgeChunk]) -> int:
        count = 0
        for chunk in chunks:
            key = str(chunk.chunk_id)
            if self._chunks.get(key) != chunk:
                self._chunks[key] = chunk
                count += 1
        return count

    async def search(self, terms: set[str], *, top_k: int) -> list[KnowledgeSearchResult]:
        scored: list[tuple[float, KnowledgeChunk]] = []
        for chunk in self._chunks.values():
            haystack = " ".join(
                [chunk.title, chunk.content, chunk.category, chunk.technique or "", *chunk.metadata.values()]
            ).casefold()
            matched = sum(1 for term in terms if term.casefold() in haystack)
            if matched:
                score = matched / max(1, len(terms))
                scored.append((score, chunk))
        scored.sort(key=lambda pair: (-pair[0], str(pair[1].chunk_id)))
        return [KnowledgeSearchResult(score=score, **chunk.model_dump()) for score, chunk in scored[:top_k]]

    @property
    def chunks(self) -> list[KnowledgeChunk]:
        return list(self._chunks.values())
