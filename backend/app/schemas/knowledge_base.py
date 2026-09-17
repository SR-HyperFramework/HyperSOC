from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

KnowledgeSource = Literal["MITRE", "Wazuh", "SOC_PLAYBOOK", "Sigma", "Windows", "Linux"]


class KnowledgeChunk(BaseModel):
    model_config = {"extra": "forbid"}

    chunk_id: UUID
    document_id: UUID
    source: KnowledgeSource
    path: str = Field(min_length=1, max_length=512)
    category: str = Field(min_length=1, max_length=64)
    technique: str | None = Field(default=None, max_length=32)
    title: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=1200)
    metadata: dict[str, str] = Field(default_factory=dict)


class KnowledgeIndexOut(BaseModel):
    indexed_documents: int = Field(ge=0)
    indexed_chunks: int = Field(ge=0)


class KnowledgeSearchQuery(BaseModel):
    model_config = {"extra": "ignore"}

    mitre_ids: list[str] = Field(default_factory=list, max_length=20)
    alert_types: list[str] = Field(default_factory=list, max_length=20)
    classification: str | None = Field(default=None, max_length=64)
    ioc_types: list[str] = Field(default_factory=list, max_length=10)
    top_k: int = Field(default=5, ge=1, le=20)


class KnowledgeSearchResult(BaseModel):
    model_config = {"extra": "forbid"}

    chunk_id: UUID
    document_id: UUID
    source: KnowledgeSource
    path: str
    category: str
    technique: str | None = None
    title: str
    content: str
    score: float = Field(ge=0)
    metadata: dict[str, str] = Field(default_factory=dict)


class KnowledgeSearchOut(BaseModel):
    query: KnowledgeSearchQuery
    results: list[KnowledgeSearchResult] = Field(default_factory=list, max_length=20)


class KnowledgeDocument(BaseModel):
    model_config = {"extra": "forbid"}

    document_id: UUID
    source: KnowledgeSource
    path: str
    category: str
    technique: str | None = None
    title: str
    content: str
    updated_at: datetime | None = None
