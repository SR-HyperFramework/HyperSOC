from fastapi import APIRouter, Depends, Query

from app.core.config import settings
from app.schemas.knowledge_base import KnowledgeIndexOut, KnowledgeSearchOut, KnowledgeSearchQuery
from app.services.knowledge_base import KnowledgeBaseService

router = APIRouter(prefix="/api/v1/knowledge", tags=["knowledge"])
_knowledge_service = KnowledgeBaseService(
    root=settings.knowledge_base_path,
    max_chunk_chars=settings.rag_max_chunk_chars,
    max_context_chars=settings.rag_max_context_chars,
    default_top_k=settings.rag_top_k,
)


def get_knowledge_base_service() -> KnowledgeBaseService:
    return _knowledge_service


@router.post("/index", response_model=KnowledgeIndexOut)
async def index_knowledge(service: KnowledgeBaseService = Depends(get_knowledge_base_service)) -> KnowledgeIndexOut:
    return await service.index()


@router.get("/search", response_model=KnowledgeSearchOut)
async def search_knowledge(
    mitre_ids: list[str] = Query(default=[]),
    alert_types: list[str] = Query(default=[]),
    classification: str | None = Query(default=None, max_length=64),
    ioc_types: list[str] = Query(default=[]),
    top_k: int = Query(default=5, ge=1, le=20),
    service: KnowledgeBaseService = Depends(get_knowledge_base_service),
) -> KnowledgeSearchOut:
    query = KnowledgeSearchQuery(
        mitre_ids=mitre_ids,
        alert_types=alert_types,
        classification=classification,
        ioc_types=ioc_types,
        top_k=top_k,
    )
    return await service.search(query)
